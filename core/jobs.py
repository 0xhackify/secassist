"""Bounded background workers. UI is a viewer, never an alternate execution path."""
import codecs
import collections
import datetime
import hashlib
import json
import os
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from .storage import atomic_json, redact
from .tools import clean_output, prepare_args, parse_nmap_xml

MAX_LOG = 16 * 1024 * 1024
MAX_TAIL = 16000


@dataclass
class Job:
    id: str
    tool: str
    args: list
    path: Path
    status: str = 'queued'
    returncode: object = None
    started: float = 0
    ended: float = 0
    tail: str = ''
    summary: str = ''
    error: str = ''
    cancel: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)
    process: object = None
    sha256: str = ''

    def record(self):
        return {'id': self.id, 'tool': self.tool, 'args': self.args,
                'status': self.status, 'returncode': self.returncode,
                'started': self.started, 'ended': self.ended,
                'output': self.path.name, 'error': self.error, 'sha256': self.sha256}


def stop_group(proc):
    if os.name == 'posix':
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif proc.poll() is None:
        subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


class JobManager:
    def __init__(self, workspace, max_jobs=2):
        self.ws = workspace
        self.max_jobs = max_jobs
        self.jobs = {}
        self.lock = threading.RLock()
        self.on_start = None
        self.closed = False
        self._write()

    def active(self):
        with self.lock:
            return [j for j in self.jobs.values() if not j.done.is_set()]

    def _write(self):
        with self.lock:
            atomic_json(self.ws.root / 'jobs.json', [j.record() for j in self.jobs.values()])

    def submit(self, action):
        with self.lock:
            if self.closed:
                raise ValueError('Job manager is closed')
            if len(self.active()) >= self.max_jobs:
                raise ValueError('Concurrency limit reached; wait for or stop a job')
            jid = uuid.uuid4().hex[:10]
            path = self.ws.outputs / f'{action.tool.name}_{jid}.txt'
            job = Job(jid, action.tool.name, action.args + list(action.defaults), path)
            self.jobs[jid] = job
            path.touch(mode=0o600)
            self._write()
            thread = threading.Thread(target=self._run, args=(job, action.tool), daemon=False)
            thread.start()
        if self.on_start:
            try:
                self.on_start(job)
            except (OSError, ValueError, subprocess.SubprocessError) as e:
                self.ws.event('pane_error', job=jid, error=str(e))
        return job

    def _run(self, job, tool):
        job.started = time.time()
        job.status = 'running'
        timer = None
        try:
            args, xml = prepare_args(tool, job.args, self.ws.outputs.resolve(), job.id)
            # Prevent curl's implicit ~/.curlrc from supplying extra targets/options.
            if tool.name == 'curl':
                args = ['-q'] + args
            binary = tool.binary()
            if not binary:
                raise ValueError('Tool disappeared before execution')
            cmd = [binary] + args
            # Tools do not inherit API credentials. Native tools still run as this OS user.
            env = {k: v for k, v in os.environ.items() if not any(
                word in k.upper() for word in ('KEY', 'TOKEN', 'SECRET', 'PASSWORD', 'PROXY'))}
            env.update(PAGER='cat', GIT_PAGER='cat', TERM='dumb', NO_COLOR='1')
            # Like curl -q: ldaprc/ldap.conf could otherwise supply a hidden URI or bind settings.
            if tool.name == 'ldapsearch':
                env['LDAPNOINIT'] = '1'
            kwargs = {'start_new_session': True} if os.name == 'posix' else {
                'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
            if job.cancel.is_set():
                job.status = 'cancelled'
                return
            proc = subprocess.Popen(cmd, cwd=str(self.ws.outputs), env=env,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, **kwargs)
            job.process = proc
            self.ws.event('job_started', job=job.id, tool=job.tool, args=job.args, effective_args=args, binary=binary)
            self._write()

            def watchdog():
                deadline = time.monotonic() + tool.timeout
                while not job.done.wait(.1):
                    if job.cancel.is_set() or time.monotonic() >= deadline:
                        job.status = 'cancelled' if job.cancel.is_set() else 'timed_out'
                        stop_group(proc)
                        return
            timer = threading.Thread(target=watchdog, daemon=True)
            timer.start()
            decoder = codecs.getincrementaldecoder('utf-8')('replace')
            count = 0
            with job.path.open('a', encoding='utf-8') as f:
                # Metadata is kept outside evidence text so a command is not mistaken for proof.
                while True:
                    chunk = os.read(proc.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    # Progress bars redraw with \r; as newlines they stay separate from result lines.
                    text = redact(decoder.decode(chunk).replace('\r\n', '\n').replace('\r', '\n'))
                    count += len(chunk)
                    if count > MAX_LOG:
                        job.status = 'output_limit'
                        stop_group(proc)
                        break
                    f.write(text)
                    f.flush()
                    with self.lock:
                        job.tail = (job.tail + text)[-MAX_TAIL:]
                final = redact(decoder.decode(b'', final=True))
                f.write(final)
                job.tail = (job.tail + final)[-MAX_TAIL:]
            proc.wait(timeout=5)
            if job.status == 'running':
                job.status = 'completed' if proc.returncode == 0 else 'failed'
            job.returncode = proc.returncode
            if xml and xml.exists():
                job.summary = parse_nmap_xml(xml)
                self.ws.register(xml, tool=job.tool, job=job.id, format='nmap_xml')
        except Exception as e:
            if job.process:
                stop_group(job.process)
                try:
                    job.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            job.status, job.error = 'failed', redact(str(e))
        finally:
            if job.process and job.process.stdout:
                job.process.stdout.close()
            job.ended = time.time()
            try:
                self.ws.register(job.path, tool=job.tool, job=job.id, status=job.status)
                job.sha256 = hashlib.sha256(job.path.read_bytes()).hexdigest()
                self.ws.event('job_finished', **job.record())
            finally:
                try:
                    self._write()
                finally:
                    job.done.set()

    def get(self, jid):
        with self.lock:
            if jid not in self.jobs:
                raise ValueError('Unknown job ID (old jobs are in the audit log)')
            return self.jobs[jid]

    def result(self, jid):
        job = self.get(jid)
        return json.dumps({**job.record(), 'source': job.path.relative_to(self.ws.root).as_posix(),
                           'summary': job.summary, 'output_tail': clean_output(job.tail)}, ensure_ascii=False)

    def stop(self, jid='all'):
        jobs = self.active() if jid == 'all' else [self.get(jid)]
        for job in jobs:
            job.cancel.set()
        return len(jobs)

    def close(self):
        self.closed = True
        self.stop()
        for job in list(self.jobs.values()):
            job.done.wait(10)
