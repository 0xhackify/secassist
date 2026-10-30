#!/usr/bin/env python3
"""SecAssist 3: evidence-led CLI assessments with managed background jobs."""
import argparse
import datetime
import getpass
import json
import os
import select
import shlex
import shutil
import sys
import time
import uuid
from pathlib import Path

from core import __version__, ui
from core.agent import Agent
from core.client import ChatClient, THINKING_LEVELS
from core.jobs import JobManager
from core.notes import NotesIndex
from core.policy import Policy, MODES
from core.scope import Scope, normalize
from core.storage import atomic_json, read_json, redact
from core.terminal import Terminal
from core.tools import REGISTRY
from core.workspace import Workspace

HERE = Path(__file__).resolve().parent
HELP = """
SecAssist 3 — Arabic/English evidence-led assessment assistant
/target HOST            select target; asks to authorize it if new
/scope                  list scope
/scope add TARGET       authorize IP/CIDR/domain/*.domain/URL
/scope remove TARGET    revoke entry and invalidate auto grant
/scope import PATH      review/import a legacy scope file
/mode explain           analysis only, no native tools
/mode manual            propose commands for you to run
/mode ask               confirm every command (default)
/mode auto RISK MIN N   grant risk ceiling for MIN minutes and N commands
                       RISK: recon | active | intrusive; never bypass scope
/run TOOL ARGS          managed command, follows mode/approval
/jobs                   IDs, states, outputs
/watch ID               live output (Ctrl+C returns; does not stop job)
/stop ID|all            stop tool process groups and revoke auto grant
/wait                   wait for current jobs and analyze results
/continue               analyze completed evidence and continue
/parallel 1..4          limit running jobs; default 2
/panes on|off           adjacent tmux output/status panes
/plan                   show evidence-led assessment plan
/findings               show suspected / user-confirmed findings
/confirm ID             human confirms a finding after reviewing evidence
/outputs                list registered evidence
/import PATH            copy local evidence to target
/file PATH QUESTION     import then ask AI (sends evidence to API)
/report                 factual local Markdown + JSON export; no API call
/resume                 restore history for current target; approvals reset
/clear                  clear conversation, keep evidence
/notes QUERY            local notes search
/tools [NAME|CATEGORY]  installed tools, descriptions and install hints
/doctor                 offline environment check
/setup                  configure endpoint/model and in-memory API key
/model NAME             select model and save non-secret preference
/think off|low|high|max  API effort; decision summaries stay visible
/cost                   token usage
/help /exit
"""


class App:
    def __init__(self, args):
        self.args = args
        self.data = Path(args.data).expanduser().resolve()
        self.data.mkdir(parents=True, exist_ok=True)
        if os.name == 'posix':
            os.chmod(self.data, 0o700)
        self.config_path = self.data / 'config.json'
        self.config = read_json(self.config_path, {})
        self.client = ChatClient(args.base_url or self.config.get('base_url', 'https://api.deepseek.com'),
                                 os.environ.get('DEEPSEEK_API_KEY', ''),
                                 args.model or self.config.get('model', 'deepseek-flash'),
                                 args.think or self.config.get('think', 'high'))
        self.scope = Scope(self.data / 'scope.json')
        self.policy = Policy(self.scope)
        self.policy.mode = args.mode
        self.notes = NotesIndex(args.notes)
        self.notified = set()
        self.activate('general')
        if args.target:
            self.target(args.target)

    def activate(self, target):
        self.ws = Workspace(self.data / 'workspace', target)
        self.jobs = JobManager(self.ws, self.args.parallel)
        self.terminal = Terminal(self.ws, Path(__file__))
        self.jobs.on_start = self.terminal.show
        self.agent = Agent(self.client, self.scope, self.ws, self.notes, self.policy,
                           self.jobs, self.args.max_steps)
        self.notified = set()
        if os.environ.get('TMUX') and self.args.panes:
            try:
                self.terminal.enable()
            except (ValueError, OSError) as e:
                ui.warn(str(e))

    def banner(self):
        print(ui.c(f'SecAssist {__version__}', ui.BOLD, ui.CYAN))
        print(f'Target={self.ws.target} | mode={self.policy.mode} | model={self.client.model} | parallel={self.jobs.max_jobs}')
        print('أضف الهدف بـ /target أو /scope add. الوضع ask يطلب موافقتك لكل أمر.')
        print('AI inputs/evidence go to the configured API. /setup for key; /help for commands.')
        print('API secrets stay in memory/environment; tool arguments/outputs are saved locally.')
        if not self.client.api_key:
            print('No API key: offline commands are available.')

    def save_config(self):
        atomic_json(self.config_path, {'base_url': self.client.base_url, 'model': self.client.model,
                                      'think': self.client.thinking})

    def setup(self):
        print('Non-secret preferences are saved. API key is hidden and kept only in this process.')
        base = ui.ask(f'API URL [{self.client.base_url}]: ').strip() or self.client.base_url
        model = ui.ask(f'Model [{self.client.model}]: ').strip() or self.client.model
        key = getpass.getpass('API key (Enter keeps current/environment key): ').strip() or self.client.api_key
        self.client = ChatClient(base, key, model, self.client.thinking)
        self.agent.client = self.client
        self.save_config()
        ui.ok('Configured. No key written to disk.')

    def target(self, text):
        if not text:
            print(self.ws.target)
            return
        target = normalize(text)
        if target.startswith('*.'):
            raise ValueError('Choose a concrete current target; wildcard belongs in /scope add')
        if self.jobs.active():
            raise ValueError('Stop or finish current jobs before switching target')
        if not self.scope.allows(target):
            print(f'New target: {target}')
            if ui.ask('Authorize this target? Type yes: ').strip().lower() != 'yes':
                return
            self.scope.add(target)
        panes = self.terminal.enabled
        self.terminal.close()
        self.jobs.close()
        self.policy.mode, self.policy.expires = 'ask', 0
        self.activate(target)
        if panes and not self.terminal.enabled:
            self.terminal.enable()
        ui.ok(f'Target: {target}. Approvals reset to ask. /resume restores previous context.')

    def scope_cmd(self, rest):
        parts = shlex.split(rest)
        if not parts:
            print('\n'.join(self.scope.describe()) or '(empty)')
            return
        if len(parts) != 2:
            raise ValueError('Usage: /scope add|remove|import VALUE')
        op, value = parts
        if op == 'add':
            self.scope.add(value)
        elif op == 'remove':
            self.scope.remove(value)
        elif op == 'import':
            entries = [x.split('#', 1)[0].strip() for x in Path(value).read_text(encoding='utf-8-sig').splitlines()]
            entries = [normalize(x) for x in entries if x]
            print('\n'.join(entries) or '(empty file)')
            if ui.ask('Import these authorized entries? Type yes: ').strip().lower() != 'yes':
                return
            for entry in entries:
                self.scope.add(entry)
        else:
            raise ValueError('Use add, remove, or import')
        self.policy.mode, self.policy.expires = 'ask', 0
        self.ws.event('scope_changed', entries=self.scope.describe())
        print('Scope saved; mode reset to ask. Running jobs keep original scope; /stop all to cancel.')

    def mode(self, rest):
        p = rest.split()
        if not p:
            print(f'{self.policy.mode}; ceiling={self.policy.ceiling}; commands remaining={self.policy.remaining}')
            return
        if p[0] not in MODES:
            raise ValueError('Modes: explain manual ask auto')
        if p[0] == 'auto':
            risk = p[1] if len(p) > 1 else 'active'
            minutes = int(p[2]) if len(p) > 2 else 30
            commands = int(p[3]) if len(p) > 3 else 20
            if self.scope.is_empty():
                raise ValueError('Add an authorized scope first')
            if risk not in ('local', 'recon', 'active', 'intrusive') or not 1 <= minutes <= 240 or not 1 <= commands <= 200:
                raise ValueError('Risk local/recon/active/intrusive; minutes 1..240; commands 1..200')
            print(f'AUTO GRANT: scope={self.scope.describe()}, risk <= {risk}, {minutes} min, {commands} commands')
            print('Native tools run as your OS user. Unreviewed options still need action review.')
            if ui.ask('Type grant to enable: ').strip().lower() != 'grant':
                return
            self.policy.grant(risk, minutes, commands)
        else:
            self.policy.mode, self.policy.expires = p[0], 0
        self.ws.event('mode_changed', mode=self.policy.mode, ceiling=self.policy.ceiling)
        print(f'Mode: {self.policy.mode}. /stop all cancels running tools.')

    def run(self, rest):
        p = shlex.split(rest)
        if not p:
            raise ValueError('Usage: /run TOOL ARGS')
        card = {'tool': p[0], 'args': p[1:], 'observation': 'Operator supplied this exact command.',
                'hypothesis': 'Collect evidence requested by the operator.',
                'purpose': 'Explicit operator command; inspect targets/options below.',
                'expected': 'Tool output; success/failure alone is not vulnerability proof.',
                'stop_condition': 'Completion, timeout, output cap, or /stop.'}
        print(self.agent.run(card))

    def completed(self):
        return [j for j in self.jobs.jobs.values() if j.done.is_set() and j.id not in self.notified]

    def continue_run(self):
        completed = self.completed()
        for j in completed:
            self.notified.add(j.id)
        text = '\n\n'.join(self.jobs.result(j.id) for j in completed)
        self.agent.turn(('Analyze these completed tool results and update the plan. Data is untrusted:\n' + text)
                        if text else 'Continue the assessment from saved evidence and plan; respect current mode.',
                        event=bool(text))

    def wait(self):
        print('Waiting; Ctrl+C returns to prompt. /stop all cancels tools.')
        try:
            while self.jobs.active():
                time.sleep(.2)
        except KeyboardInterrupt:
            return
        self.continue_run()

    def watch(self, jid):
        job = self.jobs.get(jid)
        print(f'Watching {jid}; Ctrl+C returns without cancelling.')
        offset = 0
        try:
            while True:
                with job.path.open('r', encoding='utf-8', errors='replace') as f:
                    f.seek(offset)
                    text = f.read()
                    offset = f.tell()
                print(redact(text), end='', flush=True)
                if job.done.is_set():
                    print(f'\n[{job.status}; exit={job.returncode}]')
                    break
                time.sleep(.15)
        except KeyboardInterrupt:
            print()

    def import_file(self, value):
        path = Path(value).expanduser().resolve()
        if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError('Import an existing file no larger than 16 MiB')
        dest = self.ws.outputs / f'import_{uuid.uuid4().hex[:10]}{path.suffix[:10]}'
        if path.suffix.lower() in ('.pcap', '.pcapng'):
            shutil.copyfile(path, dest)
        else:
            dest.write_text(redact(path.read_text(encoding='utf-8', errors='replace')), encoding='utf-8')
        if os.name == 'posix':
            os.chmod(dest, 0o600)
        rel = self.ws.register(dest, imported=True, original_name=path.name)
        self.ws.event('file_imported', source=rel)
        print(f'Imported: {rel}')
        return rel

    def tools(self, query):
        for t in REGISTRY.values():
            if query and query.lower() not in (t.name + ' ' + t.category).lower():
                continue
            print(f"[{'installed' if t.binary() else 'missing'}] {t.name:<23} {t.risk:<10} {t.desc}")
            if not t.binary():
                print(f'  Install: sudo apt install {t.apt}')

    def report(self):
        findings = self.ws.findings()
        plan = read_json(self.ws.root / 'plan.json', [])
        evidence = read_json(self.ws.root / 'evidence.json', {})
        jobs = [j.record() for j in self.jobs.jobs.values()]
        stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        data = {'target': self.ws.target, 'scope': self.scope.describe(),
                'generated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'findings': findings, 'plan': plan, 'evidence': evidence, 'current_process_jobs': jobs}
        out = self.ws.root / f'report_{stamp}'
        atomic_json(out.with_suffix('.json'), data)
        lines = [f'# SecAssist assessment: {self.ws.target}', '', f"Generated: {data['generated_utc']}", '',
                 '## Scope', *['- ' + x for x in self.scope.describe()], '',
                 '## Limitations', 'Automated observations require interpretation. Suspected findings are not confirmed.',
                 'Missing findings do not imply coverage or absence of vulnerabilities. Review the plan below.',
                 'Network egress is not sandboxed. Full audit: audit.jsonl; output hashes are recorded.', '',
                 '## Assessment plan / coverage']
        lines += [f"- [{x['status']}] {x['question']} — {x.get('evidence', '')}" for x in plan] or ['No assessment plan; coverage unknown.']
        lines += ['', '## Findings']
        if not findings:
            lines += ['No findings recorded; this does not establish absence of vulnerabilities.']
        for f in findings:
            lines += ['', f"### #{f['id']} {f['title']}", f"Severity: {f['severity']}; status: {f['status']}",
                      f"Source: {f['source']}", '', f['description'], '', 'Evidence:', '~~~text', f['evidence'],
                      '~~~', '', 'Remediation: ' + f['remediation']]
        lines += ['', '## Evidence inventory']
        lines += [f"- {p} | SHA256 {meta['sha256']} | {meta.get('status', 'imported/parsed')}" for p, meta in evidence.items()]
        out.with_suffix('.md').write_text(redact('\n'.join(lines)), encoding='utf-8')
        print(f'Reports: {out}.md and .json')

    def handle(self, line):
        if not line.startswith('/'):
            self.agent.turn(line)
            return True
        cmd, _, rest = line.partition(' ')
        rest = rest.strip()
        if cmd in ('/exit', '/quit'):
            return False
        if cmd == '/help': print(HELP)
        elif cmd == '/target': self.target(rest)
        elif cmd == '/scope': self.scope_cmd(rest)
        elif cmd == '/mode': self.mode(rest)
        elif cmd == '/run': self.run(rest)
        elif cmd == '/setup': self.setup()
        elif cmd == '/tools': self.tools(rest)
        elif cmd == '/jobs':
            for j in self.jobs.jobs.values():
                print(f'{j.id} {j.tool:<22} {j.status:<14} exit={j.returncode} {j.path.name}')
        elif cmd == '/stop':
            print(f'Cancellation requested: {self.jobs.stop(rest or "all")} job(s)')
            self.policy.mode, self.policy.expires = 'ask', 0
        elif cmd == '/watch': self.watch(rest)
        elif cmd == '/wait': self.wait()
        elif cmd == '/continue': self.continue_run()
        elif cmd == '/plan': print(json.dumps(self.agent.plan, ensure_ascii=False, indent=2))
        elif cmd == '/findings': print(self.ws.findings_summary())
        elif cmd == '/confirm': self.ws.confirm(int(rest))
        elif cmd == '/outputs': print('\n'.join(self.ws.list_outputs()) or '(none)')
        elif cmd == '/import':
            p = shlex.split(rest)
            if len(p) != 1: raise ValueError('/import PATH (quote spaces)')
            self.import_file(p[0])
        elif cmd == '/file':
            p = shlex.split(rest)
            if not p: raise ValueError('/file PATH [QUESTION]')
            rel = self.import_file(p[0])
            text = self.agent.dispatch('read_output', {'path': rel})
            self.agent.turn((' '.join(p[1:]) or 'Analyze this imported evidence') + '\n' + text)
        elif cmd == '/report': self.report()
        elif cmd == '/resume':
            if self.jobs.active(): raise ValueError('Finish or stop jobs first')
            self.policy.mode, self.policy.expires = 'ask', 0
            self.agent.resume()
            print('Context restored. Mode reset to ask; grants are never restored.')
        elif cmd == '/clear': self.agent.clear()
        elif cmd == '/notes':
            for src, text, _ in self.notes.search(rest): print(f'{src}\n{redact(text)}\n')
        elif cmd == '/model':
            if rest:
                self.client.model = rest
                self.save_config()
            print(self.client.model)
        elif cmd == '/think':
            if rest not in THINKING_LEVELS: raise ValueError('Use off/low/high/max. Decision summaries stay visible.')
            self.client.thinking = rest
            self.save_config()
        elif cmd == '/cost': print(json.dumps(self.client.usage))
        elif cmd == '/parallel':
            n = int(rest)
            if not 1 <= n <= 4: raise ValueError('Parallel jobs must be 1..4')
            if n < len(self.jobs.active()): raise ValueError('Stop/finish some jobs first')
            self.jobs.max_jobs = n
        elif cmd == '/panes':
            if rest == 'on': self.terminal.enable()
            elif rest == 'off': self.terminal.close()
            else: raise ValueError('/panes on|off')
        elif cmd == '/doctor':
            print(f'Python: {sys.version.split()[0]} | OS: {sys.platform} | data: {self.data}')
            print(f'tmux: {shutil.which("tmux") or "missing"} | tools installed: {len(self.agent.installed_tools())}/{len(REGISTRY)}')
            print(f'API key: {"set" if self.client.api_key else "missing"} | scope entries: {len(self.scope.entries)}')
        else: raise ValueError('Unknown command. /help')
        return True

    def loop(self):
        self.banner()
        try:
            while True:
                prompt = f'[{self.ws.target}|{self.policy.mode}] you> '
                if os.name == 'posix' and sys.stdin.isatty():
                    print(prompt, end='', flush=True)
                    while not select.select([sys.stdin], [], [], .3)[0]:
                        if self.completed() and self.policy.mode == 'auto':
                            print()
                            self.continue_run()
                            print(prompt, end='', flush=True)
                    line = sys.stdin.readline()
                    if not line: break
                    line = line.strip()
                else:
                    line = ui.ask(prompt).strip()
                if line and not self.handle(line):
                    break
        except (EOFError, KeyboardInterrupt):
            print()
        finally:
            self.close()

    def close(self):
        self.jobs.close()
        self.terminal.close()
        self.ws.save_session(self.agent.turns, self.agent.plan)


def viewer(args):
    root = Path(args.viewer_root).resolve()
    try:
        if args.viewer == 'status':
            while True:
                data = read_json(root / 'jobs.json', [])
                print('\033[2J\033[H' + 'SecAssist — jobs / المهام\n' +
                      '\n'.join(f"{x['id']}  {x['tool']:<20} {x['status']}  exit={x['returncode']}" for x in data),
                      flush=True)
                for step in read_json(root / 'plan.json', []):
                    print(redact(f"[{step['status']}] {step['question']}"))
                time.sleep(.7)
        else:
            offset = 0
            while True:
                jobs = read_json(root / 'jobs.json', [])
                job = next((j for j in jobs if j['id'] == args.job), None)
                if job:
                    path = root / 'outputs' / Path(job['output']).name
                    if path.is_file():
                        with path.open(encoding='utf-8', errors='replace') as f:
                            f.seek(offset)
                            print(redact(f.read()), end='', flush=True)
                            offset = f.tell()
                    if job['status'] not in ('running', 'queued'):
                        print(f"\n[{job['status']}; exit={job['returncode']}]")
                        if sys.stdin.isatty():
                            input('Enter closes this output pane. Output remains saved. ')
                        return
                time.sleep(.15)
    except (KeyboardInterrupt, EOFError):
        pass


def main():
    p = argparse.ArgumentParser(description='SecAssist — evidence-led Kali assessment CLI')
    p.add_argument('--version', action='version', version=__version__)
    p.add_argument('--model', default=os.environ.get('SECASSIST_MODEL'))
    p.add_argument('--base-url', default=os.environ.get('SECASSIST_BASE_URL'))
    p.add_argument('--think', choices=THINKING_LEVELS)
    p.add_argument('--target')
    p.add_argument('--mode', choices=('ask', 'explain', 'manual'), default='ask')
    p.add_argument('--data', default=str(HERE / '.secassist'))
    p.add_argument('--notes', default=str(HERE / 'notes'))
    p.add_argument('--parallel', type=int, choices=range(1, 5), default=2)
    p.add_argument('--max-steps', type=int, default=8)
    p.add_argument('--panes', action='store_true')
    p.add_argument('-q', '--question')
    p.add_argument('--viewer', choices=('status', 'job'), help=argparse.SUPPRESS)
    p.add_argument('--viewer-root', help=argparse.SUPPRESS)
    p.add_argument('--job', help=argparse.SUPPRESS)
    args = p.parse_args()
    if args.viewer:
        if not args.viewer_root: p.error('--viewer-root required')
        viewer(args)
        return
    if not 1 <= args.max_steps <= 30: p.error('--max-steps must be 1..30')
    if os.name == 'posix': os.umask(0o077)
    try:
        app = App(args)
        if args.question:
            try: app.handle(args.question)
            finally: app.close()
        else:
            original_handle = app.handle
            def safe_handle(line):
                try: return original_handle(line)
                except (ValueError, OSError, TypeError, KeyError) as e:
                    ui.error(redact(str(e)))
                    return True
            app.handle = safe_handle
            app.loop()
    except (ValueError, OSError) as e:
        print('SecAssist: ' + redact(str(e)), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
