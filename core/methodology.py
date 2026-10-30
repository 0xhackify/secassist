"""Deterministic assessment methodology: fixed phases and data-defined service playbooks.

The same target, facts and installed tools always produce the same steps in the same order.
The model analyzes results and records findings; it does not choose these checks.
Every step still crosses policy validation and approval; a grant covers only what policy allows.
"""
import collections
import datetime
import ipaddress
import re
import shlex
from dataclasses import dataclass
from .facts import Facts, port_key
from .storage import atomic_json, read_json
from .toolcheck import wordlists
from .tools import REGISTRY

PHASES = ('discovery', 'enumeration', 'vulnerability', 'validation', 'reporting')
TOOL_PHASES = PHASES[:3]
FINISHED = {'completed', 'failed', 'skipped', 'blocked', 'not_applicable', 'manual'}


@dataclass
class Step:
    id: str
    phase: str
    service: str
    tool: str
    args: list
    purpose: str
    expected: str
    observation: str
    after: tuple = ()
    note: str = ''         # why the step cannot run on this machine or target
    note_status: str = ''  # blocked | not_applicable | manual


# A check is (id, alternatives, purpose, expected). The first installed alternative is used.
# Templates: {host} {url} {hostport} {ldap_uri} {wordlist} {domain} {ports}; {terms} expands to several args.
DISCOVERY = (
    ('discovery.top-ports', [('nmap', ['-sT', '-sV', '-Pn', '--top-ports', '1000', '--max-retries', '2', '{host}'])],
     'Inventory the 1000 most common TCP ports with service and version probes.',
     'Open ports with service banners. -Pn treats the host as up, so an empty result does not prove it is down.'),
    ('discovery.all-ports', [('nmap', ['-sT', '-Pn', '-p-', '--min-rate', '1000', '--max-retries', '2', '{host}'])],
     'Find open TCP ports outside the top 1000.',
     'The complete open TCP port list; ports without a version probe get one next.'),
)
NEW_PORT_VERSIONS = (
    'discovery.new-port-versions', [('nmap', ['-sT', '-sV', '-Pn', '-p', '{ports}', '{host}'])],
    'Probe service versions on ports found only by the full port scan.',
    'Service and version banners for those ports.')
WEB = (
    ('web.fingerprint', [('whatweb', ['-a', '1', '{url}'])],
     'Identify web server, framework and CMS technologies.', 'Technology and version indicators.'),
    ('web.headers', [('curl', ['-s', '-I', '-k', '--max-time', '15', '{url}'])],
     'Record status and response headers without following redirects.',
     'Server and security headers; a redirect target needs explicit scope before it is requested.'),
    ('web.waf', [('wafw00f', ['-r', '{url}'])],
     'Detect a WAF before content discovery so rates and results are interpreted correctly.',
     'A WAF product, or none detected; a negative result is not proof.'),
    ('web.content', [('gobuster', ['dir', '-u', '{url}', '-w', '{wordlist}', '-t', '20', '-q', '-k']),
                     ('ffuf', ['-u', '{url}/FUZZ', '-w', '{wordlist}', '-t', '20', '-ac', '-s'])],
     'Discover unlinked content with a common wordlist.',
     'Paths with status codes; wildcard responses are calibrated or reported as an error.'),
)
TLS = (('web.tls', [('sslscan', ['--no-colour', '{hostport}'])],
        'Review TLS protocols, ciphers and the certificate.',
        'Protocol and cipher support, certificate names and expiry.'),)
SMB = (
    ('smb.shares', [('smbclient', ['-N', '-L', '//{host}'])],
     'List SMB shares with a null session.',
     'Share names, or access denied; a denial does not prove shares are absent.'),
    ('smb.enum', [('enum4linux-ng', ['-A', '{host}'])],
     'Enumerate SMB/RPC domain, OS, users, groups and password policy where anonymous access allows.',
     'Domain and OS details and any anonymously readable objects.'),
)
LDAP = (('ldap.rootdse', [('ldapsearch', ['-x', '-H', '{ldap_uri}', '-s', 'base', 'namingcontexts'])],
         'Read the LDAP root DSE naming contexts anonymously.',
         'Naming contexts such as the domain DN, or an authentication error.'),)
DNS = (('dns.zone-transfer', [('dig', ['axfr', '@{host}', '{domain}'])],
        'Test whether the DNS server allows a zone transfer for the target domain.',
        'Zone records if transfers are allowed, otherwise "Transfer failed".'),)
EXPLOIT_DB = ('vuln.exploit-db', [('searchsploit', ['{terms}'])],
              'Look up public exploits for the exact product and version (offline database).',
              'Candidate exploits; a version match is a lead, not proof of vulnerability.')
NUCLEI = ('vuln.nuclei', [('nuclei', ['-u', '{url}', '-severity', 'medium,high,critical', '-rl', '50', '-silent'])],
          'Run medium-to-critical nuclei templates against the web service.',
          'Template matches to verify manually; scanner alerts are leads, not confirmed findings.')
MISSING = {
    'wordlist': ('blocked', 'No web wordlist installed: sudo apt install wordlists (or seclists); see /wordlists'),
    'domain': ('not_applicable', 'Needs a domain name: select the domain with /target to test it'),
    'ports': ('not_applicable', 'Every open port already has a version probe'),
    'terms': ('not_applicable', 'No product version banner'),
}
WEB_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888}
HTTPS_PORTS = {443, 8443}
WINRM_PORTS = {5985, 5986, 47001}  # Microsoft HTTPAPI management endpoints: content discovery there is noise
GENERIC_WORDS = {'httpd', 'smbd', 'sshd', 'ftpd', 'daemon', 'server', 'service'}


def classify(key, info):
    number, _, proto = key.partition('/')
    port, name = int(number), info.get('service', '')
    if proto != 'tcp' or port in WINRM_PORTS:
        return None
    if (name.startswith('http') and 'rpc' not in name) or (not name and port in WEB_PORTS):
        return 'web'
    if name in ('microsoft-ds', 'netbios-ssn') or port in (139, 445):
        return 'smb'
    if name.startswith('ldap') or port in (389, 636, 3268, 3269):
        return 'ldap'
    if name == 'domain' or port == 53:
        return 'dns'
    return None


def search_terms(info):
    words = [w for w in info.get('product', '').split() if w.lower() not in GENERIC_WORDS][:3]
    version = info.get('version', '').split()[:1]
    return words + version if words and version else []


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Methodology:
    def __init__(self, workspace):
        self.ws = workspace
        self.facts = Facts(workspace)
        self.path = workspace.root / 'methodology.json'
        self.ingested = set()
        state = self.state()
        stale = [rec for rec in state.values() if rec.get('status') == 'running']
        for rec in stale:  # jobs belong to a process that has ended
            rec.update(status='failed', reason='Interrupted: SecAssist exited while it ran; /retry ID')
        if stale:
            self.save(state)

    def active(self):
        return self.ws.target != 'general'

    def state(self):
        value = read_json(self.path, {})
        if not isinstance(value, dict):
            raise ValueError('Invalid methodology store')
        return value

    def save(self, state):
        atomic_json(self.path, state)

    def host_label(self, address):
        """Steps use the authorized target as written (a hostname keeps vhosts and scope intact)."""
        return address if '/' in self.ws.target else self.ws.target

    def domain(self):
        target = self.ws.target
        try:
            ipaddress.ip_network(target, strict=False)
            return None
        except ValueError:
            return target

    def build(self, step_id, phase, service, spec, values, observation, after=()):
        _, alternatives, purpose, expected = spec
        installed = [(t, a) for t, a in alternatives if t in REGISTRY and REGISTRY[t].binary()]
        tool, template = installed[0] if installed else (alternatives[0][0], None)
        step = Step(step_id, phase, service, tool, [], purpose, expected, observation, tuple(after))
        if template is None:
            step.note_status = 'blocked'
            step.note = 'Not installed: ' + ' or '.join(t for t, _ in alternatives) + ' (see /tools)'
            return step
        needed = sorted({k for part in template for k in re.findall(r'\{(\w+)\}', part)})
        missing = [k for k in needed if not values.get(k)]
        if missing:
            step.note_status, step.note = MISSING[missing[0]]
            return step
        for part in template:
            step.args += list(values['terms']) if part == '{terms}' else [part.format(**values)]
        return step

    def steps(self, state=None):
        if not self.active():
            return []
        state = self.state() if state is None else state
        target = self.ws.target
        baseline = 'No service inventory yet; baseline discovery.'
        steps = [self.build(DISCOVERY[0][0], 'discovery', 'host', DISCOVERY[0], {'host': target}, baseline),
                 self.build(DISCOVERY[1][0], 'discovery', 'host', DISCOVERY[1], {'host': target}, baseline,
                            after=(DISCOVERY[0][0],))]
        services = self.facts.services()
        if state.get(DISCOVERY[1][0], {}).get('status') == 'completed':
            ports = sorted({key for _, key, info in services if key.endswith('/tcp') and not info.get('probed')},
                           key=port_key)
            steps.append(self.build(NEW_PORT_VERSIONS[0], 'discovery', 'host', NEW_PORT_VERSIONS,
                                    {'host': target, 'ports': ','.join(k.split('/')[0] for k in ports)},
                                    'Full port scan found ports without a version probe: ' + (', '.join(ports) or 'none'),
                                    after=(DISCOVERY[1][0],)))
        web_common = wordlists()['web-common']
        smb_hosts, seen_terms, vulnerability = set(), set(), []
        for address, key, info in services:
            host = self.host_label(address)
            bracketed = f'[{host}]' if ':' in host else host
            port = int(key.split('/')[0])
            where = f'{host}:{port}'
            service = f"{address} {key} {info.get('service') or 'unknown'}"
            observation = (f"nmap ({', '.join(info.get('sources', [])) or 'facts'}): {address} {key} "
                           f"{info.get('state', 'open')} {self.facts.describe(info)}")
            kind = classify(key, info)
            if kind == 'web':
                tls = info.get('tunnel') == 'ssl' or info.get('service') in ('https', 'https-alt') or port in HTTPS_PORTS
                scheme = 'https' if tls else 'http'
                default_port = port == (443 if tls else 80)
                values = {'url': f'{scheme}://{bracketed}' + ('' if default_port else f':{port}'),
                          'hostport': f'{bracketed}:{port}', 'wordlist': web_common}
                for spec in WEB + (TLS if tls else ()):
                    steps.append(self.build(f'{spec[0]}@{where}', 'enumeration', service, spec, values, observation))
                vulnerability.append(self.build(f'{NUCLEI[0]}@{where}', 'vulnerability', service, NUCLEI,
                                                values, observation))
            elif kind == 'smb':
                if address not in smb_hosts:
                    smb_hosts.add(address)
                    for spec in SMB:
                        steps.append(self.build(f'{spec[0]}@{host}', 'enumeration', f'{address} smb', spec,
                                                {'host': host}, observation))
            elif kind == 'ldap':
                scheme = 'ldaps' if port in (636, 3269) or info.get('tunnel') == 'ssl' else 'ldap'
                for spec in LDAP:
                    steps.append(self.build(f'{spec[0]}@{where}', 'enumeration', service, spec,
                                            {'ldap_uri': f'{scheme}://{bracketed}:{port}'}, observation))
            elif kind == 'dns':
                for spec in DNS:
                    steps.append(self.build(f'{spec[0]}@{where}', 'enumeration', service, spec,
                                            {'host': host, 'domain': self.domain()}, observation))
            else:
                steps.append(Step(f'manual.review@{where}', 'enumeration', service, '', [],
                                  'No playbook covers this service.', 'Manual review or an off-methodology proposal.',
                                  observation, note='No playbook for this service; review it manually',
                                  note_status='manual'))
            terms = search_terms(info)
            if terms and tuple(terms) not in seen_terms:
                seen_terms.add(tuple(terms))
                vulnerability.append(self.build(f"{EXPLOIT_DB[0]}:{'-'.join(terms).lower()}", 'vulnerability',
                                                service, EXPLOIT_DB, {'terms': terms}, observation))
        return steps + vulnerability

    def evaluate(self):
        """([(step, status, reason)], current phase). A phase starts only when earlier phases are finished."""
        state = self.state()
        rows, current, status_of = [], None, {}
        steps = self.steps(state)
        for phase in TOOL_PHASES:
            for step in (s for s in steps if s.phase == phase):
                rec = state.get(step.id)
                if rec:
                    status, reason = rec['status'], rec.get('reason', '')
                elif step.note:
                    status, reason = step.note_status, step.note
                elif current is not None or any(status_of.get(d) not in FINISHED for d in step.after):
                    status, reason = 'pending', ''
                else:
                    status, reason = 'ready', ''
                status_of[step.id] = status
                rows.append((step, status, reason))
            if current is None and any(st not in FINISHED for s, st, _ in rows if s.phase == phase):
                current = phase
        if current is None:
            suspected = any(f.get('status') == 'suspected' for f in self.ws.findings())
            current = 'validation' if suspected else 'reporting'
        return rows, current

    def ready(self):
        return [s for s, status, _ in self.evaluate()[0] if status == 'ready']

    def card(self, step):
        return {'tool': step.tool, 'args': list(step.args), 'observation': step.observation,
                'hypothesis': f'Standard {step.phase} check for {step.service}.',
                'purpose': f'Methodology step {step.id}: {step.purpose}', 'expected': step.expected,
                'stop_condition': 'Completion, tool timeout, output cap, or /stop.'}

    def record(self, step_id, status, **meta):
        with self.ws.lock:
            state = self.state()
            state[step_id] = {**state.get(step_id, {}), 'status': status, 'time': now(), **meta}
            self.save(state)
        self.ws.event('methodology_step', step=step_id, status=status, **meta)

    def start(self, step, job):
        edited = job.tool != step.tool or job.args[:len(step.args)] != step.args
        self.record(step.id, 'running', job=job.id, command=shlex.join([job.tool] + job.args),
                    edited_by_operator=edited, reason='')

    def find(self, step_id):
        rows = {s.id: (s, status) for s, status, _ in self.evaluate()[0]}
        if step_id not in rows:
            raise ValueError('Unknown step ID; /methodology lists them')
        return rows[step_id]

    def skip(self, step_id, reason=''):
        _, status = self.find(step_id)
        if status == 'running':
            raise ValueError('Step is running; /stop its job first')
        self.record(step_id, 'skipped', reason=reason.strip() or 'Skipped by operator')

    def retry(self, step_id):
        _, status = self.find(step_id)
        if status == 'running':
            raise ValueError('Step is already running')
        with self.ws.lock:
            state = self.state()
            state.pop(step_id, None)
            self.save(state)
        self.ws.event('methodology_step', step=step_id, status='reset')

    def sync(self, jobs):
        """Main thread: ingest nmap XML from any completed nmap job and close finished steps."""
        for job in list(jobs.jobs.values()):
            if job.done.is_set() and job.tool == 'nmap' and job.id not in self.ingested:
                self.ingested.add(job.id)
                xml = self.ws.outputs / f'nmap_{job.id}.xml'
                if xml.is_file():
                    self.facts.ingest_nmap(xml, xml.relative_to(self.ws.root).as_posix())
        for step_id, rec in self.state().items():
            if rec.get('status') != 'running':
                continue
            job = jobs.jobs.get(rec.get('job'))
            if job is None:
                self.record(step_id, 'failed', reason='Job is not part of this process; /retry ID')
            elif job.done.is_set():
                ok = job.status == 'completed'
                self.record(step_id, 'completed' if ok else 'failed', exit=job.returncode,
                            output=job.path.relative_to(self.ws.root).as_posix(),
                            reason='' if ok else f'{job.status}, exit {job.returncode}; review the output')

    def summary(self):
        rows, phase = self.evaluate()
        return {'phase': phase, 'counts': dict(sorted(collections.Counter(st for _, st, _ in rows).items())),
                'ready': [s.id for s, st, _ in rows if st == 'ready'],
                'running': [s.id for s, st, _ in rows if st == 'running'],
                'not_run': [f'{s.id} [{st}]: {r}' for s, st, r in rows
                            if st in ('blocked', 'failed', 'skipped', 'manual')][:30]}

    def coverage(self):
        rows, phase = self.evaluate()
        state = self.state()
        return {'phase': phase, 'steps': [
            {'id': s.id, 'phase': s.phase, 'service': s.service, 'tool': s.tool, 'status': st, 'note': r,
             'command': state.get(s.id, {}).get('command') or (shlex.join([s.tool] + s.args) if s.args else ''),
             'output': state.get(s.id, {}).get('output', '')} for s, st, r in rows]}
