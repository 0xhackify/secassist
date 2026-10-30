"""Execution policy independent of model instructions.

Reviewed argument profiles enable unattended operation for common commands.
Unsupported options require human review; indirect target/config files are blocked.
This does not sandbox trusted native tools or pin DNS/network egress.
"""
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse
from .scope import extract_targets, local_file_warnings, normalize, readable
from .toolcheck import managed_defaults
from .tools import REGISTRY, RISK_ORDER, risk_for

MODES = ('explain', 'manual', 'ask', 'auto')
# Flags accepting one scalar value. Target-bearing values are also checked.
VALUES = {
    'nmap': {'-p', '--top-ports', '--max-rate', '--min-rate', '--host-timeout', '--max-retries', '--version-intensity', '--script'},
    'curl': {'--max-time', '--connect-timeout', '-X', '--request', '-H', '--header', '-d', '--data', '--data-raw'},
    'ping': {'-c', '-W', '-i'},
    'httpx': {'-u', '-timeout', '-threads', '-rate-limit'},
    'whatweb': {'-a', '--max-threads'},
    'subfinder': {'-d', '-timeout', '-max-time', '-rl'},
    'dnsx': {'-d', '-w', '-t', '-rl'},
    'ffuf': {'-u', '-w', '-t', '-rate', '-timeout', '-mc', '-fc', '-fs', '-H'},
    'feroxbuster': {'-u', '-w', '-t', '--rate-limit', '--timeout', '-d'},
    'katana': {'-u', '-d', '-c', '-rl', '-timeout'},
    'nuclei': {'-u', '-severity', '-tags', '-etags', '-rl', '-c', '-timeout'},
    'sslscan': set(), 'testssl': set(), 'dig': set(), 'host': set(), 'whois': set(), 'nslookup': set(),
    'nikto': {'-h', '-p', '-timeout'},
    'wpscan': {'--url', '-e', '--enumerate', '--max-threads'},
    'arjun': {'-u', '-t', '--rate-limit'},
    'sqlmap': {'-u', '--url', '--level', '--risk', '--threads', '--timeout', '-p'},
    'gobuster': {'-u', '--url', '-w', '--wordlist', '-t', '--threads', '-x', '--extensions', '-s', '--status-codes',
                 '-b', '--status-codes-blacklist', '--exclude-length', '--timeout', '--delay', '--domain'},
    'dirsearch': {'-u', '--url', '-w', '--wordlists', '-e', '--extensions', '-t', '--threads', '--max-rate',
                  '-i', '--include-status', '-x', '--exclude-status', '-R', '--max-recursion-depth',
                  '--timeout', '--delay'},
    'wafw00f': set(), 'enum4linux-ng': set(),
    'smbclient': {'-L', '-p', '--port', '-W', '--workgroup', '-m', '--max-protocol'},
    'ldapsearch': {'-H', '-b', '-s', '-z', '-l'},
}
VALUES['feroxbuster'] |= {'-x', '--extensions'}
VALUES['wpscan'] |= {'-t'}
BOOLS = {
    'nmap': {'-sV', '-sT', '-sS', '-sU', '-sn', '-Pn', '-n', '-v', '-vv', '--open', '--reason', '-p-', '-T0', '-T1', '-T2', '-T3', '-T4',
             '--privileged'},
    'curl': {'-q', '-s', '-S', '-i', '-I', '-k', '--silent', '--show-error', '--head', '--insecure', '-sI', '-sik', '-sS', '-sSI', '-si'},
    'ping': {'-n'}, 'httpx': {'-silent', '-status-code', '-title', '-tech-detect', '-json', '-no-fallback'},
    'whatweb': {'--no-errors'}, 'subfinder': {'-silent', '-all'},
    'dnsx': {'-silent', '-a', '-aaaa', '-cname', '-mx', '-txt', '-resp', '-json'},
    'ffuf': {'-ac', '-s', '-noninteractive'}, 'feroxbuster': {'--no-state', '--silent', '--no-recursion'},
    'katana': {'-silent', '-jsonl'}, 'nuclei': {'-silent', '-jsonl', '-duc', '-ni', '-no-interactsh'},
    'sslscan': {'--no-colour', '--show-certificate', '--no-failed'},
    'testssl': {'--quiet', '--warnings', '--color', '--fast', '--sneaky'},
    'dig': {'+short', '+noall', '+answer'}, 'host': {'-a'}, 'whois': set(), 'nslookup': set(),
    'nikto': {'-nointeractive'}, 'wpscan': {'--no-banner', '--random-user-agent'},
    'arjun': {'--stable'}, 'sqlmap': {'--batch', '--banner', '--current-db', '--current-user', '--is-dba', '--forms'},
    'gobuster': {'-q', '--quiet', '-k', '--no-tls-validation', '-e', '--expanded', '-n', '--no-status',
                 '-z', '--no-progress', '--no-error', '--append-domain'},
    'dirsearch': {'-r', '--recursive', '-q', '--quiet-mode', '--no-color', '-f', '--force-extensions',
                  '--full-url', '--random-agent'},
    'wafw00f': {'-a', '--findall', '-r', '--noredirect', '-v'},
    'enum4linux-ng': {'-A', '-As', '-U', '-G', '-Gm', '-S', '-C', '-P', '-O', '-L', '-I', '-N', '-v', '-d'},
    'smbclient': {'-N', '--no-pass', '-g', '--grepable'},
    'ldapsearch': {'-x', '-LLL', '-LL', '-L', '-Z', '-ZZ'},
}
# Unattended speed/concurrency ceilings. Higher, zero (often "unlimited") or non-numeric values need review.
CAPS = {
    'nmap': {'--min-rate': 1000},
    'ffuf': {'-t': 50, '-rate': 500},
    'feroxbuster': {'-t': 50, '--rate-limit': 500},
    'gobuster': {'-t': 50, '--threads': 50},
    'dirsearch': {'-t': 50, '--threads': 50, '--max-rate': 500},
    'httpx': {'-threads': 50, '-rate-limit': 500},
    'whatweb': {'--max-threads': 25},
    'katana': {'-c': 20, '-rl': 500},
    'nuclei': {'-c': 25, '-rl': 150},
    'dnsx': {'-t': 100, '-rl': 500},
    'arjun': {'-t': 20, '--rate-limit': 100},
    'wpscan': {'-t': 10, '--max-threads': 10},
}
# Option values that name the target itself (besides -u/--url); they are scope-checked.
TARGET_OPTIONS = {'nikto': {'-h'}, 'subfinder': {'-d'}, 'dnsx': {'-d'}, 'gobuster': {'--domain'},
                  'smbclient': {'-L'}, 'ldapsearch': {'-H'}}
# These routes hide targets, load executable content, redirect traffic, or alter local state.
BLOCKED = {
    '-iL', '-iR', '--resume', '--script', '--script-args', '--script-args-file', '--datadir',
    '--proxies', '--proxy', '-x', '--resolve', '--connect-to', '--connect-to-file',
    '-K', '--config', '-config', '-config-file', '--config-file', '-cfile',
    '--exec', '--exec-path', '-e', '-X', '--os-shell', '--os-cmd', '--sql-shell',
    '--file-write', '--file-dest', '--tamper', '--eval', '--preprocess', '--postprocess',
    '-r', '--request-file', '-l', '--list', '-list', '-target-file', '--targets',
    '--scope', '--exclude', '--exclude-file', '-o', '--output', '-oN', '-oX', '-oA', '-oG', '-oJ', '-oY',
    '--output-dir', '--directory', '-tfile', '-t', '--templates', '-code', '-headless',
}
ATTACHED_BLOCKED = ('-iL', '-iR', '-oN', '-oX', '-oA', '-oG', '-oJ', '-oY', '-K')
# Short flags mean different things per tool. These tools use them for reviewed, non-routing purposes
# (extensions, threads, login name, recursion, simple LDAP auth/time limit, no-redirect).
READ_VALUE_EXCEPTIONS = {
    '-e': {'wpscan', 'dirsearch', 'gobuster', 'hydra'},
    '-x': {'gobuster', 'feroxbuster', 'dirsearch', 'hydra', 'ldapsearch'},
    '-X': {'curl'},
    '-t': {'ffuf', 'feroxbuster', 'arjun', 'dnsx', 'gobuster', 'dirsearch', 'hydra', 'wpscan'},
    '-l': {'hydra', 'ldapsearch'},
    '-r': {'tshark', 'dirsearch', 'wafw00f'},
    '--script': {'nmap'},
}
NMAP_SCRIPTS = {'http-title', 'http-headers', 'ssl-cert', 'ssh-hostkey', 'smb-os-discovery',
                'smb-protocols', 'smb2-security-mode', 'modbus-discover', 's7-info',
                'enip-info', 'bacnet-info', 'fox-info'}
READ_WORDLIST_FLAGS = {'ffuf': {'-w'}, 'feroxbuster': {'-w'}, 'dnsx': {'-w'},
                       'gobuster': {'-w', '--wordlist'}, 'dirsearch': {'-w', '--wordlists'}}
SYSTEM_WORDLISTS = ('/usr/share/wordlists', '/usr/share/seclists')
# nmap scan types that need raw sockets; without root they fail after launch.
RAW_SOCKET_SCANS = {'-sS', '-sU', '-sA', '-sW', '-sM', '-sN', '-sF', '-sX', '-sY', '-sZ', '-sO', '-O'}


def privileged():
    return os.name != 'posix' or os.geteuid() == 0  # Windows nmap uses Npcap instead


def within_cap(value, cap):
    try:
        number = float(value)
    except ValueError:
        return False
    return 0 < number <= cap  # NaN fails both comparisons


@dataclass
class Action:
    tool: object
    args: list
    targets: list
    risk: str
    warnings: list = field(default_factory=list)
    defaults: list = field(default_factory=list)  # managed non-interactive flags appended at launch


class Policy:
    def __init__(self, scope, toolcheck=None):
        self.scope = scope
        self.toolcheck = toolcheck  # compares flags with installed help text when set
        self.mode = 'ask'
        self.ceiling = 'active'
        self.expires = 0
        self.grant_revision = ''
        self.remaining = 0

    def grant(self, risk='active', minutes=30, commands=20):
        if risk not in RISK_ORDER or not 1 <= minutes <= 240 or not 1 <= commands <= 200:
            raise ValueError('Grant: risk local/recon/active/intrusive, minutes 1..240, commands 1..200')
        self.mode, self.ceiling = 'auto', risk
        self.expires = time.monotonic() + minutes * 60
        self.remaining = commands
        self.grant_revision = self.scope.revision

    def auto_allows(self, action):
        self.scope.reload()
        return (self.mode == 'auto' and time.monotonic() < self.expires and self.remaining > 0
                and self.grant_revision == self.scope.revision and not action.warnings
                and RISK_ORDER[action.risk] <= RISK_ORDER[self.ceiling])

    def validate(self, name, args, workspace, notes):
        if name not in REGISTRY:
            raise ValueError('Tool is not registered')
        if not isinstance(args, list) or len(args) > 100 or not all(isinstance(x, str) and len(x) <= 4096 for x in args):
            raise ValueError('Arguments must be a list of strings (max 100 x 4096 characters)')
        if any(any(ord(c) < 32 for c in x) for x in args):
            raise ValueError('Control characters in arguments')
        tool = REGISTRY[name]
        if not tool.binary():
            raise ValueError(f'{name} is not installed; /tools {name}')
        self.scope.reload()
        warnings = []
        values, bools = VALUES.get(name, set()), BOOLS.get(name, set())
        skip, positional, target_values, flags = False, [], [], []
        for i, arg in enumerate(args):
            if skip:
                skip = False
                continue
            key = arg.split('=', 1)[0]
            if key.startswith('-') and len(key) > 1:
                flags.append(key)
            if key in BLOCKED and name not in READ_VALUE_EXCEPTIONS.get(key, set()):
                raise ValueError(f'Unsupported indirect/config/output/execution option: {key}. Use explicit targets and managed outputs.')
            # Attached forms of file/config options are disallowed too.
            if any(arg.startswith(p) and arg != p for p in ATTACHED_BLOCKED):
                raise ValueError(f'Unsupported attached option: {arg}')
            if arg in ('-sC', '-A') and name == 'nmap':
                warnings.append('Default NSE scripts require review; use plain -sV for unattended reconnaissance')
                continue
            if key in values:
                if '=' in arg:
                    value = arg.split('=', 1)[1]
                elif i + 1 < len(args):
                    value = args[i + 1]
                    skip = True
                else:
                    raise ValueError(f'Missing value for {arg}')
                cap = CAPS.get(name, {}).get(key)
                if cap is not None and not within_cap(value, cap):
                    warnings.append(f'{key} {value} is outside the unattended limit 1..{cap}; requires review')
                if key == '--script' and name == 'nmap':
                    if not value or not set(value.split(',')).issubset(NMAP_SCRIPTS):
                        raise ValueError('Use named reviewed NSE scripts only: ' + ', '.join(sorted(NMAP_SCRIPTS)))
                    warnings.append('NSE scripts require explicit action review; native scripts are not sandboxed')
                elif key in READ_WORDLIST_FLAGS.get(name, set()):
                    if not Path(value).is_absolute():
                        raise ValueError('Use an absolute wordlist path; /wordlists lists the installed ones')
                    if not Path(value).is_file() or not readable(value, [workspace.root, notes.folder, *SYSTEM_WORDLISTS]):
                        raise ValueError('Wordlist must exist in workspace, notes, or standard Kali wordlist folders; '
                                         '/wordlists lists the installed ones')
                elif '@' in value and key in ('-d', '--data', '--data-raw', '-H', '--header'):
                    raise ValueError('File expansion in HTTP data/headers is not supported')
                elif key in ('-u', '--url') or key in TARGET_OPTIONS.get(name, set()):
                    target_values.append(value)
                elif extract_targets([value]) and key not in ('-H', '--header'):
                    warnings.append(f'Host-like option value requires review: {value}')
                continue
            if arg in bools:
                continue
            if arg.startswith('-') or arg.startswith('+'):
                warnings.append(f'Option outside reviewed profile: {arg}')
            else:
                positional.append(arg)
        # Ignore ordinary flag values already classified above (wordlists, HTTP payloads).
        targets = extract_targets(positional + target_values)
        if any(t.startswith('*.') for t in targets):
            raise ValueError('Wildcard target expressions are unsupported; use a concrete target')
        for value in target_values:
            if not extract_targets([value]):
                raise ValueError(f'Invalid explicit target: {value}')
        # Check remaining URLs/addresses in unreviewed options as a secondary guard.
        for t in extract_targets([x for x in args if '://' in x]):
            if t not in targets:
                targets.append(t)
        if tool.needs_target:
            if not targets:
                raise ValueError('No explicit target found; lists/config files and single-label hosts are unsupported')
            blocked = [x for x in targets if not self.scope.allows(x)]
            if blocked:
                raise ValueError('Outside scope: ' + ', '.join(blocked))
        if name not in VALUES and name not in ('searchsploit', 'hashid', 'tshark'):
            warnings.append('This adapter requires manual review; unattended argument profile is not available')
        if name == 'nmap':
            for value in positional:
                try:
                    # Accepts case and host bits (192.0.2.5/28); URLs are not nmap targets.
                    known = '://' not in value and normalize(value) in targets
                except ValueError:
                    known = False
                if not known:
                    raise ValueError('Unrecognized nmap target; ranges and target expressions are unsupported. Use IP/CIDR.')
            raw = sorted(RAW_SOCKET_SCANS & set(args))
            if raw and '--privileged' not in args and not privileged():
                raise ValueError(f'nmap {" ".join(raw)} needs raw sockets (root). Use -sT for a TCP connect scan, '
                                 'or grant nmap the capability once: sudo setcap '
                                 'cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)" '
                                 'and add --privileged')
        if name == 'wafw00f' and not {'-r', '--noredirect'} & set(args):
            warnings.append('wafw00f follows redirects unless -r is set')
        if name == 'curl':
            for value in target_values + positional:
                if '://' in value and urlparse(value).scheme not in ('http', 'https'):
                    raise ValueError('curl supports HTTP(S) targets only')
            if any(x in args for x in ('-L', '--location', '--location-trusted')):
                raise ValueError('Automatic redirects are disabled; add and request the destination explicitly')
        if name == 'tshark':
            if '-r' not in args:
                raise ValueError('TShark is offline-only; use /import and a local capture')
            from .storage import inside
            idx = args.index('-r')
            if idx + 1 >= len(args):
                raise ValueError('Missing capture file')
            capture = Path(args[idx + 1]).resolve()
            if not capture.is_file() or not inside(capture, workspace.outputs):
                raise ValueError('TShark capture must be an absolute imported workspace path')
            warnings.append('Offline packet analysis requires file review')
        warnings.extend(local_file_warnings(args, [workspace.root, notes.folder, *SYSTEM_WORDLISTS]))
        if self.toolcheck:
            warnings += [f'{f} is not in the installed {name} help; check the tool version'
                         for f in dict.fromkeys(flags) if not self.toolcheck.supports(tool, args, f)]
        return Action(tool, list(args), targets, risk_for(tool, args), sorted(set(warnings)),
                      managed_defaults(tool, args, self.toolcheck))
