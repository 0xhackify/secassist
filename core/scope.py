"""Persistent CLI scope. Argument checking is not a network sandbox."""
import hashlib
import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlparse
from .storage import atomic_json, read_json, inside

DOMAIN_RE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$')


def normalize(value):
    value = value.strip().lower()
    if '://' in value:
        value = urlparse(value).hostname or ''
    value = value.rstrip('.')
    if value.startswith('*.'):
        if not DOMAIN_RE.fullmatch(value[2:]):
            raise ValueError('Invalid wildcard domain')
        return value
    try:
        return str(ipaddress.ip_network(value, strict=False)) if '/' in value else str(ipaddress.ip_address(value.strip('[]')))
    except ValueError:
        if not DOMAIN_RE.fullmatch(value):
            raise ValueError('Use an IP, CIDR, domain, wildcard domain, or URL') from None
        return value


class Scope:
    def __init__(self, path):
        self.path = Path(path)
        self.reload()

    def reload(self):
        data = read_json(self.path, [])
        if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
            raise ValueError('Scope must be a JSON list of targets')
        self.entries = sorted(set(normalize(x) for x in data))

    @property
    def revision(self):
        return hashlib.sha256('\n'.join(self.entries).encode()).hexdigest()

    def add(self, value):
        value = normalize(value)
        self.reload()
        self.entries = sorted(set(self.entries + [value]))
        atomic_json(self.path, self.entries)
        return value

    def remove(self, value):
        value = normalize(value)
        self.reload()
        self.entries = [x for x in self.entries if x != value]
        atomic_json(self.path, self.entries)

    def allows(self, host):
        try:
            host = normalize(host)
        except ValueError:
            return False
        try:
            net = ipaddress.ip_network(host, strict=False)
        except ValueError:
            return host in self.entries or any(x.startswith('*.') and
                (host == x[2:] or host.endswith('.' + x[2:])) for x in self.entries)
        for entry in self.entries:
            try:
                allowed = ipaddress.ip_network(entry, strict=False)
                if net.version == allowed.version and net.subnet_of(allowed):
                    return True
            except ValueError:
                continue
        return False

    def check(self, args):
        targets = extract_targets(args)
        return targets, [t for t in targets if not self.allows(t)]

    def describe(self):
        return self.entries[:]

    def is_empty(self):
        return not self.entries


def extract_targets(args):
    """Supplementary detection; structured validation lives in policy.py."""
    targets = []
    for arg in args:
        value = arg.split('=', 1)[1] if arg.startswith('-') and '=' in arg else arg
        candidates = [value]
        if value.startswith('@'):
            candidates.append(value[1:])
        if value.startswith(('//', '\\\\')):
            candidates.append(re.split(r'[/\\]', value.lstrip('/\\'))[0])
        if '@' in value and '://' not in value:
            candidates.append(value.rsplit('@', 1)[1])
        for candidate in candidates:
            if '://' in candidate:
                candidate = urlparse(candidate).hostname or ''
            elif re.fullmatch(r'[^:/]+:\d+', candidate):
                candidate = candidate.rsplit(':', 1)[0]
            try:
                host = normalize(candidate)
            except ValueError:
                continue
            if host not in targets:
                targets.append(host)
    return targets


SYSTEM_DATA = '/usr/share'


def readable(value, roots):
    """The path as written must be under a root; after symlinks it must stay under a root or system data.
    Kali links /usr/share/wordlists/dirb to /usr/share/dirb/wordlists, so resolving alone is not enough."""
    path = Path(value).expanduser()
    written = Path(os.path.abspath(path))
    lexical = False
    for root in roots:
        try:
            written.relative_to(os.path.abspath(Path(root).expanduser()))
            lexical = True
        except ValueError:
            continue
    return lexical and any(inside(path, r) for r in [*roots, SYSTEM_DATA])


def local_file_warnings(args, allowed_roots):
    warnings = []
    for arg in args:
        value = arg.split('=', 1)[1] if arg.startswith('-') and '=' in arg else arg
        value = value.lstrip('@')
        path = Path(value).expanduser()
        if ('/' in value or '\\' in value) and '://' not in value and not value.startswith('//'):
            try:
                ipaddress.ip_network(value, strict=False)
                continue  # CIDR notation, scope-checked as a target rather than read as a path
            except ValueError:
                pass
            if not readable(path, allowed_roots):
                warnings.append(f'Local path requires review: {value}')
    return warnings
