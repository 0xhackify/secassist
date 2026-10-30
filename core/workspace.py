"""Per-target evidence, atomic sessions, findings, and an append-only audit log."""
import datetime
import hashlib
import json
import re
import threading
import uuid
from pathlib import Path
from .storage import atomic_json, read_json, inside, redact

SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']


def safe_name(text):
    slug = re.sub(r'[^A-Za-z0-9_-]', '_', text)[:60].strip('_') or 'general'
    return slug + '-' + hashlib.sha256(text.encode()).hexdigest()[:10]


class Workspace:
    def __init__(self, base, target='general'):
        self.base = Path(base).resolve()
        self.lock = threading.RLock()
        self.switch(target)

    def switch(self, target):
        self.target = target
        self.root = self.base / safe_name(target)
        if not inside(self.root, self.base):
            raise ValueError('Invalid workspace')
        self.outputs = self.root / 'outputs'
        self.outputs.mkdir(parents=True, exist_ok=True)
        self.findings_file = self.root / 'findings.json'
        self.session_file = self.root / 'session.json'
        self.session_id = uuid.uuid4().hex[:12]
        self.log_path = self.root / ('session_' + self.session_id + '.md')
        atomic_json(self.root / 'target.json', {'target': target})
        if not (self.root / 'audit.jsonl').exists():
            (self.root / 'audit.jsonl').touch(mode=0o600)

    def log(self, title, text):
        with self.lock, self.log_path.open('a', encoding='utf-8') as f:
            f.write(f'## {redact(title)}\n\n{redact(text)}\n\n')

    def event(self, kind, **data):
        record = {'time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'event': kind, 'session': self.session_id, **data}
        with self.lock, (self.root / 'audit.jsonl').open('a', encoding='utf-8') as f:
            f.write(redact(json.dumps(record, ensure_ascii=False)) + '\n')

    def findings(self):
        value = read_json(self.findings_file, [])
        if not isinstance(value, list):
            raise ValueError('Invalid findings store')
        return value

    def add_finding(self, title, severity, evidence, description='', remediation='',
                    source='', status='suspected'):
        """Evidence must quote a registered output; existence is not proof of a vulnerability."""
        manifest = read_json(self.root / 'evidence.json', {})
        if source not in manifest:
            raise ValueError('Evidence source must be a registered tool output or /import file')
        p = self.resolve(source)
        if not p or not evidence.strip() or len(evidence) > 4000:
            raise ValueError('Supply a nonempty evidence quote (max 4000 characters)')
        if hashlib.sha256(p.read_bytes()).hexdigest() != manifest[source]['sha256']:
            raise ValueError('Evidence changed after registration; import it again for review')
        if evidence not in p.read_text(encoding='utf-8', errors='replace'):
            raise ValueError('Evidence quote does not occur in the source file')
        items = self.findings()
        item = {'id': len(items) + 1, 'title': redact(title.strip()),
                'severity': severity if severity in SEVERITIES else 'info',
                'evidence': redact(evidence), 'source': source,
                'description': redact(description), 'remediation': redact(remediation),
                'status': 'suspected', 'time': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        items.append(item)
        atomic_json(self.findings_file, items)
        self.event('finding_saved', finding_id=item['id'], source=source)
        return item

    def finding(self, finding_id):
        item = next((x for x in self.findings() if x['id'] == finding_id), None)
        if item is None:
            raise ValueError('Unknown finding ID')
        return item

    def _update_finding(self, finding_id, event, **changes):
        """Human-only decisions; findings are never deleted so the audit trail stays complete."""
        with self.lock:
            items = self.findings()
            item = next((x for x in items if x['id'] == finding_id), None)
            if item is None:
                raise ValueError('Unknown finding ID')
            item.update(changes)
            atomic_json(self.findings_file, items)
        self.event(event, finding_id=finding_id, **changes)
        return item

    def confirm(self, finding_id):
        return self._update_finding(finding_id, 'finding_confirmed', status='user_confirmed')

    def reject(self, finding_id, reason=''):
        return self._update_finding(finding_id, 'finding_rejected', status='rejected',
                                    rejection=redact(reason.strip()))

    def set_severity(self, finding_id, severity):
        if severity not in SEVERITIES:
            raise ValueError('Severity must be one of: ' + ', '.join(SEVERITIES))
        return self._update_finding(finding_id, 'finding_severity_changed', severity=severity,
                                    severity_set_by='operator')

    def evidence_intact(self, source):
        manifest = read_json(self.root / 'evidence.json', {})
        p = self.resolve(source)
        return bool(p and source in manifest and
                    hashlib.sha256(p.read_bytes()).hexdigest() == manifest[source]['sha256'])

    def findings_summary(self, limit=25):
        return '\n'.join(f"#{x['id']} [{x['severity']}/{x.get('status', 'legacy_unreviewed')}] {x['title']}"
                         for x in self.findings()[:limit]) or 'No findings.'

    def register(self, path, **meta):
        path = Path(path).resolve()
        if not inside(path, self.outputs) or not path.is_file():
            raise ValueError('Only output files may be registered')
        rel = path.relative_to(self.root).as_posix()
        with self.lock:
            manifest = read_json(self.root / 'evidence.json', {})
            manifest[rel] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), **meta}
            atomic_json(self.root / 'evidence.json', manifest)
        return rel

    def resolve(self, relative):
        if Path(relative).is_absolute():
            return None
        path = (self.root / relative).resolve()
        return path if inside(path, self.root) and path.is_file() else None

    def list_outputs(self, limit=50):
        return list(read_json(self.root / 'evidence.json', {}).keys())[-limit:]

    def save_session(self, turns, plan):
        # Raw reasoning is needed by the API in memory, but is not persisted.
        clean_turns = [[{k: v for k, v in msg.items() if k != 'reasoning_content'} for msg in turn] for turn in turns]
        atomic_json(self.session_file, {'version': 3, 'target': self.target,
                    'turns': json.loads(redact(json.dumps(clean_turns, ensure_ascii=False))), 'plan': plan})

    def resume(self):
        data = read_json(self.session_file, {})
        # Flatten history to a quoted summary: never forge missing API reasoning/tool protocol.
        history = []
        for turn in data.get('turns', [])[-4:]:
            for msg in turn:
                history.append(f"{msg.get('role')}: {msg.get('content', '')[:3000]}")
        return '\n'.join(history)[-20000:], data.get('plan', [])
