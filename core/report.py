"""Local Markdown and HTML reports; no API call. Evidence text is untrusted and always escaped."""
import collections
import html
from .storage import redact
from .workspace import SEVERITIES

LIMITATIONS = ['Automated observations require interpretation. Suspected findings are not confirmed.',
               'Missing findings do not imply coverage or absence of vulnerabilities. Review the plan below.',
               'Network egress is not sandboxed. Full audit: audit.jsonl; output hashes are recorded.']
STATUSES = ('user_confirmed', 'suspected', 'rejected')


def ordered(findings):
    """Most severe first; rejected (false positive) findings last."""
    rank = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    return sorted(findings, key=lambda f: (f.get('status') == 'rejected', rank.get(f.get('severity'), 9), f['id']))


def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ')


def coverage_line(method):
    counts = collections.Counter(s['status'] for s in method['steps'])
    return ' · '.join(f'{n} {status}' for status, n in sorted(counts.items())) or 'no steps'


def markdown(data):
    findings = ordered(data['findings'])
    active = [f for f in findings if f.get('status') != 'rejected']
    rejected = [f for f in findings if f.get('status') == 'rejected']
    method = data.get('methodology') or {'phase': 'not started', 'steps': []}
    lines = [f"# SecAssist assessment: {data['target']}", '', f"Generated: {data['generated_utc']}", '',
             '## Scope', *['- ' + x for x in data['scope']], '', '## Limitations', *LIMITATIONS, '',
             '## Service inventory']
    if data.get('services'):
        lines += ['| Address | Port | Service | Product | Version |', '|---|---|---|---|---|']
        lines += [f"| {cell(s['address'])} | {cell(s['port'])} | {cell(s.get('service', ''))} | "
                  f"{cell(s.get('product', ''))} | {cell(s.get('version', ''))} |" for s in data['services']]
    else:
        lines += ['No services recorded.']
    lines += ['', '## Methodology coverage', f"Current phase: {method['phase']}. {coverage_line(method)}.",
              'Steps that are not completed were not tested; they are not passed.', '']
    if method['steps']:
        lines += ['| Phase | Step | Tool | Status | Note |', '|---|---|---|---|---|']
        lines += [f"| {s['phase']} | {cell(s['id'])} | {cell(s['tool'] or '-')} | {s['status']} | {cell(s['note'])} |"
                  for s in method['steps']]
    lines += ['', '## Assessment plan / coverage']
    lines += [f"- [{x['status']}] {x['question']} — {x.get('evidence', '')}" for x in data['plan']] or \
        ['No assessment plan; coverage unknown.']
    lines += ['', '## Findings']
    if not active:
        lines += ['No findings recorded; this does not establish absence of vulnerabilities.']
    for f in active:
        lines += ['', f"### #{f['id']} {f['title']}", f"Severity: {f['severity']}; status: {f.get('status')}",
                  f"Source: {f['source']}", '', f['description'], '', 'Evidence:', '~~~text', f['evidence'],
                  '~~~', '', 'Remediation: ' + f['remediation']]
    if rejected:
        lines += ['', '## Rejected by operator (false positives)']
        lines += [f"- #{f['id']} {f['title']} ({f['severity']}): {f.get('rejection') or 'no reason given'}"
                  for f in rejected]
    lines += ['', '## Evidence inventory']
    lines += [f"- {p} | SHA256 {meta['sha256']} | {meta.get('status', 'imported/parsed')}"
              for p, meta in data['evidence'].items()]
    return '\n'.join(lines)


def esc(value):
    return html.escape(redact(str(value)))


def badge(kind, value):
    return f'<span class="badge {kind}-{esc(value)}">{esc(value)}</span>'


CSS = """
:root{--bg:#f7f7f5;--card:#fff;--text:#1d1d1f;--muted:#5f6368;--line:#dcdcd8;--code:#f0f0ec;
--critical:#7a0019;--high:#c62828;--medium:#d9730d;--low:#b8860b;--info:#4a6fa5;--ok:#2e7d32}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--card:#1e1e21;--text:#e8e8ea;--muted:#a0a0a8;
--line:#34343a;--code:#26262b;--critical:#ff5c7a;--high:#ff6b6b;--medium:#ffa94d;--low:#e6c84f;--info:#7fa7e0;
--ok:#6cc070}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,"Segoe UI",sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:16px;margin:0 0 8px}.muted{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:12px 0}
.finding{border-inline-start:5px solid var(--sev)}
.counts{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.count{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.count b{display:block;font-size:24px;color:var(--sev)}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;
border:1px solid currentColor;margin-inline-end:6px}
.sev-critical{--sev:var(--critical);color:var(--critical)}.sev-high{--sev:var(--high);color:var(--high)}
.sev-medium{--sev:var(--medium);color:var(--medium)}.sev-low{--sev:var(--low);color:var(--low)}
.sev-info{--sev:var(--info);color:var(--info)}.status-rejected{color:var(--muted)}
.status-user_confirmed{color:var(--high)}.status-suspected{color:var(--medium)}
.st-completed{color:var(--ok)}.st-failed,.st-blocked{color:var(--high)}.st-manual{color:var(--medium)}
.st-ready,.st-running{color:var(--info)}.st-pending,.st-skipped,.st-not_applicable{color:var(--muted)}
.finding.sev-critical,.finding.sev-high,.finding.sev-medium,.finding.sev-low,.finding.sev-info{color:inherit}
pre{background:var(--code);border-radius:8px;padding:10px 12px;overflow-x:auto;white-space:pre-wrap;
word-break:break-word;font:13px/1.45 ui-monospace,Consolas,monospace}
.text{white-space:pre-wrap}
pre,.text,td{unicode-bidi:plaintext}.label{margin-bottom:4px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:start;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:13px;color:var(--muted);font-weight:600}td code{font-size:12px;word-break:break-all}
.table-wrap{overflow-x:auto}ul{padding-inline-start:20px}
@media print{body{background:#fff;color:#000}.card,.count{break-inside:avoid}main{padding:0}}
"""


def html_page(data):
    findings = ordered(data['findings'])
    active = [f for f in findings if f.get('status') != 'rejected']
    rejected = [f for f in findings if f.get('status') == 'rejected']
    counts = ''.join(
        f'<div class="count sev-{s}"><b>{sum(1 for f in active if f["severity"] == s)}</b>{s}</div>'
        for s in reversed(SEVERITIES))
    status_line = ' · '.join(f'{sum(1 for f in findings if f.get("status") == s)} {s}' for s in STATUSES)
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        # Defense in depth: the report never needs scripts or remote resources.
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
        f'<title>SecAssist report: {esc(data["target"])}</title><style>{CSS}</style></head><body><main>',
        f'<h1>SecAssist assessment: <span dir="auto">{esc(data["target"])}</span></h1>',
        f'<p class="muted">Generated {esc(data["generated_utc"])}</p>',
        '<h2>Summary</h2>', f'<div class="counts">{counts}</div>',
        f'<p class="muted">{esc(status_line)}</p>',
        '<h2>Scope</h2><ul>', *[f'<li><code>{esc(x)}</code></li>' for x in data['scope']], '</ul>',
        '<h2>Limitations</h2><div class="card"><ul>', *[f'<li>{esc(x)}</li>' for x in LIMITATIONS],
        '</ul></div>', '<h2>Service inventory</h2>',
    ]
    if data.get('services'):
        parts += ['<div class="table-wrap"><table><tr><th>Address</th><th>Port</th><th>Service</th>'
                  '<th>Product</th><th>Version</th></tr>']
        parts += [f'<tr><td><code>{esc(s["address"])}</code></td><td>{esc(s["port"])}</td>'
                  f'<td>{esc(s.get("service", ""))}</td><td>{esc(s.get("product", ""))}</td>'
                  f'<td>{esc(s.get("version", ""))}</td></tr>' for s in data['services']]
        parts += ['</table></div>']
    else:
        parts += ['<p>No services recorded.</p>']
    method = data.get('methodology') or {'phase': 'not started', 'steps': []}
    parts += ['<h2>Methodology coverage</h2>',
              f'<p>Current phase: <b>{esc(method["phase"])}</b> · {esc(coverage_line(method))}</p>',
              '<p class="muted">Steps that are not completed were not tested; they are not passed.</p>']
    if method['steps']:
        parts += ['<div class="table-wrap"><table><tr><th>Phase</th><th>Step</th><th>Tool</th><th>Status</th>'
                  '<th>Note</th></tr>']
        parts += [f'<tr><td>{esc(s["phase"])}</td><td><code>{esc(s["id"])}</code></td><td>{esc(s["tool"] or "-")}</td>'
                  f'<td class="st-{esc(s["status"])}"><b>{esc(s["status"])}</b></td><td>{esc(s["note"])}</td></tr>'
                  for s in method['steps']]
        parts += ['</table></div>']
    parts += ['<h2>Assessment plan</h2>']
    if data['plan']:
        parts += ['<div class="table-wrap"><table><tr><th>Status</th><th>Question</th><th>Evidence</th></tr>']
        parts += [f'<tr><td>{esc(x["status"])}</td><td dir="auto">{esc(x["question"])}</td>'
                  f'<td dir="auto">{esc(x.get("evidence", ""))}</td></tr>' for x in data['plan']]
        parts += ['</table></div>']
    else:
        parts += ['<p>No assessment plan; coverage unknown.</p>']
    parts += ['<h2>Findings</h2>']
    if not active:
        parts += ['<p>No findings recorded; this does not establish absence of vulnerabilities.</p>']
    for f in active:
        parts += [f'<section class="card finding sev-{esc(f["severity"])}">',
                  f'<h3 dir="auto">#{f["id"]} {esc(f["title"])}</h3>',
                  f'<p>{badge("sev", f["severity"])}{badge("status", f.get("status"))}'
                  f'<span class="muted">Source: <code>{esc(f["source"])}</code></span></p>',
                  f'<p class="text" dir="auto">{esc(f["description"])}</p>',
                  f'<p class="muted label">Evidence (verbatim quote)</p><pre dir="auto">{esc(f["evidence"])}</pre>',
                  f'<p class="muted label">Remediation</p><p class="text" dir="auto">{esc(f["remediation"])}</p>',
                  '</section>']
    if rejected:
        parts += ['<h2>Rejected by operator</h2><ul>']
        # <bdi> keeps right-to-left text in a reason or title from reordering the rest of the line.
        parts += [f'<li>#{f["id"]} <bdi>{esc(f["title"])}</bdi> ({esc(f["severity"])}): '
                  f'<bdi>{esc(f.get("rejection") or "no reason given")}</bdi></li>' for f in rejected]
        parts += ['</ul>']
    parts += ['<h2>Evidence inventory</h2>']
    if data['evidence']:
        parts += ['<div class="table-wrap"><table><tr><th>File</th><th>SHA256</th><th>Status</th></tr>']
        parts += [f'<tr><td><code>{esc(p)}</code></td><td><code>{esc(meta["sha256"])}</code></td>'
                  f'<td>{esc(meta.get("status", "imported/parsed"))}</td></tr>'
                  for p, meta in data['evidence'].items()]
        parts += ['</table></div>']
    else:
        parts += ['<p>No registered evidence.</p>']
    parts += ['</main></body></html>']
    return '\n'.join(parts)
