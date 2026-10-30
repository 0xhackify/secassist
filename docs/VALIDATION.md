# Validation — 2026-10-30 (3.2.0)

## Executed
- Windows: Python 3.15.0, 77 tests discovered; 73 passed, 4 platform skips (symlinks, POSIX groups, tmux).
- Linux: Ubuntu 24.04 under WSL, system Python 3.12, all 77 tests passed (tmux, POSIX and symlink tests included).
- 3.2.0 methodology: phase gating, identical steps from identical facts, exact enumeration and vulnerability
  order, every enumeration playbook command validated without warnings and auto-allowed under an active
  grant, nuclei intrusive with managed defaults, version probe for full-scan-only ports, missing tool and
  wordlist reporting, zone transfer only with a domain target, interrupted steps after restart,
  approval/decline/unattended launching, model proposals always prompting, coverage in both reports.
- 3.2.0 tool checks: help-text flag matching (slash lists, attached values, combined flags), policy warning
  for undocumented flags, defaults limited to supported flags, raw-socket refusal without root,
  Kali-style symlinked wordlists accepted and escaping links refused, progress removal, CR-separated output.
- End-to-end CLI run in WSL: real program, piped operator input, real curl against a local HTTP server on
  127.0.0.1. nmap was a test double that writes fixed XML (nmap is not installed in that WSL). Verified:
  /methodology, /next with approval, facts from XML, phase change, /skip, enumeration evidence, blocked
  steps for missing tools with reasons, reporting phase, coverage in the report and audit step events.
- 3.1.0 additions: interrupted edit/turn leaves no unanswered tool call (reproduced before the fix),
  rate ceilings disable auto, whatweb aggression risk, per-tool short flags, six reviewed profiles
  with scope rejection, nmap target normalization, operator reject/severity with audit events,
  ldapsearch LDAPNOINIT, HTML escaping of hostile evidence and severity ordering.
- HTML report inspected in a browser at desktop and phone width, light and dark, including right-to-left text.
- English-only interface/docs check and temperature 0 for non-thinking requests.
- Real tmux integration: isolated server socket, chat/status/output panes, live output capture,
  completed job and cleanup of owned panes.
- Incremental output, exit status 7 preserved, timeout, cancellation, POSIX descendant termination,
  output cap, parallel limit, API-key environment filtering.
- Exact action approval and reapproval after editing, explain/manual no-execution behavior,
  command-budget expiry/scope revision checks, scope/config/list bypass attempts.
- Target traversal, sibling prefix and symlink boundary checks.
- Registered quote validation, changed-file rejection, findings confirmation and raw reasoning exclusion.
- Mocked-model tool call -> human approval -> harmless child process -> completion analysis.
- Offline CLI target selection, import and Markdown/JSON report creation.
- Streaming API assembly and incomplete-response rejection.
- Python compilation, Bash syntax and launcher --version.

## Not executed / limitations
- No DeepSeek key or paid live API request was used. Model quality and account-specific model support
  need a real session. Tests instrument the API protocol rather than claiming live AI validation.
- No Kali package installation or real-target scanner execution was performed.
- 41 tool definitions are provided; each tool/version/flag combination is not end-to-end certified.
- The reviewed profiles, rate ceilings and playbook commands are covered by policy tests and one real curl
  run; nmap, whatweb, wafw00f, gobuster, ffuf, sslscan, smbclient, enum4linux-ng, ldapsearch, dig,
  searchsploit and nuclei were not run against installed Kali versions. Their help-text formats were
  modeled from documentation, so a real Kali run should confirm no false "not in help" warnings.
- GitHub Actions results were not checked in this validation.
- No network egress sandbox; argument checks do not guarantee containment of third-party native tools.
- Output/status panes have real tmux coverage; interactive API latency/cost and long target sessions do not.

## Reproduce
python3 -m unittest discover -s tests -v
python3 -m compileall -q core secassist.py
bash -n secassist install_kali.sh
./secassist --version
