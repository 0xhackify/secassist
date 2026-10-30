# Changes

## 3.2.0 — 2026-10-30
- Deterministic methodology engine: fixed phases (discovery, enumeration, vulnerability, validation,
  reporting) and data-defined service playbooks for HTTP/HTTPS, SMB, LDAP and DNS. The same facts and
  installed tools always give the same steps, commands and order. /methodology, /next, /skip, /retry.
- Facts store: service inventory from nmap XML only; probed banners are never erased by later guesses. /facts.
- The assistant advances the methodology and analyzes results. Its own proposals are off-methodology and
  always require human approval, even under an auto grant. Auto mode runs only granted playbook steps.
- Methodology coverage and service inventory in Markdown/HTML/JSON reports; untested steps are explicit.
- Installed-tool checks: flags compared with the installed help text, managed non-interactive defaults
  (nuclei -ni avoids interactsh callbacks), wordlist discovery (/wordlists), refusal of raw-socket nmap
  scans without root with the fix, alternatives when a tool is missing (gobuster, then ffuf).
- Fix: Kali's symlinked wordlist folders (/usr/share/wordlists/dirb) were rejected by the path check.
- Fix: carriage-return progress output could merge with result lines; progress noise is now removed
  from what the assistant reads, while evidence files keep every line.
- Fix: an operator command identical to a declined assistant proposal was refused as a duplicate.

## 3.1.0 — 2026-10-30
- Fix: Ctrl+C at the edit prompt (or any interruption mid-turn) left a model tool call without a tool
  reply, so the API rejected the rest of the conversation until /clear. Pending calls are now answered.
- Unattended speed limits: thread/rate values above per-tool ceilings, zero or non-numeric need review.
- whatweb aggression 3/4 is classified active instead of recon.
- Short flags are blocked per tool: gobuster/dirsearch/feroxbuster -x, dirsearch -e, gobuster -t,
  hydra -l now work; curl -x, nuclei -t, gobuster -r and list/output flags stay blocked. -oJ/-oY blocked.
- Reviewed profiles for gobuster, dirsearch, wafw00f (requires -r), enum4linux-ng, smbclient share
  listing (active instead of intrusive) and ldapsearch (runs with LDAPNOINIT=1).
- nmap accepts case-insensitive hostnames and CIDR host bits; CIDR targets no longer trigger path review.
- /finding ID (details and evidence integrity), /reject ID [REASON], /severity ID LEVEL; audit events.
- /report also writes a self-contained HTML report: severity summary, ordered findings, rejected section,
  escaped evidence, no scripts (CSP), correct right-to-left evidence text, print and phone layouts.
- English-only interface, README, report and model replies; a test keeps sources and docs English.
- Non-thinking mode samples at temperature 0. Thinking mode ignores temperature and has no seed,
  so model wording can still vary between runs; the execution policy itself is deterministic.

## 3.0.0 — 2026-10-30
- CLI-managed persistent scope, interactive target authorization and setup without key-on-disk storage.
- Four execution modes, per-action decision cards, bounded auto grants and exact edit reapproval.
- Background jobs with parallel limits, live files, timeouts, output limits and process-group cancellation.
- tmux status/output viewers with isolated ownership and single-terminal fallback.
- Evidence-led planning instructions, suspected findings with registered quotes and hashes, human confirmation.
- Atomic session state, resume with reset permissions, local Markdown/JSON reports and audit records.
- Stronger path containment and prevention of known indirect/config/output argument routes.
- Expanded registry to 41 tools; conservative risk classification including nmap default scripts and Nuclei.
- Discard incomplete API tool responses; raw reasoning is not printed/persisted.
- Cross-platform tests, real Linux/tmux smoke test, CI workflow, Git privacy exclusions and documentation.

The v2 synchronous command runner was removed; all native tool execution goes through JobManager.
