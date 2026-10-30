# Changes

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
