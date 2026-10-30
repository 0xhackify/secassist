# Validation — 2026-10-30

## Executed
- Windows: Python 3.15.0, 42 tests discovered; 39 passed, 3 platform skips.
- Linux: Ubuntu 24.04 under WSL, system Python 3.12, all 42 tests passed.
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
- CI configuration was prepared locally; GitHub Actions have not run and the repo was not uploaded.
- No network egress sandbox; argument checks do not guarantee containment of third-party native tools.
- Output/status panes have real tmux coverage; interactive API latency/cost and long target sessions do not.

## Reproduce
python3 -m unittest discover -s tests -v
python3 -m compileall -q core secassist.py
bash -n secassist install_kali.sh
./secassist --version
