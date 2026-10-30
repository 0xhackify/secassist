# Engineering sources — 2026-10-30

Verified primary-source facts:
- tmux supports independent panes/windows and detached sessions:
  https://github.com/tmux/tmux/wiki/Getting-Started
- Python POSIX subprocess start_new_session creates a session; process groups permit descendant cancellation:
  https://docs.python.org/3.11/library/subprocess.html
- Agent authorization and consequential approvals should be checked outside the model:
  https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- Tool returns/retrieved content are prompt-injection inputs; text instructions are not an enforcement boundary:
  https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
- Security assessment includes planning, execution, analysis and reporting:
  https://csrc.nist.gov/pubs/sp/800/115/final
- Nmap -sC can include intrusive scripts and NSE scripts are not sandboxed:
  https://nmap.org/book/man-nse
- Kali provides amass/dnsx packages, but package availability and CLI versions vary:
  https://www.kali.org/tools/amass/
  https://www.kali.org/tools/dnsx/
- DeepSeek thinking-mode tool conversations require reasoning_content to be retained for subsequent API requests:
  https://api-docs.deepseek.com/guides/thinking_mode/

Implementation choices (our design, not claims from these sources):
- Four modes: explain, manual, ask and bounded auto grants.
- Decision cards record observation, hypothesis, purpose, expected result and stop condition.
- Only human CLI commands alter scope or grant capabilities.
- tmux viewers read output; only JobManager launches native tools.
- Exact evidence quotes and output hashes, suspected findings by default, human confirmation.
- Raw reasoning kept transiently for API protocol, omitted from persisted sessions and terminal.
- CLI scope parsing is explicitly not a network sandbox.
- All historical user assessment data is excluded from Git.
