# SecAssist 3 architecture

## Intent and implementation
Develop the supplied CLI into an evidence-led, operator-controlled Kali assistant.
Windows is supported for local review/testing, not as a replacement for Kali tools.

- secassist.py: human-only commands, configuration, finding decisions, automatic completion pump.
- core/report.py: local Markdown/HTML reports; HTML escapes untrusted evidence and carries a no-script CSP.
- core/methodology.py: fixed phases and data-defined service playbooks; computes steps, order and status
  deterministically from the target, facts and installed tools; records step state and coverage.
- core/facts.py: service inventory merged from managed nmap XML; the only input to playbook selection.
- core/toolcheck.py: installed help-text flag checks, managed non-interactive defaults, wordlist discovery.
- core/agent.py: conversation/tool protocol, decision cards, approval loop, plan and findings dispatch.
- core/prompts.py: assessment methodology and evidence/uncertainty instructions.
- core/policy.py: registered tools, risk ceilings, reviewed arguments, scope checks, approval grants.
- core/scope.py: persistent CLI-managed targets.
- core/jobs.py: bounded parallel processes, output files, timeouts, group cancellation, audit.
- core/terminal.py: isolated tmux viewer panels. Security commands never pass through send-keys/shell.
- core/workspace.py: target-isolated files, evidence manifest, findings, persistence and audit.
- core/client.py: streaming API client; incomplete tool calls are discarded.
- core/storage.py: atomic writes, path containment, terminal sanitization and limited secret redaction.
- core/tools.py: registry, risk classification, nmap argument preparation and XML parsing.
- core/notes.py: local notes search; returned content is untrusted.

## Methodology flow
nmap XML -> facts -> playbook steps (fixed order) -> phase gate -> validate -> approval or grant -> job ->
sync on completion -> facts and step status -> model analysis and findings -> next ready steps.
Playbook steps, policy decisions and coverage are deterministic; model wording is not, and model
proposals are a separate, always-approved off-methodology path.

## Permission flow
Human objective -> model decision card -> validate tool/args/scope -> human approval or live grant ->
revalidate -> JobManager starts process -> live file + audit -> completion event ->
model analysis/plan update -> suspected finding with exact registered evidence -> human confirmation.

Auto grants bind risk ceiling, scope revision, expiry and remaining launches.
Grants never persist. File imports and scope changes are human-only commands.
Unknown CLI options require human review; selected indirect/config/output/execution routes are blocked.
Ambiguous short flags are blocked unless a tool is listed with a reviewed meaning for that flag.
Thread/rate values above per-tool ceilings need review, so a grant cannot launch unbounded fan-out.
An interrupted turn answers every pending tool call so the API conversation stays valid.
An unsafe native tool or default configuration can still escape semantic intent: no egress sandbox.

## Persistence
Data directory is private by default on POSIX and ignored by Git.
Target directory names include a digest; containment uses resolved path components.
Audit is append-only during execution but is not cryptographically tamper-proof.
Output hashes detect later edits when finding evidence is submitted.
Session resumption converts previous history to quoted context rather than replaying stale tool calls.
Only one application process per data directory is supported.

## Concurrency and lifecycle
Worker processes run in independent POSIX process sessions; cancellation kills the group.
Output is read incrementally, sanitized, flushed and capped at 16 MiB.
The prompt remains usable during tool execution; API requests themselves remain synchronous.
Automatic continuation occurs only in auto mode on a POSIX interactive terminal.
Shutdown stops jobs before saving the session and closes only owned tmux panes.

## Acceptance checks
Tests use instrumented tool substitutes and harmless local Python processes.
They cover modes, edited-command reapproval, scope bypass attempts, evidence integrity,
session sanitization, timeout/cancellation/descendants, concurrent task limits, API truncation,
interrupted turns, rate ceilings, per-tool flags and profiles, operator finding decisions,
offline Markdown/HTML reports with hostile evidence, and real tmux pane lifecycle with an isolated server.
