# SecAssist 3

An evidence-led, operator-controlled security assessment assistant for Kali/Linux.
SecAssist pairs a terminal interface with the DeepSeek API: the model proposes justified commands,
and an execution policy that the model cannot change enforces scope, risk and approval before anything runs.

- Python 3.10+, standard library only. tmux is optional, for side-by-side output panes.
- Built for authorized testing only: lab machines, CTFs and engagements with written permission.

## Quick start

~~~bash
cd secassist
chmod +x secassist install_kali.sh
sudo ./install_kali.sh --core
./secassist --panes
~~~

Inside SecAssist:

~~~text
/setup
/scope add 192.0.2.10
/target 192.0.2.10
/methodology
/next
~~~

Or ask the assistant to run the assessment; it advances the same methodology and analyzes each result.

192.0.2.10 is a documentation address; replace it with your authorized target. Editing scope.txt is not required.

- `/scope add` accepts an IP, CIDR, domain, wildcard domain or URL.
- URL authorization applies to the host, not to a path or port.
- `*.example.test` covers the base domain and all of its subdomains.
- The API key is entered hidden through `/setup` and kept in memory only, or read from `DEEPSEEK_API_KEY`.
- Non-secret preferences are saved automatically. `/model` selects the model and `/think` sets reasoning effort.
- The default model is `deepseek-flash`; choose a model available to your account.
- Local commands, scope management and reports work without an API key.

## Methodology

SecAssist runs a fixed methodology instead of letting the model pick tools. The same target, service inventory
and installed tools always produce the same steps, with the same commands, in the same order.

| Phase | What runs |
|---|---|
| Discovery | nmap top 1000 TCP ports with version probes, then all TCP ports, then version probes for new ports |
| Enumeration | One playbook per service found (below); unknown services are listed for manual review |
| Vulnerability | searchsploit for each exact product and version; nuclei (medium to critical) per web service |
| Validation | Human review of suspected findings: `/finding`, `/confirm`, `/reject`, `/severity` |
| Reporting | `/report` with the service inventory and full methodology coverage |

| Service | Playbook |
|---|---|
| HTTP/HTTPS | whatweb `-a 1`, curl headers (no redirects), wafw00f `-r`, gobuster (or ffuf) with the installed common wordlist, sslscan for TLS |
| SMB | smbclient null-session share list, enum4linux-ng `-A` |
| LDAP | ldapsearch anonymous root DSE naming contexts |
| DNS | dig zone transfer for the target domain (needs a domain target) |

- A phase opens only when every step of the earlier phases is finished.
- Steps are `ready`, `running`, `completed`, `failed`, `skipped`, `blocked`, `not_applicable`, `manual` or `pending`.
  Anything not completed is reported as not tested, never as passed.
- A missing tool or wordlist blocks the step with the reason; nothing is guessed. WinRM ports are not treated as web.
- Service facts come only from nmap XML, never from model text. A later port-table guess never erases a probed banner.
- The assistant analyzes results and saves findings. Its own command proposals are labeled off-methodology and
  always need your approval, even under an auto grant.
- Model wording can still vary between runs: thinking mode has no temperature or seed control.
  The steps, their order, the policy decisions and the coverage do not vary.

| Command | Purpose |
|---|---|
| `/methodology` | Phases and every step with its status and reason |
| `/next` | Run the next ready steps in their fixed order, with approval per your mode |
| `/skip STEP [REASON]` | Skip a step; it is reported as not tested with your reason |
| `/retry STEP` | Reset a failed, blocked or skipped step |
| `/facts` | Service inventory parsed from nmap XML |
| `/wordlists` | Installed wordlists used by playbooks and the assistant |

In auto mode on an interactive Linux terminal, ready steps that the grant covers start automatically,
and completed results go to the assistant for analysis. Steps outside the grant wait for `/next`.

## Execution modes

| Command | Behavior |
|---|---|
| `/mode explain` | Analysis and explanation only; no native tools run |
| `/mode manual` | Proposes a command for you to run, then you import the output |
| `/mode ask` | Approval for every command (default) |
| `/mode auto recon 30 20` | Grant up to recon risk for 30 minutes and 20 commands |
| `/mode auto active 30 20` | Grant up to active risk with the same limits |
| `/mode auto intrusive 15 10` | Wider grant including intrusive; requires typing `grant` |
| `/mode ask` | Revoke the grant for upcoming steps |
| `/stop all` | Revoke the grant and stop running jobs and their child processes |

Grant rules:

- A grant is bound to the current scope, a time limit and a command budget.
  Changing scope or target, or resuming a session, returns to `ask`.
- Options outside the reviewed argument profiles always need confirmation, even under a grant.
- So do speed and concurrency values above the per-tool ceiling (for example `ffuf -t` above 50 or
  `nmap --min-rate` above 1000), and the value 0, which often means unlimited.
- Commands proposed by the assistant are off-methodology and always need approval, even under a grant.
- Intrusive commands and commands with warnings require typing `yes` in full.
- Editing a command shows it again and requires fresh approval after validation.
- An expiring grant does not interrupt a job that started before expiry.

Before any model-proposed command, a decision card shows the observation, hypothesis, reason for the tool,
expected result and stop condition. `/run` is your own command and is labeled as such; the model does not
invent a justification for it.

## Watching jobs

`./secassist --panes` starts tmux with the conversation, a status pane and an output pane per running tool.
Zoom a pane with `Ctrl+b z` and move between panes with `Ctrl+b o`. Output is live and saved;
Enter closes the pane of a completed job. SecAssist manages only its own panes and never kills your tmux sessions.

~~~text
/jobs
/watch JOB_ID
/stop JOB_ID
/parallel 2
/panes off
/panes on
~~~

- Without tmux, use `/watch ID`. `Ctrl+C` returns to the prompt without stopping the job; use `/stop` to stop it.
- Jobs run in the background, so you can keep talking and change the mode while they run.
- In auto mode on an interactive Linux terminal, completed results are analyzed and work continues within the grant.
- In ask mode, with piped input or on Windows, use `/continue` or `/wait`.
- API requests are synchronous. `Ctrl+C` returns from waiting on the model; follow with `/stop all` if needed.
- There are no invented progress percentages: job state and output are the indicators.

## Methodology and evidence

Observation → hypothesis → test → analysis → plan update.
The instructions require the model to separate facts from conclusions, avoid repetition and explain failures
and conflicts. They do not guarantee the model is right or that every lead is a vulnerability.

| Command | Purpose |
|---|---|
| `/plan` | Assessment questions with their status and evidence |
| `/import PATH` | Register a local file (up to 16 MiB) without calling the API |
| `/file PATH QUESTION` | Import a file and send it to the API for analysis |
| `/outputs` | Registered evidence sources |
| `/findings` | Suspected, user-confirmed and rejected findings |
| `/finding ID` | Full details, the evidence quote, and whether the source file changed since registration |
| `/confirm ID` | Human confirmation after reviewing the evidence; a matching quote alone does not prove the conclusion |
| `/reject ID [REASON]` | Mark a false positive; it stays in the audit trail and the report |
| `/severity ID LEVEL` | Set severity by human decision: info, low, medium, high or critical |
| `/report` | Local Markdown, HTML and JSON with evidence, plan, coverage limits and confirmation status |
| `/resume` | Restore target context and plan; approvals are never restored |
| `/clear` | Clear the conversation and keep the evidence |

- A finding cannot be saved without a registered source and a verbatim quote; the file hash is checked first.
- The HTML report is a single self-contained file with no scripts, ordered by severity, with escaped evidence.
- Resume treats previous history as quoted, untrusted context and never re-runs commands.
- Decision summaries are visible; raw model reasoning is neither displayed nor written to disk.

## Tools

`/tools` lists installed and missing tools with install packages; `/doctor` shows the installed count.
Definitions cover Nmap, curl, httpx, WhatWeb, Wafw00f, Subfinder, Amass, dnsx, dig, host, nslookup, whois,
ffuf, Gobuster, Feroxbuster, Dirsearch, Katana, Arjun, Nuclei, Nikto, WPScan, SSLScan, testssl, ping,
SNMPwalk, onesixtyone, enum4linux-ng, smbclient, smbmap, rpcclient, NetExec, ldapsearch,
Impacket GetNPUsers/GetUserSPNs/lookupsid, SQLmap, Hydra, Searchsploit, hashid and TShark.

- `sudo ./install_kali.sh --all` installs the packages available in Kali. The model never installs software.
- Flags are checked against the installed tool's own help text. A flag your version does not document
  becomes a review warning before launch, instead of a failed job.
- Managed defaults keep tools non-interactive and quiet, added only when your version supports them and shown
  on the decision card: sqlmap `--batch`, ffuf `-noninteractive`, nikto `-nointeractive`,
  nuclei `-duc -ni -nc` (no interactsh callbacks to public servers), httpx `-duc -nc`, wpscan `--no-update`,
  feroxbuster `--no-state`.
- Kali wordlist folders are symlinks (`/usr/share/wordlists/dirb` points to `/usr/share/dirb/wordlists`);
  they are accepted, while a link that leads outside system data or your workspace is not.
- nmap `-sS`, `-sU` and `-O` need raw sockets. Without root they are refused before launch with the fix:
  use `-sT`, or grant nmap the capability once and add `--privileged`.
- Progress bars are kept out of the assistant's view, and carriage-return redraws cannot hide result lines.
- Support means a definition and managed execution, not a review of every option or every version.
- Reviewed argument profiles exist for nmap, curl, ffuf, gobuster, dirsearch, feroxbuster, wafw00f,
  enum4linux-ng, smbclient, ldapsearch and others; everything else needs human review.
- Short flags mean different things per tool (`-x` is extensions in gobuster but a proxy in curl),
  so blocking is decided per tool.
- wafw00f without `-r` follows redirects and needs review. `smbclient -L` share listing is active;
  `-c` commands and tar operations remain intrusive.
- ldapsearch runs with `LDAPNOINIT=1`, so ldaprc or ldap.conf cannot add a hidden target.
- Nmap writes managed XML that is parsed; other tools return text, and JSONL can be selected through their options.
- NSE is restricted to specific named scripts with confirmation; no external files or broad categories.
- Nuclei is classified intrusive as a precaution; installed templates are part of the trust surface.
- TShark analyzes imported captures inside outputs only; no live capture.
- There is no direct Burp/ZAP integration; their text reports can be imported.

## Security and privacy boundaries

- Scope checks on arguments are not a sandbox or network isolation. Tools run with your user's privileges and
  may use DNS, public sources and their own defaults. There is no DNS pinning or egress firewall, and no
  guarantee that crawlers or templates will not contact a third party.
- When real network containment is required, use an isolated lab or VM and an unprivileged account.
- Do not run SecAssist with sudo; it is only needed to install packages.
- Target files, configuration files, external output flags and known execution routes are blocked.
  The checks are conservative, not a complete parser for every tool. Automatic curl redirects are blocked.
- Content returned by tools and files is untrusted data and never changes scope or authorization.
- The conversation, selected evidence and retrieved notes are sent to the configured API endpoint.
- Do not put secrets in arguments; they are stored in the local log.
- Redaction of known keys and Authorization headers is limited help, not general secret detection.
- API keys are not inherited by tools. Text output is redacted and capped at 16 MiB; it is not a byte-exact copy.

## Data and development

Data lives in `.secassist/`, which is excluded from Git: `scope.json`, `config.json` and a `workspace/`
directory per target. Each target holds `outputs/`, `evidence.json` with SHA256 hashes, `facts.json`,
`methodology.json`, `findings.json`, `plan.json`, `session.json`, `audit.jsonl`, `jobs.json` and reports.

- The audit log keeps the history of all sessions; `/jobs` shows jobs of the current process only.
- Run one instance per data directory; concurrent use of the same `.secassist` is not supported.
- The log is editable; it is not a forensic signature or a tamper-proof record.

~~~bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q core secassist.py
./secassist --version
~~~

Tests use harmless local processes, with no network scanning and no real API calls.
The tmux test uses a separate socket. See `docs/VALIDATION.md` for the limits of what was verified
and `docs/RESEARCH.md` for references. Choose a license that matches code ownership before publishing;
none is assumed.
