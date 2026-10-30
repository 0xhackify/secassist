"""Checks against the operator's installed tools, so commands match real versions.

- Flags are compared with the installed tool's own help text: invented flags and version drift
  surface as review warnings before launch instead of failed jobs.
- Managed non-interactive defaults are added only when the installed tool documents them.
- Wordlists are discovered on disk instead of guessed.
"""
import re
import subprocess
from pathlib import Path
from .storage import clean

# Help invocations that list every option; default is --help.
HELP_ARGS = {'curl': ('--help', 'all'), 'sqlmap': ('-hh',), 'nikto': ('-H',), 'dig': ('-h',), 'ping': ('-h',),
             'host': (), 'hydra': ('-h',), 'searchsploit': ('-h',), 'wafw00f': ('-h',), 'enum4linux-ng': ('-h',),
             'ffuf': ('-h',), 'nuclei': ('-h',), 'httpx': ('-h',), 'katana': ('-h',), 'subfinder': ('-h',),
             'dnsx': ('-h',)}
# Options of these tools are documented per subcommand (gobuster dir --help).
SUBCOMMAND_TOOLS = {'gobuster', 'netexec'}
# Prevent prompts, update checks and third-party callbacks. Added after validation, shown on the card.
MANAGED_DEFAULTS = {
    'sqlmap': ('--batch',),
    'ffuf': ('-noninteractive',),
    'nikto': ('-nointeractive',),
    'nuclei': ('-duc', '-ni', '-nc'),  # -ni: no interactsh callbacks to public OAST servers
    'httpx': ('-duc', '-nc'),
    'wpscan': ('--no-update',),
    'feroxbuster': ('--no-state',),
}
# First existing path wins; deterministic for a given machine.
WORDLISTS = {
    'web-common': ('/usr/share/wordlists/dirb/common.txt',
                   '/usr/share/seclists/Discovery/Web-Content/common.txt'),
    'web-medium': ('/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
                   '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt'),
    'subdomains': ('/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',),
    'passwords': ('/usr/share/wordlists/rockyou.txt',),
}


def wordlists():
    return {name: next((p for p in paths if Path(p).is_file()), None) for name, paths in WORDLISTS.items()}


def mentioned(text, flag):
    if re.search(r'(?<![\w-])' + re.escape(flag) + r'(?![\w-])', text):
        return True
    # Slash lists such as nmap's "-sS/sT/sA".
    return bool(re.search(r'(?<![\w-])-\w+(?:/\w+)*/' + re.escape(flag.lstrip('-')) + r'(?![\w-])', text))


class ToolCheck:
    def __init__(self, runner=None):
        self.runner = runner or self.run_help
        self.cache = {}

    @staticmethod
    def run_help(cmd):
        try:
            result = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            return ''
        return result.stdout.decode('utf-8', 'replace')

    def help_text(self, tool, args):
        binary = tool.binary()
        if not binary:
            return ''
        cmd = [binary]
        if tool.name in SUBCOMMAND_TOOLS and args and not args[0].startswith('-'):
            cmd.append(args[0])
        cmd += HELP_ARGS.get(tool.name, ('--help',))
        key = tuple(cmd)
        if key not in self.cache:
            self.cache[key] = clean(self.runner(cmd))
        return self.cache[key]

    def supports(self, tool, args, flag):
        text = self.help_text(tool, args)
        if len(text) < 80:  # no usable help text: do not guess
            return True
        if mentioned(text, flag):
            return True
        if flag.startswith('-') and not flag.startswith('--') and len(flag) > 2:
            rest = flag[2:]
            if not rest.isalpha() and mentioned(text, flag[:2]):  # attached value: -T4, -p-
                return True
            if flag[1:].isalpha() and all(mentioned(text, '-' + c) for c in flag[1:]):  # combined: -sik
                return True
        return False

    def defaults(self, tool, args):
        return [f for f in MANAGED_DEFAULTS.get(tool.name, ()) if f not in args and self.supports(tool, args, f)]


def managed_defaults(tool, args, check=None):
    """Documented defaults; with a ToolCheck, only those the installed version supports."""
    if check:
        return check.defaults(tool, args)
    return [f for f in MANAGED_DEFAULTS.get(tool.name, ()) if f not in args]
