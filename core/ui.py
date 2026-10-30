"""Terminal helpers: colors, boxes and prompts."""
import os
import sys

try:
    import readline  # gives arrow keys / history in input() on Linux, and lets us pre-fill text
except ImportError:  # Windows
    readline = None

USE_COLOR = (sys.stdout.isatty() and os.name != "nt") or bool(os.environ.get("FORCE_COLOR"))

DIM, BOLD, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN = "2", "1", "31", "32", "33", "34", "35", "36"
RISK_COLORS = {"local": GREEN, "recon": CYAN, "active": YELLOW, "intrusive": RED}


def c(text, *codes):
    if not USE_COLOR or not codes:
        return str(text)
    return f"\033[{';'.join(codes)}m{text}\033[0m"


def info(text):
    print(c(text, DIM))


def warn(text):
    print(c(text, YELLOW))


def error(text):
    print(c(text, RED))


def ok(text):
    print(c(text, GREEN))


def ask(prompt, prefill=""):
    """input() that can pre-fill editable text (used for editing commands)."""
    if prefill and readline and sys.stdin.isatty():
        readline.set_startup_hook(lambda: readline.insert_text(prefill))
        try:
            return input(prompt)
        finally:
            readline.set_startup_hook()
    return input(prompt)


def box(title, lines, color=CYAN):
    print(c("┌─ " + title, color))
    for line in lines:
        print(c("│ ", color) + line)
    print(c("└" + "─" * 2, color))
