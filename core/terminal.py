"""tmux viewer panes; the job manager alone starts security tools."""
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


class Terminal:
    def __init__(self, workspace, script):
        self.ws = workspace
        self.script = Path(script).resolve()
        self.panes = []
        self.enabled = False
        self.status_pane = None

    def _tmux(self, *args):
        return subprocess.check_output(['tmux', *args], text=True, timeout=5).strip()

    def available(self):
        return os.name == 'posix' and bool(os.environ.get('TMUX')) and bool(shutil.which('tmux'))

    def enable(self):
        if not self.available():
            raise ValueError('Start with ./secassist --panes (requires tmux on Linux), or use /watch JOB')
        if not self.enabled:
            self.status_pane = self._split('status', None, vertical=True)
            self.enabled = True

    def _split(self, kind, job, vertical=False):
        cmd = [sys.executable, str(self.script), '--viewer', kind,
               '--viewer-root', str(self.ws.root)]
        if job:
            cmd += ['--job', job.id]
        # tmux receives only a quoted program path and our generated IDs, never tool arguments.
        pane = self._tmux('split-window', '-d', '-v' if vertical else '-h', '-P', '-F', '#{pane_id}',
                          shlex.join(cmd))
        self._tmux('select-layout', 'tiled')
        return pane

    def show(self, job):
        if not self.enabled:
            return
        # Reuse completed viewers; at most max_jobs worker panes are normally live.
        live = set(self._tmux('list-panes', '-F', '#{pane_id}').splitlines())
        self.panes = [p for p in self.panes if p in live]
        if len(self.panes) >= 4:
            self._tmux('kill-pane', '-t', self.panes.pop(0))
        self.panes.append(self._split('job', job))

    def close(self):
        for pane in self.panes + ([self.status_pane] if self.status_pane else []):
            try:
                self._tmux('kill-pane', '-t', pane)
            except (OSError, subprocess.SubprocessError):
                pass
        self.panes, self.status_pane, self.enabled = [], None, False
