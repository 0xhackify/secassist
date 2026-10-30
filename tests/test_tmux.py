"""Isolated real-tmux smoke test. No user session or security scanner is used."""
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'posix' and shutil.which('tmux'), 'Linux + tmux required')
class TmuxTests(unittest.TestCase):
    def test_adjacent_viewers_and_cleanup(self):
        socket_name = 'secassist-test-' + uuid.uuid4().hex[:10]
        tmux = ['tmux', '-L', socket_name]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            program = root / 'fixture.py'
            result = root / 'result.json'
            program.write_text(
                "import sys,time,json\n"
                f"sys.path.insert(0, {str(ROOT)!r})\n"
                "from pathlib import Path\n"
                "from types import SimpleNamespace\n"
                "from core.workspace import Workspace\n"
                "from core.jobs import JobManager\n"
                "from core.policy import Action\n"
                "from core.terminal import Terminal\n"
                f"ws=Workspace({str(root / 'data')!r},'fixture.test')\n"
                f"t=Terminal(ws,{str(ROOT / 'secassist.py')!r})\n"
                "m=JobManager(ws); m.on_start=t.show\n"
                "t.enable()\n"
                "tool=SimpleNamespace(name='fixture',binary=lambda:sys.executable,timeout=5)\n"
                "j=m.submit(Action(tool,['-u','-c',\"import time; print('LIVE_FIXTURE',flush=True); time.sleep(1)\"],[],'local'))\n"
                "time.sleep(.6)\n"
                "panes=t._tmux('list-panes','-F','#{pane_id}')\n"
                "capture=t._tmux('capture-pane','-p','-t',t.panes[0])\n"
                "j.done.wait(5)\n"
                "m.close(); t.close()\n"
                "remaining=t._tmux('list-panes','-F','#{pane_id}')\n"
                f"Path({str(result)!r}).write_text(json.dumps({{'panes':panes,'capture':capture,'remaining':remaining,'status':j.status}}))\n")
            cmd = shlex.join([sys.executable, str(program)])
            try:
                subprocess.run(tmux + ['new-session', '-d', '-s', 'test', '-x', '160', '-y', '48', cmd],
                               check=True, timeout=10)
                deadline = time.monotonic() + 12
                while not result.exists() and time.monotonic() < deadline:
                    time.sleep(.1)
                self.assertTrue(result.exists(), 'tmux fixture did not finish')
                data = json.loads(result.read_text())
                self.assertEqual(len(data['panes'].splitlines()), 3)
                self.assertIn('LIVE_FIXTURE', data['capture'])
                self.assertEqual(data['status'], 'completed')
                self.assertEqual(len(data['remaining'].splitlines()), 1)
            finally:
                subprocess.run(tmux + ['kill-server'], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5, check=False)


if __name__ == '__main__':
    unittest.main()
