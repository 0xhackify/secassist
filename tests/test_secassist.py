"""No scanner/network use. Harmless child processes and instrumented tools."""
import argparse
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.agent import Agent, CARD
from core.client import ChatClient, APIError
from core.jobs import JobManager
from core.notes import NotesIndex
from core.policy import Policy, Action
from core.report import html_page, markdown
from core.scope import Scope
from core.storage import atomic_json, inside
from core.tools import REGISTRY, risk_for
from core.workspace import Workspace
from secassist import App

ROOT = Path(__file__).resolve().parents[1]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.scope = Scope(self.root / 'scope.json')
        self.scope.add('192.0.2.10')
        self.scope.add('example.test')
        self.ws = Workspace(self.root / 'work', 'example.test')
        self.notes = NotesIndex(self.root / 'notes')
        self.policy = Policy(self.scope)
        self.jobs = JobManager(self.ws)
        self.agent = Agent(SimpleNamespace(api_key=''), self.scope, self.ws, self.notes, self.policy, self.jobs)
        self.installed = patch('core.tools.shutil.which', return_value=sys.executable)
        self.installed.start()

    def tearDown(self):
        self.jobs.close()
        self.installed.stop()
        self.tmp.cleanup()

    def validate(self, name, args):
        return self.policy.validate(name, args, self.ws, self.notes)

    def card(self, tool='nmap', args=None):
        return dict(tool=tool, args=args or ['-sV', '192.0.2.10'], **{k: 'Documented rationale' for k in CARD})


class ScopeTests(Base):
    def test_persistence_and_network_containment(self):
        self.scope.add('192.0.2.0/28')
        other = Scope(self.scope.path)
        self.assertTrue(other.allows('192.0.2.1'))
        self.assertFalse(other.allows('192.0.2.0/24'))
        self.assertFalse(other.allows('evil-example.test'))
        self.assertTrue(other.allows('https://example.test/path'))

    def test_wildcard_boundary(self):
        self.scope.add('*.example.test')
        self.assertTrue(self.scope.allows('a.example.test'))
        self.assertFalse(self.scope.allows('example.test.evil.test'))

    def test_existing_file_named_like_target_is_still_checked(self):
        p = self.root / '203.0.113.10'
        p.touch()
        with patch('os.getcwd', return_value=str(self.root)):
            with self.assertRaises(ValueError):
                self.validate('nmap', ['203.0.113.10'])

    def test_scope_changes_revoke_grant(self):
        action = self.validate('nmap', ['-sV', '192.0.2.10'])
        self.policy.grant()
        self.assertTrue(self.policy.auto_allows(action))
        self.scope.add('other.test')
        self.assertFalse(self.policy.auto_allows(action))

    def test_expired_or_exhausted_grants(self):
        action = self.validate('nmap', ['192.0.2.10'])
        self.policy.grant()
        self.policy.expires = 0
        self.assertFalse(self.policy.auto_allows(action))
        self.policy.grant()
        self.policy.remaining = 0
        self.assertFalse(self.policy.auto_allows(action))

    def test_invalid_scope_fails_closed(self):
        self.scope.path.write_text('{broken')
        with self.assertRaises(ValueError):
            self.validate('nmap', ['192.0.2.10'])


class PolicyTests(Base):
    def test_basic_nmap_is_reviewed(self):
        action = self.validate('nmap', ['-sV', '-p', '80,443', '192.0.2.10'])
        self.assertEqual(action.risk, 'recon')
        self.assertFalse(action.warnings)

    def test_scope_bypass_forms_blocked(self):
        for args in (['192.0.2.10', '-iL', 'targets.txt'],
                     ['192.0.2.10', '-iLtargets.txt'],
                     ['192.0.2.10', '203.0.113.10'],
                     ['192.0.2.1-254'],
                     ['192.0.2.10', '--script', 'unsafe.nse'],
                     ['192.0.2.10', '-oX/tmp/out']):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.validate('nmap', args)

    def test_http_expansion_and_redirects_blocked(self):
        for args in (['-L', 'https://example.test'], ['-d', '@/etc/passwd', 'https://example.test'],
                     ['-K/etc/curlrc', 'https://example.test'],
                     ['--resolve', 'example.test:443:203.0.113.10', 'https://example.test'],
                     ['file:///etc/passwd', 'https://example.test']):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.validate('curl', args)

    def test_curl_post_intrusive(self):
        action = self.validate('curl', ['-X', 'POST', '-d', 'a=1', 'https://example.test'])
        self.assertEqual(action.risk, 'intrusive')

    def test_nmap_scripts_and_nuclei_not_recon(self):
        self.assertEqual(self.validate('nmap', ['-sC', '192.0.2.10']).risk, 'intrusive')
        self.assertEqual(self.validate('nuclei', ['-u', 'https://example.test']).risk, 'intrusive')

    def test_unknown_flags_disable_auto(self):
        action = self.validate('curl', ['--made-up-flag', 'https://example.test'])
        self.policy.grant('intrusive')
        self.assertFalse(self.policy.auto_allows(action))

    def test_control_characters_rejected(self):
        with self.assertRaises(ValueError):
            self.validate('nmap', ['192.0.2.10\n--script=all'])

    def test_explain_never_runs(self):
        self.policy.mode = 'explain'
        with self.assertRaises(ValueError), patch.object(self.jobs, 'submit') as submit:
            self.agent.run(self.card())
        submit.assert_not_called()

    def test_manual_never_runs(self):
        self.policy.mode = 'manual'
        with patch.object(self.jobs, 'submit') as submit:
            result = self.agent.run(self.card())
        self.assertTrue(result.startswith('MANUAL'))
        submit.assert_not_called()

    def test_edit_requires_new_confirmation(self):
        with patch('core.ui.ask', side_effect=['e', 'curl -X POST https://example.test', 'n']) as ask, \
             patch.object(self.jobs, 'submit') as submit:
            result = self.agent.run(self.card())
        self.assertEqual(ask.call_count, 3)
        self.assertIn('Declined', result)
        submit.assert_not_called()

    def test_edit_cannot_escape_scope(self):
        with patch('core.ui.ask', side_effect=['e', 'nmap 203.0.113.10']), \
             patch.object(self.jobs, 'submit') as submit, self.assertRaises(ValueError):
            self.agent.run(self.card())
        submit.assert_not_called()

    def test_intrusive_needs_full_yes(self):
        with patch('core.ui.ask', return_value='y'), patch.object(self.jobs, 'submit') as submit:
            self.agent.run(self.card('curl', ['-X', 'POST', 'https://example.test']))
        submit.assert_not_called()

    def test_missing_card_is_rejected(self):
        with self.assertRaises(ValueError):
            self.agent.run({'tool': 'nmap', 'args': ['192.0.2.10']})

    def wordlist(self):
        path = self.ws.root / 'words.txt'
        path.write_text('admin\n')
        return str(path)

    def test_rate_caps_require_review(self):
        words = self.wordlist()
        self.policy.grant('active')
        fast = self.validate('ffuf', ['-u', 'https://example.test/FUZZ', '-w', words, '-t', '1000'])
        self.assertFalse(self.policy.auto_allows(fast))
        normal = self.validate('ffuf', ['-u', 'https://example.test/FUZZ', '-w', words, '-t', '40'])
        self.assertTrue(self.policy.auto_allows(normal))
        # Zero often means unlimited; non-numeric values cannot be compared.
        for value in ('5000', '0', 'fast', 'nan'):
            with self.subTest(value=value):
                self.assertTrue(self.validate('nmap', ['--min-rate', value, '192.0.2.10']).warnings)

    def test_whatweb_aggression_raises_risk(self):
        self.assertEqual(self.validate('whatweb', ['-a', '1', 'https://example.test']).risk, 'recon')
        self.assertEqual(self.validate('whatweb', ['-a', '3', 'https://example.test']).risk, 'active')

    def test_short_flags_are_blocked_per_tool(self):
        words = self.wordlist()
        # The same letters stay blocked where they proxy traffic, load templates, follow redirects or read lists.
        for name, args in (('curl', ['-x', 'http://192.0.2.10:8080', 'https://example.test']),
                           ('nuclei', ['-t', 'custom.yaml', '-u', 'https://example.test']),
                           ('gobuster', ['dir', '-u', 'https://example.test', '-w', words, '-r']),
                           ('dirsearch', ['-l', 'urls.txt'])):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validate(name, args)
        self.validate('hydra', ['-l', 'admin', '-P', '/usr/share/wordlists/rockyou.txt', 'ssh://192.0.2.10'])
        self.validate('dirsearch', ['-u', 'https://example.test', '-e', 'php', '-x', '404', '-t', '20'])

    def test_reviewed_profiles_allow_unattended_use(self):
        words = self.wordlist()
        self.policy.grant('active')
        for name, args in (
                ('gobuster', ['dir', '-u', 'https://example.test', '-w', words, '-x', 'php', '-t', '50', '-q']),
                ('dirsearch', ['-u', 'https://example.test', '-w', words, '-e', 'php', '-r']),
                ('wafw00f', ['-r', 'https://example.test']),
                ('enum4linux-ng', ['-A', '192.0.2.10']),
                ('smbclient', ['-N', '-L', '//192.0.2.10']),
                ('ldapsearch', ['-x', '-H', 'ldap://192.0.2.10', '-s', 'base', 'namingcontexts'])):
            with self.subTest(name=name):
                action = self.validate(name, args)
                self.assertEqual(action.warnings, [])
                self.assertTrue(self.policy.auto_allows(action))

    def test_profiles_keep_scope_and_state_changes_reviewed(self):
        for name, args in (('ldapsearch', ['-x', '-H', 'ldap://203.0.113.10']),
                           ('smbclient', ['-N', '-L', '//203.0.113.10']),
                           ('gobuster', ['dns', '--domain', 'other.test'])):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validate(name, args)
        shell = self.validate('smbclient', ['-N', '//192.0.2.10/share', '-c', 'put local.txt'])
        self.assertEqual(shell.risk, 'intrusive')
        self.assertTrue(shell.warnings)
        self.assertTrue(self.validate('wafw00f', ['https://example.test']).warnings)
        self.assertEqual(self.validate('enum4linux-ng', ['-A', '-R', '192.0.2.10']).warnings,
                         ['Option outside reviewed profile: -R'])

    def test_nmap_accepts_normalized_targets(self):
        self.scope.add('192.0.2.0/28')
        for args in (['-sV', 'EXAMPLE.test'], ['-sV', '192.0.2.5/28']):
            with self.subTest(args=args):
                self.assertEqual(self.validate('nmap', args).warnings, [])
        with self.assertRaises(ValueError):
            self.validate('nmap', ['-sV', 'https://example.test'])


class EvidenceTests(Base):
    def test_sibling_prefix_and_traversal_rejected(self):
        sibling = self.ws.root.parent / (self.ws.root.name + '_other')
        sibling.mkdir()
        (sibling / 'secret.txt').write_text('private')
        self.assertIsNone(self.ws.resolve('../' + sibling.name + '/secret.txt'))
        self.assertIsNone(self.ws.resolve(str(sibling / 'secret.txt')))

    def test_symlink_escape_rejected(self):
        outside = self.root / 'secret.txt'
        outside.write_text('private')
        link = self.ws.outputs / 'escape'
        try:
            link.symlink_to(outside)
        except OSError:
            self.skipTest('Symlinks require permission on this OS')
        self.assertIsNone(self.ws.resolve('outputs/escape'))

    def test_findings_need_real_registered_quote(self):
        output = self.ws.outputs / 'result.txt'
        output.write_text('Service says hello\n')
        source = self.ws.register(output)
        with self.assertRaises(ValueError):
            self.ws.add_finding('Made up', 'high', 'Vulnerable!', source=source)
        item = self.ws.add_finding('Observed greeting', 'info', 'Service says hello', source=source)
        self.assertEqual(item['status'], 'suspected')
        self.ws.confirm(item['id'])
        self.assertEqual(self.ws.findings()[0]['status'], 'user_confirmed')

    def test_raw_reasoning_not_persisted(self):
        self.ws.save_session([[{'role': 'assistant', 'content': 'Decision',
                                'reasoning_content': 'private raw reasoning'}]], [])
        self.assertNotIn('private raw reasoning', self.ws.session_file.read_text())

    def test_corrupt_findings_not_silently_overwritten(self):
        self.ws.findings_file.write_text('{broken')
        with self.assertRaises(ValueError):
            self.ws.findings()

    def test_unregistered_file_not_readable_by_model(self):
        self.ws.log_path.write_text('sensitive session')
        with self.assertRaises(ValueError):
            self.agent.dispatch('read_output', {'path': self.ws.log_path.name})

    def test_changed_evidence_cannot_be_used(self):
        output = self.ws.outputs / 'changed.txt'
        output.write_text('original')
        source = self.ws.register(output)
        output.write_text('changed')
        with self.assertRaises(ValueError):
            self.ws.add_finding('Changed', 'info', 'changed', source=source)

    def test_operator_finding_decisions(self):
        output = self.ws.outputs / 'banner.txt'
        output.write_text('Server: Apache/2.4.49\n')
        source = self.ws.register(output)
        item = self.ws.add_finding('Outdated Apache', 'medium', 'Apache/2.4.49', source=source)
        self.ws.set_severity(item['id'], 'high')
        self.ws.reject(item['id'], 'Backported patch confirmed by owner')
        stored = self.ws.finding(item['id'])
        self.assertEqual((stored['severity'], stored['status']), ('high', 'rejected'))
        self.assertEqual(stored['rejection'], 'Backported patch confirmed by owner')
        self.assertEqual(len(self.ws.findings()), 1)
        with self.assertRaises(ValueError):
            self.ws.set_severity(item['id'], 'urgent')
        with self.assertRaises(ValueError):
            self.ws.reject(99)
        self.assertTrue(self.ws.evidence_intact(source))
        output.write_text('changed')
        self.assertFalse(self.ws.evidence_intact(source))
        events = [json.loads(x)['event'] for x in (self.ws.root / 'audit.jsonl').read_text(encoding='utf-8').splitlines()]
        self.assertIn('finding_rejected', events)
        self.assertIn('finding_severity_changed', events)


class JobTests(Base):
    def setUp(self):
        super().setUp()
        self.installed.stop()  # real subprocess executable paths, no scanner used
        self.installed = patch('core.tools.shutil.which', wraps=__import__('shutil').which)
        self.installed.start()

    def tool(self, timeout=5):
        return SimpleNamespace(name='fixture', binary=lambda: sys.executable, timeout=timeout)

    def launch(self, script, timeout=5):
        return self.jobs.submit(Action(self.tool(timeout), ['-u', '-c', script], [], 'local'))

    def test_live_output_exit_status_and_evidence(self):
        job = self.launch("import time; print('first', flush=True); time.sleep(.5); print('second')")
        limit = time.monotonic() + 3
        while 'first' not in job.tail and time.monotonic() < limit:
            time.sleep(.02)
        self.assertIn('first', job.tail)
        self.assertTrue(job.done.wait(5))
        self.assertEqual(job.status, 'completed')
        self.assertEqual(job.returncode, 0)
        self.assertTrue(job.sha256)
        self.assertIn(job.path.relative_to(self.ws.root).as_posix(), self.ws.list_outputs())

    def test_nonzero_exit_not_success(self):
        job = self.launch("import sys; print('failed'); sys.exit(7)")
        self.assertTrue(job.done.wait(5))
        self.assertEqual((job.status, job.returncode), ('failed', 7))

    def test_timeout(self):
        job = self.launch('import time; time.sleep(20)', timeout=.3)
        self.assertTrue(job.done.wait(5))
        self.assertEqual(job.status, 'timed_out')

    def test_stop(self):
        job = self.launch('import time; time.sleep(20)')
        self.jobs.stop(job.id)
        self.assertTrue(job.done.wait(5))
        self.assertEqual(job.status, 'cancelled')

    def test_parallel_limit(self):
        self.jobs.max_jobs = 1
        job = self.launch('import time; time.sleep(5)')
        with self.assertRaises(ValueError):
            self.launch("print('extra')")
        self.jobs.stop(job.id)

    def test_output_limit(self):
        with patch('core.jobs.MAX_LOG', 100):
            job = self.launch("print('x' * 10000)")
            self.assertTrue(job.done.wait(5))
        self.assertEqual(job.status, 'output_limit')
        self.assertLess(job.path.stat().st_size, 1000)

    def test_ldapsearch_ignores_user_ldap_config(self):
        tool = SimpleNamespace(name='ldapsearch', binary=lambda: sys.executable, timeout=5)
        job = self.jobs.submit(Action(tool, ['-u', '-c', "import os; print(os.environ.get('LDAPNOINIT'))"], [], 'active'))
        self.assertTrue(job.done.wait(5))
        self.assertEqual(job.tail.strip(), '1')

    def test_api_key_not_in_tool_environment(self):
        with patch.dict(os.environ, {'DEEPSEEK_API_KEY': 'fake-test-key'}):
            job = self.launch("import os; print(os.environ.get('DEEPSEEK_API_KEY', 'absent'))")
            self.assertTrue(job.done.wait(5))
        self.assertEqual(job.tail.strip(), 'absent')

    @unittest.skipUnless(os.name == 'posix', 'POSIX process groups')
    def test_timeout_kills_descendants_holding_stdout(self):
        script = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); time.sleep(30)"
        job = self.launch(script, timeout=.3)
        self.assertTrue(job.done.wait(5))
        self.assertEqual(job.status, 'timed_out')


class StreamTests(unittest.TestCase):
    def test_truncated_tool_call_never_returned(self):
        client = ChatClient('https://api.deepseek.com', 'fake', 'fake')
        response = io.BytesIO(b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"run_tool","arguments":"{"}}]}}]}\n')
        with patch.object(client, '_open', return_value=response), self.assertRaises(APIError):
            client.chat([])

    def test_complete_stream_assembles_tool_calls(self):
        client = ChatClient('https://api.deepseek.com', 'fake', 'fake')
        response = io.BytesIO(b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"id","function":{"name":"run_tool","arguments":"{}"}}]}}]}\ndata: [DONE]\n')
        with patch.object(client, '_open', return_value=response):
            msg = client.chat([])
        self.assertEqual(msg['tool_calls'][0]['function']['arguments'], '{}')

    def test_insecure_remote_endpoint_rejected(self):
        with self.assertRaises(ValueError):
            ChatClient('http://remote.test', 'fake', 'fake')

    def test_non_thinking_mode_uses_repeatable_sampling(self):
        payload = ChatClient('https://api.deepseek.com', 'fake', 'fake', 'off')._payload([], None)
        self.assertEqual(payload['temperature'], 0)


class LanguageTests(unittest.TestCase):
    def test_interface_and_docs_are_english(self):
        files = [ROOT / 'secassist.py', ROOT / 'README.md', *sorted((ROOT / 'core').glob('*.py')),
                 *sorted((ROOT / 'docs').glob('*.md'))]
        for path in files:
            with self.subTest(path=path.name):
                text = path.read_text(encoding='utf-8')
                self.assertFalse(any('\u0600' <= c <= '\u06ff' for c in text))
        from core.prompts import SYSTEM_PROMPT
        self.assertIn('Always reply in English', SYSTEM_PROMPT)


class AgentIntegrationTests(Base):
    def test_model_tool_call_crosses_approval_then_completion_is_analyzed(self):
        tool = SimpleNamespace(name='fixture', binary=lambda: sys.executable, timeout=5,
                               risk='local', needs_target=False, desc='Harmless fixture')
        card = self.card('fixture', ['-u', '-c', "print('OBSERVED_FIXTURE')"])
        client = SimpleNamespace(api_key='fake', chat=None)
        call = {'id': 'fixture-call', 'type': 'function',
                'function': {'name': 'run_tool', 'arguments': json.dumps(card)}}
        client.chat = unittest.mock.Mock(side_effect=[
            {'role': 'assistant', 'content': 'Collect a harmless fixture.', 'tool_calls': [call]},
            {'role': 'assistant', 'content': 'Observed local fixture; no vulnerability established.'}])
        self.agent.client = client
        with patch.dict(REGISTRY, {'fixture': tool}), patch('core.ui.ask', return_value='yes') as ask:
            self.agent.turn('Collect fixture evidence')
            self.assertEqual(ask.call_count, 1)
            self.assertEqual(len(self.jobs.jobs), 1)
            job = next(iter(self.jobs.jobs.values()))
            self.assertTrue(job.done.wait(5))
            self.assertEqual(job.status, 'completed')
            self.agent.turn(self.jobs.result(job.id), event=True)
        self.assertEqual(client.chat.call_count, 2)
        self.assertIn('OBSERVED_FIXTURE', self.ws.session_file.read_text())

    def test_model_cannot_modify_scope(self):
        with self.assertRaises(ValueError):
            self.agent.dispatch('set_scope', {'scope': ['0.0.0.0/0']})
        self.assertFalse(self.scope.allows('203.0.113.10'))

    def model_calls(self, *calls):
        self.agent.client = SimpleNamespace(api_key='fake', chat=unittest.mock.Mock(
            return_value={'role': 'assistant', 'content': '', 'tool_calls': list(calls)}))

    def test_interrupted_edit_leaves_no_unanswered_tool_call(self):
        self.model_calls({'id': 'edit-call', 'type': 'function',
                          'function': {'name': 'run_tool', 'arguments': json.dumps(self.card())}})

        def ask(prompt, prefill=''):
            if prompt.startswith('edit>'):
                raise KeyboardInterrupt
            return 'e'
        with patch('core.ui.ask', side_effect=ask), patch.object(self.jobs, 'submit') as submit:
            self.agent.turn('Scan the host')
        submit.assert_not_called()
        self.assertTrue(self.agent.stopped)
        replies = [m['tool_call_id'] for m in self.agent.turns[-1] if m.get('role') == 'tool']
        self.assertEqual(replies, ['edit-call'])

    def test_interrupt_anywhere_answers_pending_calls(self):
        # Otherwise the API rejects every later request in this conversation.
        self.model_calls(*[{'id': f'call-{i}', 'type': 'function',
                            'function': {'name': 'search_notes', 'arguments': '{"query": "x"}'}} for i in range(2)])
        with patch.object(self.agent, 'dispatch', side_effect=KeyboardInterrupt):
            self.agent.turn('Search notes')
        replies = {m['tool_call_id'] for m in self.agent.turns[-1] if m.get('role') == 'tool'}
        self.assertEqual(replies, {'call-0', 'call-1'})


class ReportTests(unittest.TestCase):
    def data(self):
        base = {'source': 'outputs/a.txt', 'description': 'Observed.', 'remediation': 'Patch.', 'evidence': 'quote'}
        return {'target': 'example.test', 'scope': ['example.test'], 'generated_utc': '2026-10-30T00:00:00+00:00',
                'plan': [{'question': 'Is HTTP exposed?', 'status': 'supported', 'evidence': 'outputs/a.txt'}],
                'evidence': {'outputs/a.txt': {'sha256': 'ab' * 32, 'status': 'completed'}},
                'findings': [
                    {**base, 'id': 1, 'title': 'Low thing', 'severity': 'low', 'status': 'suspected',
                     'evidence': '<script>alert(1)</script> Authorization: Bearer abc123'},
                    {**base, 'id': 2, 'title': 'Critical thing', 'severity': 'critical', 'status': 'user_confirmed'},
                    {**base, 'id': 3, 'title': 'Noise', 'severity': 'high', 'status': 'rejected',
                     'rejection': 'false positive per owner'}],
                'current_process_jobs': []}

    def test_html_escapes_untrusted_evidence(self):
        page = html_page(self.data())
        self.assertNotIn('<script>', page)
        self.assertIn('&lt;script&gt;', page)
        self.assertNotIn('abc123', page)
        self.assertIn("default-src 'none'", page)

    def test_severity_order_and_rejected_section(self):
        for name, text in (('markdown', markdown(self.data())), ('html', html_page(self.data()))):
            with self.subTest(name=name):
                self.assertLess(text.index('Critical thing'), text.index('Low thing'))
                self.assertLess(text.index('Low thing'), text.index('Noise'))
                self.assertIn('false positive per owner', text)


class CLITests(unittest.TestCase):
    def test_offline_workflow_and_report(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = Path(temp) / 'evidence.txt'
            fixture.write_text('observed fixture only')
            commands = ('/scope add example.test\n/target example.test\n/import "' + fixture.as_posix() + '"\n'
                        '/finding 1\n/report\n/exit\n')
            env = {**os.environ, 'PYTHONIOENCODING': 'utf-8'}
            env.pop('DEEPSEEK_API_KEY', None)
            result = subprocess.run([sys.executable, str(ROOT / 'secassist.py'), '--data', temp],
                                    input=commands, text=True, capture_output=True, encoding='utf-8',
                                    env=env, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Reports:', result.stdout)
            self.assertIn('Unknown finding ID', result.stdout)
            reports = list(Path(temp).rglob('report_*.json'))
            self.assertTrue(reports)
            self.assertEqual(json.loads(reports[0].read_text())['target'], 'example.test')
            self.assertTrue(list(Path(temp).rglob('report_*.html')))

    def test_version_without_api_key(self):
        result = subprocess.run([sys.executable, str(ROOT / 'secassist.py'), '--version'],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertIn('3.2.0', result.stdout)


if __name__ == '__main__':
    unittest.main()
