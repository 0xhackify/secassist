"""Deterministic methodology, facts and installed-tool checks. No scanner or network use."""
import os
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.facts import Facts
from core.jobs import JobManager
from core.methodology import Methodology
from core.policy import Action
from core.report import html_page, markdown
from core.scope import readable
from core.toolcheck import ToolCheck, managed_defaults
from core.tools import REGISTRY, clean_output
from core.workspace import Workspace
from test_secassist import Base

TOP_PORTS = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="192.0.2.10" addrtype="ipv4"/><hostnames><hostname name="example.test"/></hostnames><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5" method="probed"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.49" method="probed"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" method="probed"/></port>
<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MySQL" method="probed"/></port>
<port protocol="tcp" portid="5985"><state state="open"/><service name="http" product="Microsoft HTTPAPI httpd" version="2.0" method="probed"/></port>
<port protocol="tcp" portid="8443"><state state="closed"/></port>
</ports></host></nmaprun>"""
ALL_PORTS = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" method="table"/></port>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy" method="table"/></port>
</ports></host></nmaprun>"""
DNS_HOST = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="53"><state state="open"/><service name="domain" method="probed"/></port>
</ports></host></nmaprun>"""
ENUMERATION = ['manual.review@example.test:22', 'web.fingerprint@example.test:80', 'web.headers@example.test:80',
               'web.waf@example.test:80', 'web.content@example.test:80', 'smb.shares@example.test',
               'smb.enum@example.test', 'manual.review@example.test:3306', 'manual.review@example.test:5985']
VULNERABILITY = ['vuln.exploit-db:openssh-8.2p1', 'vuln.nuclei@example.test:80', 'vuln.exploit-db:apache-2.4.49',
                 'vuln.exploit-db:microsoft-httpapi-2.0']


class MethodologyBase(Base):
    def setUp(self):
        super().setUp()
        self.words = self.ws.root / 'common.txt'
        self.words.write_text('admin\n')
        self.lists = patch('core.methodology.wordlists', return_value={'web-common': str(self.words)})
        self.lists.start()
        self.method = self.agent.method
        self.fake = SimpleNamespace(jobs={})

    def tearDown(self):
        self.lists.stop()
        super().tearDown()

    def statuses(self, method=None):
        return {s.id: status for s, status, _ in (method or self.method).evaluate()[0]}

    def finish(self, step_id, xml=None, status='completed'):
        jid = f'job{len(self.fake.jobs)}'
        path = self.ws.outputs / f'nmap_{jid}.txt'
        path.write_text('done')
        if xml:
            (self.ws.outputs / f'nmap_{jid}.xml').write_text(xml)
        step = next(s for s in self.method.steps() if s.id == step_id)
        job = SimpleNamespace(id=jid, tool=step.tool, args=list(step.args), done=threading.Event(), status=status,
                              returncode=0 if status == 'completed' else 1, path=path)
        job.done.set()
        self.method.start(step, job)
        self.fake.jobs[jid] = job
        self.method.sync(self.fake)

    def discovered(self):
        self.finish('discovery.top-ports', TOP_PORTS)
        self.method.skip('discovery.all-ports', 'Lab time box')


class MethodologyTests(MethodologyBase):
    def test_discovery_runs_first_in_fixed_order(self):
        self.assertEqual(self.statuses(), {'discovery.top-ports': 'ready', 'discovery.all-ports': 'pending'})
        self.finish('discovery.top-ports', TOP_PORTS)
        rows, phase = self.method.evaluate()
        self.assertEqual(phase, 'discovery')
        self.assertEqual(self.statuses()['discovery.all-ports'], 'ready')
        self.assertTrue(all(st == 'pending' for s, st, _ in rows if s.phase == 'enumeration' and not s.note))

    def test_same_facts_produce_identical_steps(self):
        self.discovered()
        first = [(s.id, s.tool, s.args) for s in self.method.steps()]
        again = [(s.id, s.tool, s.args) for s in Methodology(self.ws).steps()]
        self.assertEqual(first, again)
        self.assertEqual([s.id for s in self.method.steps() if s.phase == 'enumeration'], ENUMERATION)
        self.assertEqual([s.id for s in self.method.steps() if s.phase == 'vulnerability'], VULNERABILITY)
        statuses = self.statuses()
        self.assertEqual(statuses['manual.review@example.test:5985'], 'manual')  # WinRM is not a web target
        self.assertEqual(self.method.evaluate()[1], 'enumeration')

    def test_playbook_commands_are_reviewed_for_unattended_use(self):
        self.discovered()
        self.policy.grant('active')
        ready = self.method.ready()
        self.assertEqual([s.id for s in ready], [x for x in ENUMERATION if not x.startswith('manual')])
        for step in ready:
            with self.subTest(step=step.id):
                action = self.validate(step.tool, step.args)
                self.assertEqual(action.warnings, [])
                self.assertTrue(self.policy.auto_allows(action))
        content = next(s for s in ready if s.id.startswith('web.content'))
        self.assertEqual(content.args, ['dir', '-u', 'http://example.test', '-w', str(self.words), '-t', '20', '-q', '-k'])

    def test_vulnerability_phase_follows_enumeration(self):
        self.discovered()
        for step in self.method.ready():
            self.method.record(step.id, 'completed')
        rows, phase = self.method.evaluate()
        self.assertEqual(phase, 'vulnerability')
        exploit = next(s for s in self.method.ready() if s.id == 'vuln.exploit-db:apache-2.4.49')
        self.assertEqual(exploit.args, ['Apache', '2.4.49'])
        nuclei = self.validate(*next((s.tool, s.args) for s in self.method.ready() if s.tool == 'nuclei'))
        self.assertEqual(nuclei.risk, 'intrusive')
        self.assertEqual(nuclei.defaults, ['-duc', '-ni', '-nc'])
        for step in self.method.ready():
            self.method.record(step.id, 'completed')
        self.assertEqual(self.method.evaluate()[1], 'reporting')

    def test_full_port_scan_queues_version_probe_for_new_ports(self):
        self.finish('discovery.top-ports', TOP_PORTS)
        self.finish('discovery.all-ports', ALL_PORTS)
        step = next(s for s in self.method.steps() if s.id == 'discovery.new-port-versions')
        self.assertEqual(step.args, ['-sT', '-sV', '-Pn', '-p', '8080', 'example.test'])
        apache = next(info for _, key, info in self.method.facts.services() if key == '80/tcp')
        self.assertEqual(apache['product'], 'Apache httpd')  # a later table guess never erases a probed banner

    def test_missing_tool_or_wordlist_is_reported_not_guessed(self):
        self.discovered()
        with patch('core.tools.shutil.which', side_effect=lambda b: None if b in ('gobuster', 'ffuf') else sys.executable):
            reason = dict((s.id, r) for s, _, r in self.method.evaluate()[0])['web.content@example.test:80']
        self.assertIn('Not installed: gobuster or ffuf', reason)
        with patch('core.methodology.wordlists', return_value={'web-common': None}):
            rows = {s.id: (st, r) for s, st, r in self.method.evaluate()[0]}
        self.assertEqual(rows['web.content@example.test:80'][0], 'blocked')
        self.assertIn('No web wordlist', rows['web.content@example.test:80'][1])

    def test_zone_transfer_needs_a_domain(self):
        for target, expected in (('192.0.2.10', 'not_applicable'), ('example.test', 'ready')):
            with self.subTest(target=target):
                ws = Workspace(self.root / f'dns-{target}', target)
                method = Methodology(ws)
                (ws.outputs / 'nmap_dns.xml').write_text(DNS_HOST)
                method.facts.ingest_nmap(ws.outputs / 'nmap_dns.xml', 'outputs/nmap_dns.xml')
                method.record('discovery.top-ports', 'completed')
                method.record('discovery.all-ports', 'skipped')
                self.assertEqual(self.statuses(method)[f'dns.zone-transfer@{target}:53'], expected)
        step = next(s for s in method.steps() if s.id.startswith('dns.'))
        self.assertEqual(self.validate(step.tool, step.args).warnings, [])

    def test_interrupted_steps_fail_on_restart_and_can_be_retried(self):
        self.method.record('discovery.top-ports', 'running', job='gone')
        method = Methodology(self.ws)
        self.assertEqual(self.statuses(method)['discovery.top-ports'], 'failed')
        method.retry('discovery.top-ports')
        self.assertEqual(self.statuses(method)['discovery.top-ports'], 'ready')
        with self.assertRaises(ValueError):
            method.skip('no.such.step')


class AdvanceTests(MethodologyBase):
    def submit(self, action):
        return SimpleNamespace(id='job-x', tool=action.tool.name, args=action.args + action.defaults)

    def test_next_launches_ready_steps_in_order(self):
        with patch('core.ui.ask', return_value='y') as ask, \
             patch.object(self.jobs, 'submit', side_effect=self.submit) as submit:
            results = self.agent.advance()
        self.assertEqual(submit.call_count, 1)  # all-ports waits for top-ports
        self.assertEqual(ask.call_count, 1)
        self.assertTrue(results[0].startswith('discovery.top-ports: STARTED'))
        self.assertEqual(self.statuses()['discovery.top-ports'], 'running')

    def test_declined_step_is_reported_as_skipped(self):
        with patch('core.ui.ask', return_value='n'), patch.object(self.jobs, 'submit') as submit:
            self.agent.advance()
        submit.assert_not_called()
        self.assertEqual(self.statuses()['discovery.top-ports'], 'skipped')

    def test_unattended_runs_only_what_the_grant_covers(self):
        self.policy.grant('local')
        with patch('core.ui.ask', side_effect=AssertionError('no prompt in unattended mode')), \
             patch.object(self.jobs, 'submit', side_effect=self.submit) as submit:
            self.assertEqual(self.agent.advance(unattended=True), [])
            submit.assert_not_called()
            self.policy.grant('recon')
            self.agent.advance(unattended=True)
        self.assertEqual(submit.call_count, 1)

    def test_model_proposals_always_need_approval(self):
        self.policy.grant('intrusive')
        with patch('core.ui.ask', return_value='n') as ask, patch.object(self.jobs, 'submit') as submit:
            self.agent.run(self.card())
        ask.assert_called_once()
        submit.assert_not_called()
        with patch('core.ui.ask', side_effect=AssertionError('granted operator command')), \
             patch.object(self.jobs, 'submit', side_effect=self.submit) as submit:
            self.agent.run(self.card(), source='operator')
        submit.assert_called_once()


class ToolCheckTests(Base):
    NMAP_HELP = ('Nmap 7.94 ( https://nmap.org )\nSCAN TECHNIQUES:\n  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK scans\n'
                 '  -sV: Probe open ports to determine service/version info\n  -Pn: Treat all hosts as online\n'
                 '  -p <port ranges>: Only scan specified ports\n  -T<0-5>: Set timing template\n'
                 '  --min-rate <number>: Send packets no slower than <number> per second\n')

    def check(self, text):
        return ToolCheck(runner=lambda cmd: text)

    def test_flags_are_matched_against_installed_help(self):
        check, nmap = self.check(self.NMAP_HELP), REGISTRY['nmap']
        for flag in ('-sT', '-sV', '-Pn', '-p', '-p-', '-T4', '--min-rate'):
            with self.subTest(flag=flag):
                self.assertTrue(check.supports(nmap, [], flag))
        for flag in ('-sZ', '--made-up', '--top-ports'):
            with self.subTest(flag=flag):
                self.assertFalse(check.supports(nmap, [], flag))
        curl = self.check('Usage: curl [options...] <url>\n -s, --silent  Silent mode\n -i, --include  Include headers\n'
                          ' -k, --insecure  Allow insecure server connections\n')
        self.assertTrue(curl.supports(REGISTRY['curl'], [], '-sik'))
        self.assertTrue(self.check('usage: tool').supports(nmap, [], '--anything'))  # no usable help: no guess

    def test_policy_warns_about_flags_missing_from_installed_version(self):
        self.policy.toolcheck = self.check(self.NMAP_HELP)
        action = self.validate('nmap', ['-sV', '--top-ports', '100', '192.0.2.10'])
        self.assertIn('--top-ports is not in the installed nmap help; check the tool version', action.warnings)
        self.assertEqual(self.validate('nmap', ['-sT', '-sV', '-Pn', '192.0.2.10']).warnings, [])

    def test_managed_defaults_follow_installed_support(self):
        nuclei = REGISTRY['nuclei']
        self.assertEqual(managed_defaults(nuclei, ['-ni']), ['-duc', '-nc'])
        help_text = 'Nuclei usage\n  -duc, -disable-update-check  disable update check\n' + ' ' * 80
        self.assertEqual(managed_defaults(nuclei, [], self.check(help_text)), ['-duc'])

    def test_raw_socket_scans_need_root(self):
        with patch('core.policy.privileged', return_value=False):
            with self.assertRaises(ValueError) as error:
                self.validate('nmap', ['-sS', '192.0.2.10'])
            self.assertIn('-sT', str(error.exception))
            self.validate('nmap', ['-sS', '--privileged', '192.0.2.10'])

    def test_symlinked_kali_wordlists_are_readable(self):
        share = self.root / 'share'
        (share / 'dirb' / 'wordlists').mkdir(parents=True)
        (share / 'dirb' / 'wordlists' / 'common.txt').write_text('admin\n')
        (self.root / 'secret').mkdir()
        (self.root / 'secret' / 'key').write_text('private')
        wordlists = share / 'wordlists'
        wordlists.mkdir()
        try:
            (wordlists / 'dirb').symlink_to(share / 'dirb' / 'wordlists', target_is_directory=True)
            (wordlists / 'leak').symlink_to(self.root / 'secret', target_is_directory=True)
        except OSError:
            self.skipTest('Symlinks require permission on this OS')
        with patch('core.scope.SYSTEM_DATA', str(share)):
            self.assertTrue(readable(wordlists / 'dirb' / 'common.txt', [wordlists]))
            self.assertFalse(readable(wordlists / 'leak' / 'key', [wordlists]))
            self.assertFalse(readable(self.root / 'secret' / 'key', [wordlists]))


class OutputTests(Base):
    def test_progress_noise_is_removed_for_the_model(self):
        raw = ('\n:: Progress: [120/4614] :: Job [1/1] :: 41 req/sec\nadmin                   [Status: 301, Size: 0]\n'
               'Progress: 1200 / 4615 (26.00%)\n[>-------------------] - 3s      120/4614    40/s\n'
               '/backup               (Status: 403) [Size: 277]\n/backup               (Status: 403) [Size: 277]\n')
        self.assertEqual(clean_output(raw), 'admin                   [Status: 301, Size: 0]\n'
                                            '/backup               (Status: 403) [Size: 277]')

    def test_carriage_return_progress_cannot_swallow_results(self):
        jobs = JobManager(self.ws)
        tool = SimpleNamespace(name='fixture', binary=lambda: sys.executable, timeout=5)
        script = "import sys; sys.stdout.write(':: Progress: [1/9]\\r:: Progress: [9/9]\\radmin [Status: 301]\\n')"
        with patch('core.tools.shutil.which', wraps=__import__('shutil').which):
            job = jobs.submit(Action(tool, ['-u', '-c', script], [], 'local'))
            self.assertTrue(job.done.wait(5))
        jobs.close()
        self.assertIn('\nadmin [Status: 301]', job.path.read_text())
        self.assertEqual(clean_output(job.tail), 'admin [Status: 301]')


class FactsTests(Base):
    def test_probed_banner_survives_later_guess_and_order_is_fixed(self):
        facts = Facts(self.ws)
        for name, xml in (('a.xml', ALL_PORTS), ('b.xml', TOP_PORTS)):
            (self.ws.outputs / name).write_text(xml)
            facts.ingest_nmap(self.ws.outputs / name, 'outputs/' + name)
        services = facts.services()
        self.assertEqual([key for _, key, _ in services], ['22/tcp', '80/tcp', '445/tcp', '3306/tcp', '5985/tcp', '8080/tcp'])
        apache = dict((k, i) for _, k, i in services)['80/tcp']
        self.assertEqual((apache['product'], apache['probed']), ('Apache httpd', True))
        self.assertEqual(apache['sources'], ['outputs/a.xml', 'outputs/b.xml'])


class CoverageReportTests(MethodologyBase):
    def test_reports_show_inventory_and_untested_steps(self):
        self.discovered()
        self.method.skip('web.waf@example.test:80', 'WAF check | out of time')
        data = {'target': 'example.test', 'scope': ['example.test'], 'generated_utc': 'now', 'plan': [],
                'evidence': {}, 'findings': [], 'methodology': self.method.coverage(),
                'services': [{'address': a, 'port': k, **i} for a, k, i in self.method.facts.services()]}
        md, page = markdown(data), html_page(data)
        for text in (md, page):
            self.assertIn('Methodology coverage', text)
            self.assertIn('Apache httpd', text)
            self.assertIn('web.waf@example.test:80', text)
        self.assertIn('WAF check \\| out of time', md)
        self.assertIn('class="st-skipped"', page)


if __name__ == '__main__':
    unittest.main()
