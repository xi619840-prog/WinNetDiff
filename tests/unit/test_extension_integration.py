"""Actual isolated Tk callbacks and mocked CLI; never changes the clipboard."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from winnetdiff import cli
from winnetdiff.gui import app
from winnetdiff.core.i18n import set_language
from winnetdiff.core.models import Probe
from winnetdiff.core import engine
from tests.unit.test_extensions import dns_routes,dns_probe,runtime
import types
from tests.unit import test_i18n_safety_gui as gui_helpers
from tests.unit.test_extensions import private_card_report


def repeated_tls_report():
    report=gui_helpers.empty_report('en')
    context={'port':443,'sni':'synthetic.example','method':'HEAD','path':'/',
             'connect_timeout':5,'tls_timeout':6,'http_timeout':5}
    report.probes=[Probe('synthetic.example','IPv4',ip='203.0.113.7',stage='tls_timeout',tcp_ms=5,context=context,
        attempts=[{'host':'synthetic.example','family':'IPv4','ip':'203.0.113.7','stage':'tls_timeout','tcp_ms':5,
                   'attempt':i,'context':context} for i in (1,2)])]
    return report


class ExtensionCliTests(unittest.TestCase):
    def setUp(self):
        override = patch.object(cli, '_live_audit_supported', return_value=True)
        override.start()
        self.addCleanup(override.stop)

    def tearDown(self):set_language('en')

    def test_card_stdout_is_only_bounded_preview_and_progress_is_suppressed(self):
        report,_=private_card_report()
        def scan(*args,**kwargs):args[2]('PrivateProgressToken');return report
        with patch.object(cli,'load_settings',return_value={}),patch.object(cli,'scan',side_effect=scan) as scanner, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(['--cli','--no-network','--share-card','--lang','en']),0)
        self.assertLessEqual(len(output.getvalue().rstrip('\n')),500)
        self.assertNotIn('PrivateProgressToken',output.getvalue());self.assertNotIn('PrivateAlice',output.getvalue())
        self.assertTrue(scanner.call_args.kwargs['fake_ip_audit'])

    def test_pmtu_requires_explicit_consent_and_network(self):
        with patch.object(cli,'load_settings',return_value={}),patch.object(cli,'scan') as scanner,contextlib.redirect_stderr(io.StringIO()):
            for args in (['--pmtu'],['--pmtu','--confirm-pmtu','--no-network']):
                with self.assertRaises(SystemExit) as caught:cli.main(['--cli',*args])
                self.assertEqual(caught.exception.code,2)
        scanner.assert_not_called()

    def test_pmtu_only_runs_selected_repeated_tls_target(self):
        report=repeated_tls_report()
        with patch.object(cli,'load_settings',return_value={}),patch.object(cli,'scan',return_value=report),patch.object(
                cli,'probe_pmtu',return_value={'status':'icmp_no_result'}) as probe,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['--cli','--lang','en','--pmtu','--confirm-pmtu','--no-fake-ip-audit']),0)
        self.assertEqual(probe.call_count,1);self.assertEqual(probe.call_args.args[0],'203.0.113.7')
        self.assertIs(probe.call_args.kwargs['confirmed'],True)
        self.assertEqual(report.pmtu,[{'status':'icmp_no_result'}])

    def test_saved_disabled_audit_and_explicit_enable_override(self):
        with patch.object(cli,'load_settings',return_value={'fake_ip_audit':False}),patch.object(
                cli,'scan',return_value=gui_helpers.empty_report('en')) as scanner,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['--cli','--no-network']),0)
            self.assertFalse(scanner.call_args.kwargs['fake_ip_audit'])
            self.assertEqual(cli.main(['--cli','--no-network','--fake-ip-audit']),0)
            self.assertTrue(scanner.call_args.kwargs['fake_ip_audit'])

    def test_cli_existing_report_remains_intact(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'manual.json';path.write_text('manual evidence',encoding='utf-8')
            with patch.object(cli,'load_settings',return_value={}),patch.object(cli,'scan',return_value=gui_helpers.empty_report('en')),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(['--cli','--no-network','--json',str(path)]),1)
            self.assertEqual(path.read_text(),'manual evidence')

    def test_card_with_snapshot_keeps_file_status_off_stdout(self):
        report=gui_helpers.empty_report('en')
        with tempfile.TemporaryDirectory() as directory,patch.object(cli,'load_settings',return_value={}),patch.object(cli,'scan',return_value=report),contextlib.redirect_stdout(io.StringIO()) as output,contextlib.redirect_stderr(io.StringIO()) as status:
            self.assertEqual(cli.main(['--cli','--no-network','--share-card','--snapshot',str(Path(directory)/'snapshot.json')]),0)
            self.assertLessEqual(len(output.getvalue().rstrip('\n')),500)
            self.assertNotIn('Saved:',output.getvalue());self.assertIn('Saved:',status.getvalue())


class ExtensionEngineTests(unittest.TestCase):
    def tearDown(self):set_language('en')

    def execute(self,enabled=True,network=True,fail=False):
        routes=dns_routes()
        if fail:routes['routes']=[]
        def probe(host,family,**kwargs):
            return Probe(host,'IPv4',ip='198.18.1.5',resolved_addresses=['198.18.1.5'],stage='tcp_timeout' if fail else 'http_ok') if family==2 else Probe(host,'IPv6',stage='dns_error')
        with patch.object(engine,'os',types.SimpleNamespace(name='nt')),patch.object(engine,'is_admin',return_value=False),patch.object(engine.platform,'platform',return_value='Synthetic Windows'),patch.object(engine,'collect_proxy',return_value={'errors':[]}),patch.object(engine,'collect_routes',return_value=routes),patch.object(engine,'collect_security',return_value={'errors':[],'evidence':[]}),patch.object(engine,'probe_host_family',side_effect=probe),patch.object(engine,'collect_dns_runtime',return_value=runtime(not fail)) as collector:
            report=engine.scan(['synthetic.example'],do_network=network,fake_ip_audit=enabled)
        return report,collector

    def test_engine_keeps_explicit_fake_ip_codes_and_priority(self):
        report,collector=self.execute(fail=True)
        finding=next(f for f in report.findings if f.code=='dns.fake_ip_unroutable_suspected')
        self.assertEqual(finding.severity,'高優先級');self.assertEqual(finding.evidence_grade,'E1')
        collector.assert_called_once();self.assertTrue(report.scan_options['fake_ip_audit'])

    def test_engine_disabled_is_independent_of_network_mode(self):
        report,collector=self.execute(enabled=False)
        collector.assert_not_called();self.assertFalse(report.dns_audit['enabled'])
        self.assertFalse(any(f.code.startswith('dns.fake_ip') for f in report.findings))

    def test_engine_offline_has_config_context_without_fabricated_failure(self):
        report,collector=self.execute(network=False)
        self.assertEqual(report.probes,[]);self.assertTrue(report.dns_audit['dns_servers'])
        self.assertFalse(report.dns_audit['network_tested'])
        self.assertFalse(any(f.code=='dns.fake_ip_unroutable_suspected' for f in report.findings))


@unittest.skipUnless(sys.platform=='win32','Actual isolated Windows Tk callbacks')
class ExtensionGuiTests(unittest.TestCase):
    run_gui=gui_helpers.GuiAuditSafetyTests.run_gui
    wait_worker=gui_helpers.GuiAuditSafetyTests.wait_worker
    def tearDown(self):set_language('en')

    def test_card_preview_is_not_copied_until_explicit_button(self):
        import tkinter as tk
        real_toplevel=tk.Toplevel
        def hidden(*args,**kwargs):
            result=real_toplevel(*args,**kwargs);result.withdraw();return result
        report,_=private_card_report()
        def exercise(root,widgets,state):
            widgets['display_report'](report)
            widgets['share'].invoke()
            self.assertLessEqual(len(root.winnetdiff_share_preview['card']),500)
            clear.assert_not_called();append.assert_not_called()
            root.winnetdiff_share_preview['copy'].invoke()
            clear.assert_called_once();append.assert_called_once_with(root.winnetdiff_share_preview['card'])
            self.assertNotIn('PrivateAlice',append.call_args.args[0])
        with patch.object(tk,'Toplevel',side_effect=hidden),patch.object(tk.Tk,'clipboard_clear') as clear,patch.object(tk.Tk,'clipboard_append') as append:
            self.run_gui(exercise)

    def test_pmtu_decline_sends_nothing_then_accept_uses_worker(self):
        from tkinter import messagebox
        report=repeated_tls_report()
        def exercise(root,widgets,state):
            widgets['display_report'](report)
            widgets['request_pmtu']();probe.assert_not_called()
            widgets['request_pmtu']();self.wait_worker(root,state)
            self.assertEqual(len(state['report'].pmtu),1)
            self.assertEqual(probe.call_args.args[0],'203.0.113.7')
            self.assertIs(probe.call_args.kwargs['confirmed'],True)
        with patch.object(messagebox,'askyesno',side_effect=[False,True]),patch.object(messagebox,'showinfo'),patch.object(
                app,'probe_pmtu',return_value={'status':'icmp_no_result','samples':[]}) as probe:
            self.run_gui(exercise)

    def test_language_keeps_fake_ip_switch_and_scan_parameter(self):
        def exercise(root,widgets,state):
            widgets['fake_ip_var'].set(False)
            widgets['language_var'].set('繁體中文');widgets['change_language']()
            self.assertFalse(widgets['fake_ip_var'].get())
            widgets['run'].invoke();self.wait_worker(root,state)
        with patch.object(app,'scan',return_value=gui_helpers.empty_report('zh-TW')) as scanner:
            self.run_gui(exercise,no_network=True)
        self.assertFalse(scanner.call_args.kwargs['fake_ip_audit'])

    def test_report_overwrite_decline_preserves_file_then_confirm_replaces(self):
        from tkinter import messagebox,filedialog
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'manual.json';path.write_text('manual evidence',encoding='utf-8')
            def exercise(root,widgets,state):
                widgets['display_report'](gui_helpers.empty_report('en'))
                widgets['export_report']('json');self.assertEqual(path.read_text(),'manual evidence')
                widgets['export_report']('json');self.wait_worker(root,state)
                self.assertEqual(json.loads(path.read_text(encoding='utf-8'))['locale'],'en')
            # Default export is now redacted directly; only overwrite asks.
            with patch.object(filedialog,'asksaveasfilename',return_value=str(path)),patch.object(messagebox,'askyesno',side_effect=[False,True]) as overwrite:
                self.run_gui(exercise)
            self.assertEqual(overwrite.call_count,2)
