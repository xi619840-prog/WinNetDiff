"""Synthetic data only; no network, driver or user configuration changes."""
import copy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from winnetdiff.core.privacy import redact, redacted_data
from winnetdiff.core.snapshots import create_snapshot, compare_snapshots, save_snapshot
from winnetdiff.core.models import Finding, Report
from winnetdiff.reports.export import evidence_text, markdown_report, summarize, repair_text
from winnetdiff.collectors.security import export_wfp, classify_security
from winnetdiff.collectors.routes import collect_routes, BINDING_COMPONENT_QUERY
from tests.unit.test_snapshots_scenarios import sample_report
from winnetdiff import cli


class PrivacyPolicyTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict('os.environ', {'USERNAME': '张三', 'COMPUTERNAME': 'Synthetic-LAPTOP99'})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.payload = {'SSID': 'PrivateWifi', 'ProfileName': 'PrivateProfile',
                        'MacAddress': 'AA:BB:CC:DD:EE:FF', 'PhysicalAddress': 'AA-BB-CC-DD-EE-FF',
                        'raw_columns': [r'D:\PrivateLab\Internal\bdnet.sys', 'aa bb cc dd ee ff'],
                        'error': r'D:\Projects\张三的测试目录\app.exe; prefix_Synthetic-LAPTOP99_suffix',
                        'error_detail': 'error: {"password": "synthetic-private-sentinel"}',
                        'DisplayVersion': '4.5.5.0', 'version': '2.1.0.1', 'Module': 'BdNet', 'tcp_ms': 12.5}

    def assert_private_removed(self, text):
        for value in ('PrivateWifi', 'PrivateProfile', 'aa:bb:cc:dd:ee:ff', 'aa-bb-cc-dd-ee-ff',
                      'aa bb cc dd ee ff', 'PrivateLab', 'Internal', '张三', 'Synthetic-LAPTOP99', 'synthetic-private-sentinel'):
            self.assertNotIn(value.casefold(), text.casefold())

    def test_one_policy_preserves_semantic_versions_and_is_idempotent(self):
        clean = redacted_data(self.payload)
        self.assert_private_removed(json.dumps(clean, ensure_ascii=False))
        self.assertEqual(clean['DisplayVersion'], '4.5.5.0')
        self.assertEqual(clean['version'], '2.1.0.1')
        self.assertEqual(clean['tcp_ms'], 12.5)
        self.assertEqual(clean['Module'], 'BdNet')
        self.assertIn('bdnet.sys', str(clean))
        self.assertEqual(clean, redacted_data(clean))

    def test_header_and_quoted_secrets_and_ascii_identity_boundaries(self):
        for text in ('Authorization: Bearer synthetic-token-987', 'password="first second third"',
                     'Auth result {\'password\': \'first second third\'}'):
            clean = redact(text)
            for private in ('synthetic-token-987', 'first', 'second', 'third'):
                self.assertNotIn(private, clean)
        with patch.dict('os.environ', {'USERNAME': 'Al'}):
            self.assertEqual(redact('Malwarebytes'), 'Malwarebytes')
            self.assertNotIn('_Al_', redact('prefix_Al_suffix'))
        self.assertIn('https://example.com', redact('https://example.com'))
        prefixed = redact('error: {"password": "first\\\"second", "DisplayVersion": "4.5.5.0"}')
        self.assertNotIn('first', prefixed)
        self.assertNotIn('second', prefixed)
        self.assertIn('4.5.5.0', prefixed)

    def test_every_report_renderer_and_full_opt_in(self):
        evidence = json.dumps(self.payload, ensure_ascii=False)
        report = Report('2.1.0b2', '2026-10-24', 'Synthetic-LAPTOP99', False, ['example.com'],
                        self.payload, {}, [], {}, [Finding('資訊', '安全/驅動', 'Observation', evidence,
                        self.payload['error'], commands=[self.payload['error']])], [self.payload['error']])
        for renderer in (evidence_text, markdown_report, summarize, repair_text):
            with self.subTest(renderer=renderer.__name__):
                text = renderer(report)
                self.assert_private_removed(text)
                self.assertIn('4.5.5.0', text)
                self.assertIn('2.1.0.1', text)
        self.assertIn('PrivateLab', evidence_text(report, full=True))

    def test_snapshot_and_difference_use_same_privacy_policy(self):
        before = sample_report()
        before['security']['installed_apps'] = [dict(self.payload, DisplayName='TestVPN', Publisher='Alden',
                                                    Scope='user', RegistryKey='synthetic-app')]
        before['route']['adapters'][0]['Name'] = self.payload['error']
        before['route']['errors'] = [json.dumps(self.payload, ensure_ascii=False)]
        after = copy.deepcopy(before)
        after['security']['installed_apps'][0]['DisplayVersion'] = '2.1.0.1'
        first, second = create_snapshot(before), create_snapshot(after)
        for value in (first, second, compare_snapshots(first, second)):
            self.assert_private_removed(json.dumps(value, ensure_ascii=False))
        self.assertIn('4.5.5.0', json.dumps(first))
        self.assertIn('2.1.0.1', json.dumps(compare_snapshots(first, second)))

    def test_cli_real_exports_and_comparison_redact_default_output(self):
        evidence = json.dumps(self.payload, ensure_ascii=False)
        report = Report('2.1.0b2', '2026-10-24', 'Synthetic-LAPTOP99', False, ['example.com'],
                        self.payload, {}, [], {}, [Finding('資訊', '安全/驅動', 'Observation', evidence,
                        self.payload['error'])], [self.payload['error']])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = io.StringIO()
            with patch.object(cli, '_live_audit_supported', return_value=True), patch.object(cli, 'scan', return_value=report), patch.object(cli, 'load_settings', return_value={}), contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(['--cli', '--lang', 'en', '--no-network', '--json', str(root/'report.json'),
                                           '--markdown', str(root/'report.md'), '--snapshot', str(root/'snapshot.json')]), 0)
            for text in [output.getvalue(), *[p.read_text(encoding='utf-8') for p in root.iterdir()]]:
                self.assert_private_removed(text)
            before = sample_report()
            before['security']['installed_apps'] = [dict(self.payload, DisplayName='TestVPN', Publisher='Alden',
                                                        Scope='user', RegistryKey='synthetic-app')]
            after = copy.deepcopy(before)
            after['security']['installed_apps'][0]['DisplayVersion'] = '2.1.0.1'
            save_snapshot(root/'before.json', before, label=self.payload['error'])
            save_snapshot(root/'after.json', after, label=self.payload['error'])
            with patch.object(cli, 'load_settings', return_value={}), contextlib.redirect_stdout(io.StringIO()) as comparison:
                self.assertEqual(cli.main(['--cli', '--lang', 'en', '--compare', str(root/'before.json'), str(root/'after.json'),
                                           '--json', str(root/'diff.json'), '--markdown', str(root/'diff.md')]), 0)
            for text in (comparison.getvalue(), (root/'diff.json').read_text(encoding='utf-8'), (root/'diff.md').read_text(encoding='utf-8')):
                self.assert_private_removed(text)
                self.assertIn('4.5.5.0', text)
                self.assertIn('2.1.0.1', text)


class AtomicEvidenceTests(unittest.TestCase):
    def test_snapshot_replace_and_failed_replace_preserve_old_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'snapshot.json'
            save_snapshot(path, sample_report(), label='first')
            save_snapshot(path, sample_report(), label='second', overwrite=True)
            self.assertEqual(json.loads(path.read_text(encoding='utf-8'))['label'], 'second')
            old = path.read_bytes()
            with patch('winnetdiff.core.atomic.os.replace', side_effect=OSError('synthetic failure')):
                with self.assertRaises(OSError):
                    save_snapshot(path, sample_report(), overwrite=True)
            self.assertEqual(path.read_bytes(), old)
            with self.assertRaises(FileExistsError):
                save_snapshot(path, sample_report())
            self.assertEqual(path.read_bytes(), old)
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_wfp_replace_only_after_successful_validation(self):
        def command(argv, **kwargs):
            temporary = Path(next(arg[5:] for arg in argv if arg.startswith('file=')))
            temporary.write_text('<wfp><providers/></wfp>', encoding='utf-8')
            return {'ok': True}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.xml'
            path.write_text('original', encoding='utf-8')
            with patch('winnetdiff.collectors.security.run_command', side_effect=command):
                with self.assertRaises(FileExistsError):
                    export_wfp(path)
                result = export_wfp(path, overwrite=True)
                self.assertTrue(result['ok'])
                self.assertIn('<wfp>', path.read_text())
                old = path.read_bytes()
                with patch('winnetdiff.collectors.security.summarize_wfp_xml', side_effect=OSError('parse failed')):
                    self.assertFalse(export_wfp(path, overwrite=True)['ok'])
                self.assertEqual(old, path.read_bytes())
                cancelled = threading.Event(); cancelled.set()
                self.assertFalse(export_wfp(path, cancel=cancelled, overwrite=True)['ok'])
                self.assertEqual(old, path.read_bytes())


class MetadataAttributionTests(unittest.TestCase):
    def test_metadata_failure_does_not_invalidate_core_route_queries(self):
        def query(script, timeout):
            return ([], 'synthetic metadata denied') if BINDING_COMPONENT_QUERY in script else ([], '')
        with patch('winnetdiff.collectors.routes.ps_json', side_effect=query), patch(
                'winnetdiff.collectors.routes.run_command', return_value={'ok': True, 'stdout': ''}):
            routes = collect_routes()
        self.assertEqual(routes['query_status']['routes'], 'ok')
        self.assertEqual(routes['errors'], [])
        self.assertEqual(len(routes['metadata_errors']), 1)
        self.assertNotIn('-Recurse', BINDING_COMPONENT_QUERY)
        self.assertIn('2048', BINDING_COMPONENT_QUERY)

    def test_sdk_brand_and_installed_main_product_remain_distinct(self):
        data = {'installed_apps': [{'DisplayName': 'Avira Antivirus', 'Publisher': 'Avira'}],
                'driverquery': [{'Name': 'BdNet', 'DisplayName': 'Avira Network Filter', 'State': 'Running'}],
                'service_registry': [{'Name': 'BdNet'}], 'completeness': {'installed_apps': True, 'service_registry': True}}
        row = classify_security(data)[0]
        self.assertEqual(row['Group'], 'SharedEndpoint')
        self.assertEqual(row['Status'], 'owner_unknown')
        self.assertEqual(row['OwnerApps'], [])
        data['antivirus_products'] = [{'displayName': 'Avira Antivirus'}]
        provider = next(row for row in classify_security(data) if row['Status'] == 'provider_registered')
        self.assertEqual(provider['Group'], 'Avira')
