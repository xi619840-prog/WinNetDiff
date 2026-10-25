import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from winnetdiff import cli
from winnetdiff.core import config
from winnetdiff.core.i18n import set_language, tr
from winnetdiff.core.models import Finding, Report
from winnetdiff.reports.export import evidence_text, redacted_data, redact, summarize
from winnetdiff.repairs.manager import RepairManager


def empty_report(language='en'):
    return Report('2.1.0b1', '2026-10-24', 'Synthetic Windows', False, ['example.com'], {}, {}, [], {},
                  [Finding('資訊', '代理', '未發現明確異常', '{}', '本輪可用證據未觸發規則')], [], locale=language)


class LanguageCliTests(unittest.TestCase):
    def setUp(self):
        override = patch.object(cli, '_live_audit_supported', return_value=True)
        override.start()
        self.addCleanup(override.stop)

    def tearDown(self):
        set_language('en')

    def test_three_languages_use_distinct_configurable_target_defaults(self):
        defaults = [tuple(config.resolve_targets(language)) for language in config.LANGUAGES]
        self.assertEqual(len(set(defaults)), 3)
        for language in config.LANGUAGES:
            self.assertEqual(config.resolve_targets(language, 'global'), list(defaults[0]))

    def test_custom_targets_override_language_and_profile(self):
        for language in config.LANGUAGES:
            self.assertEqual(config.resolve_targets(language, 'mainland', 'one.example.com,two.example.com'),
                             ['one.example.com', 'two.example.com'])

    def test_settings_roundtrip_only_allows_public_preferences(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(config, 'settings_path', return_value=Path(folder) / 'settings.json'):
            config.save_settings({'language': 'zh-TW', 'hosts': ['example.com'], 'mode': 'expert', 'token': 'do-not-save'})
            data = config.load_settings()
            self.assertEqual(data['language'], 'zh-TW')
            self.assertNotIn('token', data)

    def test_invalid_settings_do_not_execute_or_break_startup(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'settings.json'
            path.write_text('{broken JSON', encoding='utf-8')
            with patch.object(config, 'settings_path', return_value=path):
                self.assertEqual(config.load_settings(), {})

    def test_cli_language_default_and_explicit_target_contract(self):
        for language in config.LANGUAGES:
            output = io.StringIO()
            with patch.object(cli, 'load_settings', return_value={}), patch.object(cli, 'scan', return_value=empty_report(language)) as scan, contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(['--cli', '--lang', language, '--no-network']), 0)
            self.assertEqual(scan.call_args.args[0], config.resolve_targets(language))
            self.assertFalse(scan.call_args.args[1])
            self.assertEqual(scan.call_args.kwargs['locale'], language)

    def test_cli_custom_target_and_profile_are_independent_of_language(self):
        with patch.object(cli, 'load_settings', return_value={}), patch.object(cli, 'scan', return_value=empty_report('zh-TW')) as scan, contextlib.redirect_stdout(io.StringIO()):
            cli.main(['--cli', '--lang', 'zh-TW', '--profile', 'mainland', '--hosts', 'custom.example.com'])
        self.assertEqual(scan.call_args.args[0], ['custom.example.com'])
        self.assertEqual(scan.call_args.kwargs['profile'], 'mainland')

    def test_reports_translate_explanations_without_changing_raw_evidence(self):
        for language, expected in [('en', 'No confirmed issue found'), ('zh-CN', '未发现明确异常'), ('zh-TW', '未發現明確異常')]:
            report = empty_report(language)
            report.findings[0].evidence = '原始系統證據'
            exported = json.loads(evidence_text(report))
            self.assertEqual(exported['findings'][0]['title'], expected)
            self.assertEqual(exported['findings'][0]['evidence'], '原始系統證據')

    def test_tokens_and_device_identifiers_are_redacted_by_default(self):
        result = redacted_data({'token': 'token-value', 'api_key': 'key-value', 'InterfaceGuid': 'synthetic-device-123'})
        text = json.dumps(result)
        for value in ['token-value', 'key-value', 'synthetic-device-123']:
            self.assertNotIn(value, text)
        self.assertNotIn('test-secret-value', redact('API_KEY=test-secret-value'))

    def test_irreversible_dns_clear_is_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as folder, patch('winnetdiff.repairs.manager.run_command') as execute:
            with self.assertRaisesRegex(RuntimeError, 'cannot be faithfully rolled back'):
                RepairManager(Path(folder)).flush_dns(confirmed=True)
            execute.assert_not_called()

    def test_same_host_one_attempt_per_family_is_not_repeated_path_evidence(self):
        import windows_net_diffdiag as app
        probes = [app.Probe(host, family, stage='tls_timeout', tcp_ms=2)
                  for host in ['first.example.com', 'second.example.com'] for family in ['IPv4', 'IPv6']]
        findings = app.analyze({}, {'defaults_ipv4': [{'Gateway': '192.0.2.1'}]}, probes,
                               {'evidence': [{'Name': 'SyntheticFilter', 'Status': 'orphan_candidate'}]})
        self.assertFalse(any(f.priority == 0 for f in findings))


if __name__ == '__main__':
    unittest.main()
