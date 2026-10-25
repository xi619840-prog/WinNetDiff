"""Audit regressions: raw identity safety and isolated Tk state/export behavior."""
import contextlib
import copy
from dataclasses import asdict
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from winnetdiff import cli
from winnetdiff.core import config, process
from winnetdiff.core.catalog import SIMPLIFIED_CHARACTERS
from winnetdiff.core.i18n import localized_data, set_language, tr
from winnetdiff.core.messages import Message, msg
from winnetdiff.collectors import security
from winnetdiff.gui import app
from tests.unit.test_language_cli import empty_report


class ExactTranslationSafetyTests(unittest.TestCase):
    def tearDown(self):
        set_language('en')

    def test_unknown_names_paths_and_language_list_remain_exact(self):
        samples = ['English / 简体中文 / 繁體中文', '中國移動高級網路適配器',
                   '深信服安全中心', r'D:\中文代理狀態\高級路由服務.sys',
                   '未收錄異常：低優先網路中斷', '疑似孤兒安全／VPN 元件：深信服安全中心']
        for language in config.LANGUAGES:
            for text in samples:
                with self.subTest(language=language, text=text):
                    self.assertEqual(tr(text, language), text)

    def test_parameterized_title_translates_only_template_and_survives_copy(self):
        title = msg('疑似孤兒安全／VPN 元件：{name}', name='深信服安全中心高級代理')
        expected = 'Possible orphaned security or VPN component: 深信服安全中心高級代理'
        self.assertEqual(tr(title, 'en'), expected)
        self.assertEqual(tr(copy.deepcopy(title), 'en'), expected)
        report = empty_report('en')
        report.findings[0].title = title
        copied = asdict(report)['findings'][0]['title']
        self.assertIsInstance(copied, Message)
        self.assertEqual(tr(copied, 'en'), expected)

    def test_nested_message_is_explicit_but_raw_parameter_is_never_translated(self):
        text = msg('{title}：{name}', title=msg('共用元件歸屬待核實'), name='高')
        self.assertEqual(tr(text, 'en'), 'Shared-component ownership requires review：高')

    def test_simplified_character_table_does_not_confuse_words_with_pairs(self):
        self.assertEqual('伺機而動'.translate(SIMPLIFIED_CHARACTERS), '伺机而动')
        self.assertEqual('埠'.translate(SIMPLIFIED_CHARACTERS), '埠')

    def test_recursive_localization_preserves_identity_even_when_it_equals_enum(self):
        data = {'title': '未發現明確異常', 'evidence': {'Name': '中', 'Status': '高'},
                'items': [{'Name': '中', 'Path': '低', 'title': '未發現明確異常'}]}
        translated = localized_data(data, 'en')
        self.assertEqual(translated['title'], 'No confirmed issue found')
        self.assertEqual(translated['evidence'], data['evidence'])
        self.assertEqual(translated['items'][0]['Name'], '中')
        self.assertEqual(translated['items'][0]['Path'], '低')
        self.assertEqual(translated['items'][0]['title'], 'No confirmed issue found')

    def test_config_exception_prefix_localizes_and_argument_remains_exact(self):
        with self.assertRaises(ValueError) as caught:
            config.safe_host('https://example.com:443')
        self.assertEqual(tr(caught.exception, 'en'),
                         'Enter a domain name without a URL or port: https://example.com:443')
        raw = '深信服安全中心：高級代理查詢失敗'
        self.assertEqual(tr(OSError(raw), 'en'), raw)

    def test_process_json_error_translates_authored_prefix_preserving_raw_output(self):
        raw = '深信服安全中心高級代理：不是 JSON'
        with patch.object(process, 'powershell', return_value={'ok': True, 'stdout': raw}):
            _, error = process.ps_json('synthetic query')
        self.assertTrue(error.startswith('Could not parse PowerShell JSON: '))
        self.assertTrue(error.endswith('; original output: ' + raw))

    def test_english_help_contains_static_three_language_names(self):
        output = io.StringIO()
        with patch.object(cli, 'load_settings', return_value={}), contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as caught:
                cli.main(['--lang', 'en', '--help'])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn('English / 简体中文 / 繁體中文', output.getvalue())
        self.assertNotIn('Medium文', output.getvalue())

    def test_settings_roundtrip_keeps_valid_retries_and_passive_preference_only(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(config, 'settings_path', return_value=Path(folder) / 'prefs.json'):
            config.save_settings({'language': 'zh-CN', 'profile': 'mainland', 'hosts': ['custom.example.com'],
                                  'retries': 4, 'no_network': True, 'token': 'private'})
            self.assertEqual(config.load_settings(), {'language': 'zh-CN', 'profile': 'mainland',
                             'hosts': ['custom.example.com'], 'retries': 4, 'no_network': True})

    def test_cli_exception_output_uses_common_privacy_policy(self):
        error = OSError('Authorization: Bearer synthetic-private-token\n'
                        'password="first second third"\nD:\\PrivateProject\\app.sys 王涛的电脑')
        output = io.StringIO()
        with patch.dict('os.environ', {'USERNAME': '王涛'}), \
             patch.object(cli, 'load_settings', return_value={}), \
             patch.object(cli, '_live_audit_supported', return_value=True), patch.object(cli, 'scan', side_effect=error), contextlib.redirect_stderr(output):
            self.assertEqual(cli.main(['--cli', '--lang', 'en', '--no-network']), 1)
        for secret in ['synthetic-private-token', 'first', 'second', 'third', 'PrivateProject', '王涛']:
            self.assertNotIn(secret, output.getvalue())
        self.assertIn('app.sys', output.getvalue())

    def test_security_authored_reasons_translate_without_changing_component_identity(self):
        name = '深信服安全中心高級代理'
        data = {'service_registry': [{'Name': name}], 'services_wmi': [{'Name': name, 'State': 'Running'}],
                'installed_apps': [], 'completeness': {'installed_apps': True, 'service_registry': True}}
        finding = security.security_findings(data)[0]
        for value in [finding, copy.deepcopy(finding)]:
            self.assertIn(name, tr(value.title, 'en'))
            interpretation = tr(value.interpretation, 'en')
            self.assertIn('Complete uninstall records did not include Sangfor', interpretation)
            self.assertIn('The current enumerated state is Running', interpretation)
            self.assertIn('Review signatures, product ownership', interpretation)
            self.assertFalse(any('\u4e00' <= c <= '\u9fff' for c in interpretation), interpretation)

    def test_security_static_validation_and_cancel_errors_are_localized(self):
        import threading
        set_language('en')
        with patch.object(security, 'winreg', None):
            _, errors = security.registry_services_inventory()
            self.assertEqual(errors, ['Services registry queries require Windows'])
            _, errors = security.installed_apps_inventory()
            self.assertEqual(errors, ['Application registry queries require Windows'])
        cancelled = threading.Event(); cancelled.set()
        self.assertEqual(security.inspect_security_files([], cancelled)[1], ['File-signature query cancelled'])
        self.assertEqual(security.inspect_inf_provider(r'..\secret.inf')['Error'],
                         'Only an INF filename within the local Windows INF directory is accepted')
        with self.assertRaises(ValueError) as error:
            security.parse_driverquery_csv('"one","two"')
        self.assertEqual(tr(error.exception, 'en'), 'driverquery CSV has 2 columns (at least 6 required)')


@unittest.skipUnless(sys.platform == 'win32', 'Isolated Windows Tk callback integration')
class GuiAuditSafetyTests(unittest.TestCase):
    def tearDown(self):
        set_language('en')

    def run_gui(self, exercise, expected_error=False, **options):
        import tkinter as tk
        from tkinter import messagebox

        def harness(root, *args, **kwargs):
            root.withdraw()
            try:
                exercise(root, root.winnetdiff_widgets, root.winnetdiff_state)
            finally:
                root.winnetdiff_close()

        with tempfile.TemporaryDirectory() as output, \
             patch.object(app, 'default_output_dir', return_value=Path(options.pop('_output_dir', output))), \
             patch.object(app, 'load_settings', return_value={}), patch.object(app, 'save_settings'), \
             patch.object(app, 'is_admin', return_value=False), patch.object(tk.Tk, 'mainloop', harness), \
             patch.object(messagebox, 'showerror') as errors:
            app.gui(**options)
        if expected_error:
            errors.assert_called_once()
        else:
            errors.assert_not_called()
        return errors

    def wait_worker(self, root, state):
        deadline = time.monotonic() + 3
        while state['busy'] and time.monotonic() < deadline:
            root.update()
            time.sleep(.01)
        self.assertFalse(state['busy'], 'Synthetic worker did not complete')

    def test_language_changes_keep_selected_profile_domains_and_retries(self):
        calls = []
        def scan(**kwargs):
            calls.append(kwargs)
            return empty_report(kwargs['locale'])
        def exercise(root, widgets, state):
            original = widgets['hosts_var'].get()
            widgets['language_var'].set('English')
            widgets['change_language']()
            self.assertEqual(state['profile'], 'mainland')
            self.assertEqual(widgets['hosts_var'].get(), original)
            widgets['hosts_var'].set('custom.example.com')
            widgets['language_var'].set('繁體中文')
            widgets['change_language']()
            self.assertEqual(state['profile'], 'mainland')
            self.assertEqual(widgets['hosts_var'].get(), 'custom.example.com')
            widgets['run'].invoke()
            self.wait_worker(root, state)
        with patch.object(app, 'scan', scan):
            self.run_gui(exercise, locale='zh-CN', profile='mainland', retries=4, no_network=True)
        self.assertEqual(calls[0]['retries'], 4)
        self.assertEqual(calls[0]['profile'], 'mainland')
        self.assertEqual(calls[0]['locale'], 'zh-TW')
        self.assertEqual(calls[0]['hosts'], ['custom.example.com'])
        self.assertFalse(calls[0]['do_network'])

    def test_export_uses_display_language_without_mutating_scan_report(self):
        from tkinter import filedialog, messagebox
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'report.json'
            markdown = Path(folder) / 'report.md'
            report = empty_report('zh-CN')
            report.proxy = {'SSID': 'private-wifi-987', 'DisplayVersion': '4.5.5.0',
                            'raw_columns': [r'D:\PrivateProject\private_driver.sys'],
                            'error': 'Authorization: Bearer private-bearer-987'}
            report.findings[0].evidence = json.dumps(report.proxy)
            def exercise(root, widgets, state):
                widgets['display_report'](report)
                widgets['language_var'].set('English')
                widgets['change_language']()
                widgets['export_report']('json')
                self.wait_worker(root, state)
                exported = json.loads(path.read_text(encoding='utf-8'))
                self.assertEqual(exported['locale'], 'en')
                self.assertEqual(exported['findings'][0]['title'], 'No confirmed issue found')
                widgets['export_report']('markdown')
                self.wait_worker(root, state)
                for output in [path.read_text(encoding='utf-8'), markdown.read_text(encoding='utf-8')]:
                    for private in ['private-wifi-987', 'PrivateProject', 'private-bearer-987']:
                        self.assertNotIn(private, output)
                    self.assertIn('4.5.5.0', output)
                    self.assertIn('private_driver.sys', output)
                    self.assertIn('No confirmed issue found', output)
                self.assertEqual(report.locale, 'zh-CN')
            with patch.object(filedialog, 'asksaveasfilename', side_effect=[str(path), str(markdown)]), \
                 patch.object(messagebox, 'askyesno', return_value=False):
                self.run_gui(exercise, locale='zh-CN')

    def test_manual_guidance_preview_uses_current_language_without_mutating_scan(self):
        import tkinter as tk
        from tkinter import messagebox
        original_toplevel = tk.Toplevel
        def hidden_toplevel(*args, **kwargs):
            window = original_toplevel(*args, **kwargs)
            window.withdraw()
            return window
        report = empty_report('zh-CN')
        def exercise(root, widgets, state):
            widgets['display_report'](report)
            widgets['language_var'].set('English')
            widgets['change_language']()
            widgets['request_guidance']()
            self.assertEqual(report.locale, 'zh-CN')
        with patch.object(messagebox, 'askyesno', return_value=True), \
             patch.object(tk, 'Toplevel', side_effect=hidden_toplevel), \
             patch.object(app, 'repair_text', return_value='Synthetic manual guidance') as preview:
            self.run_gui(exercise, locale='zh-CN')
        self.assertEqual(preview.call_args.args[0].locale, 'en')

    def test_gui_worker_error_dialog_and_status_redact_secrets_and_private_path(self):
        from tkinter import filedialog, messagebox
        error = OSError('Authorization: Bearer gui-private-token\n'
                        'password="private words secret"\nD:\\PrivateProject\\driver.sys 王涛的电脑')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'snapshot.json'
            def exercise(root, widgets, state):
                widgets['display_report'](empty_report('en'))
                widgets['request_snapshot_save']()
                self.wait_worker(root, state)
                for private in ['gui-private-token', 'private words', 'words', 'PrivateProject', '王涛']:
                    self.assertNotIn(private, widgets['status_var'].get())
            with patch.dict('os.environ', {'USERNAME': '王涛'}), \
                 patch.object(filedialog, 'asksaveasfilename', return_value=str(path)), \
                 patch.object(messagebox, 'askyesno', return_value=False), \
                 patch.object(app, 'save_snapshot', side_effect=error):
                errors = self.run_gui(exercise, expected_error=True)
        detail = errors.call_args.args[1]
        for private in ['gui-private-token', 'words', 'PrivateProject', '王涛']:
            self.assertNotIn(private, detail)
        self.assertIn('driver.sys', detail)

    def test_snapshot_and_wfp_overwrite_require_explicit_yes_and_preserve_cancelled_file(self):
        from tkinter import filedialog, messagebox
        for kind in ['snapshot', 'wfp']:
            for confirmed in [False, True]:
                with self.subTest(kind=kind, confirmed=confirmed), tempfile.TemporaryDirectory() as folder:
                    path = Path(folder) / ('existing.json' if kind == 'snapshot' else 'existing.xml')
                    path.write_text('original', encoding='utf-8')
                    def exercise(root, widgets, state):
                        widgets['display_report'](empty_report('en'))
                        widgets['request_snapshot_save' if kind == 'snapshot' else 'request_wfp']()
                        if confirmed:
                            self.wait_worker(root, state)
                    # Ordinary snapshots now redact without a full-data prompt.
                    # WFP uses the separate acknowledged raw-evidence dialog.
                    with patch.object(filedialog, 'asksaveasfilename', return_value=str(path)), \
                         patch.object(app, 'confirm_full_export', return_value='wfp') as full_consent, \
                         patch.object(messagebox, 'askyesno', side_effect=[confirmed]) as consent, \
                         patch.object(app, 'save_snapshot') as snapshot, \
                         patch.object(app, 'export_wfp', return_value={'ok': True}) as wfp:
                        self.run_gui(exercise)
                    operation = snapshot if kind == 'snapshot' else wfp
                    self.assertEqual(consent.call_count, 1)
                    if kind == 'wfp':
                        full_consent.assert_called_once()
                        self.assertIs(full_consent.call_args.kwargs['wfp'],True)
                    else:
                        full_consent.assert_not_called()
                    if confirmed:
                        operation.assert_called_once()
                        self.assertIs(operation.call_args.kwargs['overwrite'], True)
                    else:
                        operation.assert_not_called()
                    self.assertEqual(path.read_text(encoding='utf-8'), 'original')

    def test_uac_captures_current_parameters_and_persists_before_dispatch(self):
        from tkinter import messagebox
        events, launches = [], []
        def save(data):
            events.append(('saved', data))
        def elevate(**kwargs):
            events.append(('launched', None))
            launches.append(kwargs)
            return {'ok': False, 'cancelled': True}
        def exercise(root, widgets, state):
            widgets['hosts_var'].set('custom.example.com')
            widgets['language_var'].set('繁體中文')
            widgets['change_language']()
            widgets['passive_var'].set(True)
            events.clear()
            with patch.object(app, 'save_settings', side_effect=save):
                widgets['request_elevation']()
                self.wait_worker(root, state)
            self.assertEqual([event[0] for event in events], ['saved', 'launched'])
            self.assertIn('已取消 UAC', widgets['status_var'].get())
        with patch.object(messagebox, 'askyesno', return_value=True), \
             patch.object(app, 'relaunch_as_admin', side_effect=elevate), \
             patch.object(app, 'default_output_dir', return_value=Path(r'D:\中文 folder\WinNetDiff results')):
            self.run_gui(exercise, locale='zh-CN', profile='mainland', retries=3,
                         _output_dir=Path(r'D:\中文 folder\WinNetDiff results'))
        argv = launches[0]['argv']
        self.assertEqual(argv, ['--lang', 'zh-TW', '--profile', 'mainland', '--hosts', 'custom.example.com',
                               '--retries', '3', '--output-dir', r'D:\中文 folder\WinNetDiff results', '--fake-ip-audit', '--retry-mode', 'same-ip', '--no-network'])
        self.assertGreater(launches[0]['hwnd'], 0)
        self.assertEqual(events[0][1]['retries'], 3)
        self.assertTrue(events[0][1]['no_network'])
        self.assertTrue(events[0][1]['fake_ip_audit'])
        self.assertEqual(events[0][1]['retry_mode'], 'same-ip')


if __name__ == '__main__':
    unittest.main()
