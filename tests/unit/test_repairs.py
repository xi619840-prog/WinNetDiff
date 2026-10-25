import base64
import copy
import json
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import windows_net_diffdiag as app


def dead_proxy():
    return {'wininet': {'ProxyEnable': 1, 'ProxyServer': 'http=127.0.0.1:7890;https=127.0.0.1:7890',
                        'AutoConfigURL': None},
            'effective_scope': 'HKCU', 'errors': [], 'policy': {}, 'policy_user': {},
            'wininet_api': {'flags': 3},
            'local_listeners': [{'host': '127.0.0.1', 'port': 7890, 'confirmed_dead': True}]}


def snapshot(enabled):
    return {app.INET_PATH: {'ProxyEnable': {'exists': True, 'type': 4, 'value': int(enabled)},
                            'ProxyServer': {'exists': True, 'type': 1, 'value': 'http=127.0.0.1:7890;https=127.0.0.1:7890'}},
            app.INET_PATH + r'\Connections': {
                'DefaultConnectionSettings': {'exists': True, 'type': 3,
                                               'value': {'base64': base64.b64encode(b'\x00\xffbefore' if enabled else b'\x00\xffafter').decode('ascii')}},
                'SavedLegacySettings': {'exists': False, 'type': None, 'value': None}},
            'flags': 3 if enabled else 1}


class RepairEligibilityTests(unittest.TestCase):
    def test_confirmed_dead_proxy_eligible(self):
        self.assertTrue(app.proxy_repair_eligibility(dead_proxy())['eligible'])

    def test_disabled_proxy_needs_no_change(self):
        proxy = dead_proxy()
        proxy['wininet']['ProxyEnable'] = 0
        self.assertFalse(app.proxy_repair_eligibility(proxy)['eligible'])

    def test_listener_timeout_or_success_refuses_repair(self):
        for extra in ({'confirmed_dead': False}, {'confirmed_dead': False, 'accepts_tcp': True}):
            proxy = dead_proxy()
            proxy['local_listeners'][0].update(extra)
            self.assertFalse(app.proxy_repair_eligibility(proxy)['eligible'])

    def test_machine_scope_or_query_error_refuses_repair(self):
        for extra in ({'effective_scope': 'HKLM'}, {'errors': ['Access denied']}, {'policy': {'error': 'denied'}}):
            proxy = dead_proxy()
            proxy.update(extra)
            self.assertFalse(app.proxy_repair_eligibility(proxy)['eligible'])

    def test_remote_entry_or_pac_refuses_repair(self):
        proxy = dead_proxy()
        proxy['wininet']['ProxyServer'] += ';https=remote.example.com:8080'
        self.assertFalse(app.proxy_repair_eligibility(proxy)['eligible'])
        proxy = dead_proxy()
        proxy['wininet']['AutoConfigURL'] = 'https://example.com/proxy.pac'
        self.assertFalse(app.proxy_repair_eligibility(proxy)['eligible'])


class RepairManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = app.RepairManager(Path(self.temp.name))
        self.proxy = dead_proxy()
        self.report = types.SimpleNamespace(proxy=self.proxy)
        self.before, self.after = snapshot(True), snapshot(False)
        self.private = patch.object(app, 'private_storage').start()
        self.sid = patch.object(app, 'current_sid', return_value='S-1-5-21-123').start()
        self.addCleanup(patch.stopall)

    def test_confirmation_required(self):
        with patch.object(app, 'collect_proxy') as collect:
            with self.assertRaises(ValueError):
                self.manager.disable_proxy(self.report)
        self.assertFalse(collect.called)

    def test_disabled_noop_is_idempotent(self):
        disabled = copy.deepcopy(self.proxy)
        disabled['wininet']['ProxyEnable'] = 0
        with patch.object(app, 'collect_proxy', return_value=disabled), patch.object(app, 'set_wininet_flags') as setter:
            first = self.manager.disable_proxy(self.report, confirmed=True)
            second = self.manager.disable_proxy(self.report, confirmed=True)
        self.assertFalse(first['changed'])
        self.assertFalse(second['changed'])
        self.assertFalse(setter.called)
        self.assertEqual([], list(Path(self.temp.name).glob('proxy_*.json')))

    def test_backup_durable_before_change_and_verified_restore(self):
        def check_backup_before_change(flags):
            backups = list(Path(self.temp.name).glob('proxy_*.json'))
            self.assertEqual(1, len(backups))
            data = json.loads(backups[0].read_text(encoding='utf-8'))
            self.assertEqual('prepared', data['phase'])
            self.assertEqual(self.before, data['before'])
            self.assertEqual(1, flags)
            self.assertEqual('prepared', self.manager.history()[-1]['phase'])

        with patch.object(app, 'collect_proxy', return_value=self.proxy), patch.object(app, 'proxy_snapshot', side_effect=[self.before, self.after]), patch.object(
                app, 'set_wininet_flags', side_effect=check_backup_before_change):
            applied = self.manager.disable_proxy(self.report, confirmed=True)
        backup_path = Path(applied['backup'])
        data = json.loads(backup_path.read_text(encoding='utf-8'))
        self.assertEqual('verified', data['phase'])
        self.assertEqual(['prepared', 'applied', 'verified'], [row['phase'] for row in self.manager.history()])
        self.assertEqual(self.after, data['after'])
        with patch.object(app, 'proxy_snapshot', side_effect=[self.after, self.before]), patch.object(app, 'restore_proxy_snapshot') as restore:
            restored = self.manager.restore_proxy(backup_path, confirmed=True)
        restore.assert_called_once_with(self.before)
        self.assertTrue(restored['ok'])
        self.assertTrue(restored['changed'])

    def test_failed_mutation_rolls_back_and_records_result(self):
        with patch.object(app, 'collect_proxy', return_value=self.proxy), patch.object(app, 'proxy_snapshot', side_effect=[self.before, self.before, self.before]), patch.object(
                app, 'set_wininet_flags', side_effect=OSError('notification failed')), patch.object(app, 'restore_proxy_snapshot') as restore:
            with self.assertRaisesRegex(RuntimeError, 'True'):
                self.manager.disable_proxy(self.report, confirmed=True)
        restore.assert_called_once_with(self.before)
        last = self.manager.history()[-1]
        self.assertFalse(last['ok'])
        self.assertTrue(last['rollback_verified'])
        self.assertEqual('restored', json.loads(Path(last['backup']).read_text(encoding='utf-8'))['phase'])

    def test_verification_failure_triggers_rollback(self):
        with patch.object(app, 'collect_proxy', return_value=self.proxy), patch.object(app, 'proxy_snapshot', side_effect=[self.before, self.before, self.before]), patch.object(
                app, 'set_wininet_flags'), patch.object(app, 'restore_proxy_snapshot') as restore:
            with self.assertRaises(RuntimeError):
                self.manager.disable_proxy(self.report, confirmed=True)
        restore.assert_called_once_with(self.before)

    def test_stale_report_refuses_mutation(self):
        fresh = copy.deepcopy(self.proxy)
        fresh['wininet']['ProxyOverride'] = '<local>'
        with patch.object(app, 'collect_proxy', return_value=fresh), patch.object(app, 'set_wininet_flags') as setter:
            with self.assertRaisesRegex(RuntimeError, '設定已變更'):
                self.manager.disable_proxy(self.report, confirmed=True)
        self.assertFalse(setter.called)

    def test_backup_write_failure_prevents_mutation(self):
        with patch.object(app, 'collect_proxy', return_value=self.proxy), patch.object(app, 'proxy_snapshot', return_value=self.before), patch.object(
                app, 'atomic_json', side_effect=OSError('disk full')), patch.object(app, 'set_wininet_flags') as setter:
            with self.assertRaises(OSError):
                self.manager.disable_proxy(self.report, confirmed=True)
        self.assertFalse(setter.called)

    def make_backup(self):
        path = Path(self.temp.name) / 'proxy_backup.json'
        app.atomic_json(path, {'schema': 2, 'kind': 'wininet_proxy', 'sid': 'S-1-5-21-123',
                              'machine': app.platform.node(), 'before': self.before, 'after': self.after})
        return path

    def test_restore_conflict_refuses_to_overwrite_new_config(self):
        path = self.make_backup()
        conflict = copy.deepcopy(self.after)
        conflict[app.INET_PATH]['ProxyServer']['value'] = '127.0.0.1:9999'
        with patch.object(app, 'proxy_snapshot', return_value=conflict), patch.object(app, 'restore_proxy_snapshot') as restore:
            with self.assertRaisesRegex(RuntimeError, '設定已不同'):
                self.manager.restore_proxy(path, confirmed=True)
        self.assertFalse(restore.called)

    def test_restore_already_original_is_noop(self):
        path = self.make_backup()
        with patch.object(app, 'proxy_snapshot', return_value=self.before), patch.object(app, 'restore_proxy_snapshot') as restore:
            result = self.manager.restore_proxy(path, confirmed=True)
        self.assertTrue(result['ok'])
        self.assertFalse(result['changed'])
        self.assertFalse(restore.called)

    def test_restore_wrong_user_refused(self):
        path = self.make_backup()
        self.sid.return_value = 'S-1-5-21-999'
        with patch.object(app, 'restore_proxy_snapshot') as restore:
            with self.assertRaisesRegex(RuntimeError, '使用者不符'):
                self.manager.restore_proxy(path, confirmed=True)
        self.assertFalse(restore.called)

    def test_restore_failure_recovers_and_journals_terminal_state(self):
        path = self.make_backup()
        with patch.object(app, 'proxy_snapshot', side_effect=[self.after, self.after, self.after]), patch.object(
                app, 'restore_proxy_snapshot', side_effect=[OSError('registry write failed'), None]) as restore:
            with self.assertRaisesRegex(RuntimeError, 'True'):
                self.manager.restore_proxy(path, confirmed=True)
        self.assertEqual(2, restore.call_count)
        self.assertEqual(self.after, restore.call_args.args[0])
        history = self.manager.history()
        self.assertEqual('restore_started', history[-2]['phase'])
        self.assertEqual('rollback_failed', history[-1]['phase'])
        self.assertFalse(history[-1]['ok'])
        self.assertTrue(history[-1]['rollback_verified'])
        self.assertFalse(history[-1]['changed'])
        self.assertIn('registry write failed', history[-1]['error'])

    def test_restore_failure_and_recovery_failure_journals_required_action(self):
        path = self.make_backup()
        with patch.object(app, 'proxy_snapshot', return_value=self.after), patch.object(
                app, 'restore_proxy_snapshot', side_effect=[OSError('restore failed'), OSError('recovery failed')]):
            with self.assertRaisesRegex(RuntimeError, 'False'):
                self.manager.restore_proxy(path, confirmed=True)
        last = self.manager.history()[-1]
        self.assertEqual('rollback_failed', last['phase'])
        self.assertTrue(last['changed'])
        self.assertFalse(last['rollback_verified'])
        self.assertIn('recovery failed', last['after']['query_error'])
        self.assertEqual(str(path), last['backup'])

    def test_restore_verification_failure_recovers_and_journals(self):
        path = self.make_backup()
        wrong = copy.deepcopy(self.before)
        wrong['flags'] = 0
        with patch.object(app, 'proxy_snapshot', side_effect=[self.after, wrong, self.after]), patch.object(
                app, 'restore_proxy_snapshot') as restore:
            with self.assertRaisesRegex(RuntimeError, '驗證失敗'):
                self.manager.restore_proxy(path, confirmed=True)
        self.assertEqual(2, restore.call_count)
        last = self.manager.history()[-1]
        self.assertEqual('rollback_failed', last['phase'])
        self.assertTrue(last['rollback_verified'])


class WindowsApiTests(unittest.TestCase):
    def acl_libraries(self):
        advapi, kernel = MagicMock(), MagicMock()
        def convert(sddl, revision, output, length):
            output._obj.value = 0x1234
            return 1
        def get_dacl(descriptor, present, acl, defaulted):
            present._obj.value = 1
            acl._obj.value = 0x5678
            defaulted._obj.value = 0
            return 1
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.side_effect = convert
        advapi.GetSecurityDescriptorDacl.side_effect = get_dacl
        advapi.SetNamedSecurityInfoW.return_value = 0
        return advapi, kernel

    @unittest.skipUnless(app.os.name == 'nt', 'Windows ACL API mock')
    def test_protected_acl_uses_single_named_security_update_and_frees_descriptor(self):
        advapi, kernel = self.acl_libraries()
        path = Path(r'C:\測試 報告\備份')
        with patch.object(app.ctypes, 'WinDLL', side_effect=[advapi, kernel]):
            app.protect_directory(path, 'S-1-5-21-123')
        sddl = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.call_args.args[0]
        self.assertEqual('D:P(A;OICI;FA;;;S-1-5-21-123)(A;OICI;FA;;;SY)', sddl)
        args = advapi.SetNamedSecurityInfoW.call_args.args
        self.assertEqual(str(path), args[0])
        self.assertEqual(1, args[1])
        self.assertEqual(0x80000004, args[2])
        self.assertEqual(0x5678, args[5].value)
        kernel.LocalFree.assert_called_once()
        self.assertEqual(0x1234, kernel.LocalFree.call_args.args[0].value)

    @unittest.skipUnless(app.os.name == 'nt', 'Windows ACL API mock')
    def test_acl_application_failure_frees_descriptor(self):
        advapi, kernel = self.acl_libraries()
        advapi.SetNamedSecurityInfoW.return_value = 5
        with patch.object(app.ctypes, 'WinDLL', side_effect=[advapi, kernel]):
            with self.assertRaises(OSError):
                app.protect_directory(Path(r'C:\測試\備份'), 'S-1-5-21-123')
        kernel.LocalFree.assert_called_once()

    @unittest.skipUnless(app.os.name == 'nt', 'Windows ACL API mock')
    def test_empty_dacl_refused_without_applying(self):
        advapi, kernel = self.acl_libraries()
        advapi.GetSecurityDescriptorDacl.side_effect = lambda *args: 1
        with patch.object(app.ctypes, 'WinDLL', side_effect=[advapi, kernel]):
            with self.assertRaisesRegex(RuntimeError, '空白 DACL'):
                app.protect_directory(Path(r'C:\測試\備份'), 'S-1-5-21-123')
        self.assertFalse(advapi.SetNamedSecurityInfoW.called)
        kernel.LocalFree.assert_called_once()

    def test_script_elevation_preserves_unicode_spaces_and_args(self):
        script = str(Path(r'C:\工具 程式\網路診斷.py').resolve())
        args = ['--json', r'C:\使用者\報告 結果.json', '--hosts', 'example.com']
        with patch.object(app, '__file__', script), patch.object(app.sys, 'executable', r'C:\Python 安裝\python.exe'), patch.object(app.sys, 'frozen', False, create=True):
            executable, parameters = app.elevation_command(args)
        self.assertEqual(r'C:\Python 安裝\python.exe', executable)
        self.assertEqual(subprocess.list2cmdline([script] + args), parameters)

    def test_frozen_elevation_omits_script_argument(self):
        args = ['--json', r'C:\使用者\報告 結果.json']
        with patch.object(app.sys, 'executable', r'C:\診斷 程式\診斷.exe'), patch.object(app.sys, 'frozen', True, create=True):
            executable, parameters = app.elevation_command(args)
        self.assertEqual(r'C:\診斷 程式\診斷.exe', executable)
        self.assertEqual(subprocess.list2cmdline(args), parameters)

    @unittest.skipUnless(app.os.name == 'nt', 'Windows ctypes API mock')
    def test_uac_cancelled_is_not_success(self):
        shell = MagicMock()
        shell.ShellExecuteW.return_value = 5
        with patch.object(app.ctypes, 'WinDLL', return_value=shell), patch.object(app.ctypes, 'get_last_error', return_value=1223):
            result = app.relaunch_as_admin(['--cli'])
        self.assertFalse(result['ok'])
        self.assertTrue(result['cancelled'])
        self.assertEqual('runas', shell.ShellExecuteW.call_args.args[1])

    @unittest.skipUnless(app.os.name == 'nt', 'Windows UAC API mock')
    def test_frozen_uac_uses_executable_folder_not_extraction_folder(self):
        shell = MagicMock()
        shell.ShellExecuteW.return_value = 33
        executable = str(Path(r'C:\安裝 程式\網路診斷.exe').resolve())
        extraction = str(Path(r'C:\Temp\_MEI12345\windows_net_diffdiag.py').resolve())
        with patch.object(app.ctypes, 'WinDLL', return_value=shell), patch.object(app.ctypes, 'get_last_error', return_value=0), patch.object(
                app.sys, 'frozen', True, create=True), patch.object(app.sys, 'executable', executable), patch.object(app, '__file__', extraction):
            result = app.relaunch_as_admin(['--cli'])
        self.assertTrue(result['ok'])
        self.assertEqual(str(Path(executable).parent), shell.ShellExecuteW.call_args.args[4])

    @unittest.skipUnless(app.os.name == 'nt', 'Windows ACL command mock')
    def test_private_storage_failure_stops_repair(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'current_token_sid', return_value='S-1-5-21-123'), patch.object(
                app, 'protect_directory', side_effect=OSError('Access denied')):
            with self.assertRaisesRegex(RuntimeError, '權限設定失敗'):
                app.private_storage(Path(directory))

    def test_binary_registry_value_round_trip(self):
        value = bytes(range(256))
        self.assertEqual(value, app._unpacked_value(app._packed_value(value)))

    def test_snapshot_restore_uses_supported_api_and_never_writes_archived_blobs(self):
        events = []
        registry = MagicMock()
        library = MagicMock()
        def set_option(handle, code, pointer, size):
            self.assertIsNone(handle)
            self.assertEqual(75, code)
            options = pointer._obj
            self.assertIsNone(options.pszConnection)
            self.assertEqual(4, options.dwOptionCount)
            actual = {options.pOptions[i].dwOption:
                      options.pOptions[i].Value.dwValue if i == 0 else
                      app.ctypes.wstring_at(options.pOptions[i].Value.pszValue)
                      for i in range(4)}
            events.append(('options', actual))
            return 1
        library.InternetSetOptionW.side_effect = set_option
        with patch.object(app, 'winreg', registry), patch.object(app.ctypes, 'WinDLL', return_value=library, create=True), patch.object(
                app, 'notify_wininet', side_effect=lambda: events.append(('notify',))):
            app.restore_proxy_snapshot(snapshot(True))
        self.assertEqual(('options', {1: 3, 2: 'http=127.0.0.1:7890;https=127.0.0.1:7890', 3: '', 4: ''}), events[0])
        self.assertEqual(('notify',), events[-1])
        registry.OpenKey.assert_not_called()
        registry.SetValueEx.assert_not_called()
        registry.DeleteValue.assert_not_called()
        library.InternetSetOptionW.assert_called_once()


if __name__ == '__main__':
    unittest.main()
