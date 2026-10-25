"""Proxy transaction regressions; every settings mutation is mocked."""
import copy
import ctypes
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from winnetdiff.core import windows
from winnetdiff.repairs import manager as app


SERVER = '127.0.0.1:7890'


def state(enabled, counter=1):
    values = {'ProxyEnable': int(enabled), 'ProxyServer': SERVER,
              'ProxyOverride': '<local>', 'AutoConfigURL': '', 'AutoDetect': 1}
    return {app.INET_PATH: {key: {'exists': True, 'type': 4 if isinstance(value, int) else 1,
                                'value': value} for key, value in values.items()},
            app.INET_PATH + r'\Connections': {
                'DefaultConnectionSettings': {'exists': True, 'type': 3,
                                               'value': app._packed_value(bytes([70, 0, 0, 0, counter]))}},
            'flags': 11 if enabled else 9,
            'api': {'flags': 11 if enabled else 9, 'ProxyServer': SERVER,
                    'ProxyOverride': '<local>', 'AutoConfigURL': ''}, 'policy': {}}


def evidence():
    return {'wininet': {'ProxyEnable': 1, 'ProxyServer': SERVER, 'ProxyOverride': '<local>',
                        'AutoConfigURL': '', 'AutoDetect': 1},
            'wininet_api': {'flags': 11, 'ProxyServer': SERVER,
                            'ProxyOverride': '<local>', 'AutoConfigURL': ''},
            'errors': [], 'effective_scope': 'HKCU', 'policy': {}, 'policy_user': {},
            'applicable_policy': {},
            'local_listeners': [{'host': '127.0.0.1', 'port': 7890, 'confirmed_dead': True}]}


class SemanticRestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = app.RepairManager(Path(self.temp.name))
        self.before, self.after = state(True), state(False, 2)
        self.backup_path = Path(self.temp.name) / 'proxy_backup.json'
        self.backup = {'schema': 2, 'kind': 'wininet_proxy', 'sid': 'S-1-5-21-123',
                       'machine': 'synthetic', 'before': self.before, 'after': self.after,
                       'phase': 'verified'}
        app.atomic_json(self.backup_path, self.backup)
        for patcher in (patch.object(app, 'current_sid', return_value='S-1-5-21-123'),
                        patch.object(app.platform, 'node', return_value='synthetic'),
                        patch.object(app, 'private_storage')):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_restore_executes_despite_blob_counter_and_savedlegacy_changes(self):
        current = state(False, 71)
        current[app.INET_PATH + r'\Connections']['SavedLegacySettings'] = {'arbitrary': 'archival drift'}
        with patch.object(app, 'proxy_snapshot', side_effect=[current, state(True, 99)]), patch.object(
                app, 'restore_proxy_snapshot') as actual_restore:
            result = self.manager.restore_proxy(self.backup_path, confirmed=True)
        actual_restore.assert_called_once_with(self.before)
        self.assertTrue(result['ok'])
        self.assertTrue(result['changed'])
        self.assertEqual(['restore_started', 'restored'], [x['phase'] for x in self.manager.history()])
        self.assertEqual('restored', json.loads(self.backup_path.read_text(encoding='utf-8'))['phase'])

    def test_server_pac_bypass_autodetect_and_policy_external_changes_refused(self):
        for key, value in [('ProxyServer', '127.0.0.1:9999'),
                           ('AutoConfigURL', 'https://new.example/proxy.pac'),
                           ('ProxyOverride', '*.new.example'), ('AutoDetect', 0), ('policy', 0)]:
            with self.subTest(key=key):
                current = copy.deepcopy(self.after)
                if key == 'policy':
                    current['policy'] = {'HKLM\\policy': {'values': {'ProxySettingsPerUser': value}}}
                else:
                    current[app.INET_PATH][key]['value'] = value
                with patch.object(app, 'proxy_snapshot', return_value=current), patch.object(
                        app, 'restore_proxy_snapshot') as actual_restore:
                    with self.assertRaisesRegex(RuntimeError, '設定已不同'):
                        self.manager.restore_proxy(self.backup_path, confirmed=True)
                actual_restore.assert_not_called()

    def test_api_only_server_or_flags_change_refused(self):
        for key, value in [('ProxyServer', '127.0.0.1:9999'), ('flags', 1)]:
            current = copy.deepcopy(self.after)
            if key == 'flags':
                current['flags'] = value
            else:
                current['api'][key] = value
            with self.subTest(key=key), patch.object(app, 'proxy_snapshot', return_value=current), patch.object(
                    app, 'restore_proxy_snapshot') as actual_restore:
                with self.assertRaises(RuntimeError):
                    self.manager.restore_proxy(self.backup_path, confirmed=True)
                actual_restore.assert_not_called()

    def test_policy_read_error_never_treated_as_empty_policy(self):
        current = copy.deepcopy(self.after)
        current['policy'] = {'HKCU\\policy': {'error': 'Access denied', 'values': {}}}
        with patch.object(app, 'proxy_snapshot', return_value=current), patch.object(app, 'restore_proxy_snapshot') as restore:
            with self.assertRaisesRegex(RuntimeError, '原則查詢'):
                self.manager.restore_proxy(self.backup_path, confirmed=True)
        restore.assert_not_called()

    def test_interrupted_prepared_transaction_recovers_only_expected_semantics(self):
        self.backup.update(after=None, expected_after=self.after, phase='prepared')
        app.atomic_json(self.backup_path, self.backup)
        with patch.object(app, 'proxy_snapshot', side_effect=[state(False, 8), state(True, 9)]), patch.object(
                app, 'restore_proxy_snapshot') as restore:
            result = self.manager.restore_proxy(self.backup_path, confirmed=True)
        self.assertTrue(result['ok'])
        restore.assert_called_once_with(self.before)

    def test_restore_retry_after_write_before_terminal_journal_is_idempotent(self):
        self.backup['phase'] = 'restore_started'
        app.atomic_json(self.backup_path, self.backup)
        with patch.object(app, 'proxy_snapshot', return_value=state(True, 91)), patch.object(
                app, 'restore_proxy_snapshot') as restore:
            first = self.manager.restore_proxy(self.backup_path, confirmed=True)
            second = self.manager.restore_proxy(self.backup_path, confirmed=True)
        self.assertTrue(first['ok'])
        self.assertFalse(first['changed'])
        self.assertFalse(second['changed'])
        restore.assert_not_called()

    def test_restore_intent_write_failure_prevents_any_setting_write(self):
        with patch.object(app, 'proxy_snapshot', return_value=self.after), patch.object(
                app, 'atomic_json', side_effect=OSError('restore intent disk full')), patch.object(
                app, 'restore_proxy_snapshot') as restore:
            with self.assertRaisesRegex(OSError, 'restore intent disk full'):
                self.manager.restore_proxy(self.backup_path, confirmed=True)
        restore.assert_not_called()

    def test_failed_restore_refuses_recovery_over_external_pac_change(self):
        changed = copy.deepcopy(self.after)
        changed['api']['AutoConfigURL'] = 'https://external.example/new.pac'
        with patch.object(app, 'proxy_snapshot', side_effect=[self.after, changed]), patch.object(
                app, 'restore_proxy_snapshot', side_effect=OSError('setting call failed')) as restore:
            with self.assertRaisesRegex(RuntimeError, 'False'):
                self.manager.restore_proxy(self.backup_path, confirmed=True)
        restore.assert_called_once_with(self.before)
        record = self.manager.history()[-1]
        self.assertFalse(record['rollback_verified'])
        self.assertEqual('rollback_failed', record['phase'])
        self.assertIn('外部變更', record['after']['query_error'])

    def test_atomic_history_replace_failure_preserves_existing_file_and_cleans_temp(self):
        target = Path(self.temp.name) / 'atomic_history.json'
        target.write_text('[{"original":true}]', encoding='utf-8')
        with patch.object(app.os, 'replace', side_effect=OSError('replace denied')):
            with self.assertRaisesRegex(OSError, 'replace denied'):
                app.atomic_json(target, [{'new': True}])
        self.assertEqual([{'original': True}], json.loads(target.read_text(encoding='utf-8')))
        self.assertEqual([], list(target.parent.glob('atomic_history.json.*.tmp')))

    def test_last_backup_skips_unverified_failed_and_consumed_records(self):
        good_path = Path(self.temp.name) / 'good.json'
        app.atomic_json(good_path, self.backup)
        records = [{'operation': 'disable_proxy', 'ok': True, 'changed': True, 'phase': 'verified', 'backup': str(good_path)},
                   {'operation': 'disable_proxy', 'phase': 'prepared', 'backup': 'prepared.json'},
                   {'operation': 'disable_proxy', 'phase': 'applied', 'backup': 'applied.json'},
                   {'operation': 'disable_proxy', 'ok': False, 'changed': True, 'backup': 'failed.json'}]
        with patch.object(self.manager, 'history', return_value=records):
            self.assertEqual(good_path, self.manager.last_backup())
            records.append({'operation': 'restore_proxy', 'ok': True, 'changed': False, 'phase': 'restored', 'backup': str(good_path)})
            self.assertIsNone(self.manager.last_backup())

    def test_last_backup_skips_deleted_backup_and_directory(self):
        records = [{'operation': 'disable_proxy', 'ok': True, 'changed': True, 'phase': 'verified', 'backup': str(self.backup_path)}]
        self.backup_path.unlink()
        with patch.object(self.manager, 'history', return_value=records):
            self.assertIsNone(self.manager.last_backup())
            self.backup_path.mkdir()
            self.assertIsNone(self.manager.last_backup())

    def test_last_backup_reconciles_durable_restored_phase_after_journal_interruption(self):
        self.backup['phase'] = 'restored'
        app.atomic_json(self.backup_path, self.backup)
        with patch.object(self.manager, 'history', return_value=[
                {'operation': 'disable_proxy', 'ok': True, 'changed': True, 'phase': 'verified', 'backup': str(self.backup_path)}]):
            self.assertIsNone(self.manager.last_backup())


class DisableTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manager = app.RepairManager(Path(self.temp.name))
        self.proxy = evidence()
        self.report = types.SimpleNamespace(proxy=copy.deepcopy(self.proxy))
        for patcher in (patch.object(app, 'private_storage'),
                        patch.object(app, 'current_sid', return_value='S-1-5-21-123')):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_inconsistent_effective_flag_rejected_by_preview_and_execute(self):
        self.proxy['wininet_api']['flags'] = 9
        self.assertFalse(app.proxy_repair_eligibility(self.proxy)['eligible'])
        with patch.object(app, 'collect_proxy', return_value=self.proxy), patch.object(app, 'set_wininet_flags') as setter:
            result = self.manager.disable_proxy(self.report, confirmed=True)
        self.assertFalse(result['ok'])
        self.assertFalse(result['changed'])
        setter.assert_not_called()
        self.assertIsNone(self.manager.last_backup())

    def test_snapshot_race_from_consistent_to_inconsistent_does_not_report_success(self):
        inconsistent = state(True)
        inconsistent['flags'] = 9
        with patch.object(app, 'collect_proxy', return_value=self.proxy), patch.object(app, 'proxy_snapshot', return_value=inconsistent), patch.object(
                app, 'set_wininet_flags') as setter:
            result = self.manager.disable_proxy(self.report, confirmed=True)
        self.assertFalse(result['ok'])
        setter.assert_not_called()

    def test_success_verifies_both_registry_and_api_preserving_autodetect(self):
        with patch.object(app, 'collect_proxy', return_value=self.proxy), patch.object(app, 'proxy_snapshot', side_effect=[state(True), state(False, 7)]), patch.object(
                app, 'set_wininet_flags') as setter:
            result = self.manager.disable_proxy(self.report, confirmed=True)
        setter.assert_called_once_with(9)
        self.assertTrue(result['ok'])
        self.assertEqual(0, result['after'][app.INET_PATH]['ProxyEnable']['value'])
        self.assertFalse(result['after']['flags'] & 2)
        self.assertEqual('verified', result['phase'])
        self.assertEqual(Path(result['backup']), self.manager.last_backup())

    def test_registry_enable_still_one_fails_even_when_api_disabled(self):
        bad = state(False)
        bad[app.INET_PATH]['ProxyEnable']['value'] = 1
        with patch.object(app, 'collect_proxy', return_value=self.proxy), patch.object(app, 'proxy_snapshot', side_effect=[state(True), bad, state(True, 4)]), patch.object(
                app, 'set_wininet_flags'), patch.object(app, 'restore_proxy_snapshot') as restore:
            with self.assertRaisesRegex(RuntimeError, '驗證失敗'):
                self.manager.disable_proxy(self.report, confirmed=True)
        restore.assert_called_once_with(state(True))
        self.assertIsNone(self.manager.last_backup())

    def test_verification_does_not_rollback_over_external_server_change(self):
        changed = state(False)
        changed[app.INET_PATH]['ProxyServer']['value'] = '127.0.0.1:9999'
        changed['api']['ProxyServer'] = '127.0.0.1:9999'
        with patch.object(app, 'collect_proxy', return_value=self.proxy), patch.object(app, 'proxy_snapshot', side_effect=[state(True), changed]), patch.object(
                app, 'set_wininet_flags'), patch.object(app, 'restore_proxy_snapshot') as restore:
            with self.assertRaisesRegex(RuntimeError, 'False'):
                self.manager.disable_proxy(self.report, confirmed=True)
        restore.assert_not_called()
        self.assertIsNone(self.manager.last_backup())
        self.assertEqual('rollback_failed', self.manager.history()[-1]['phase'])

    def test_policy_change_between_collect_and_mutation_is_rejected(self):
        before = state(True)
        before['policy'] = {'HKCU\\policy': {'values': {'Proxy': 1}}}
        with patch.object(app, 'collect_proxy', return_value=self.proxy), patch.object(app, 'proxy_snapshot', return_value=before), patch.object(
                app, 'set_wininet_flags') as setter:
            with self.assertRaisesRegex(RuntimeError, '管理原則已變更'):
                self.manager.disable_proxy(self.report, confirmed=True)
        setter.assert_not_called()

    def test_api_endpoint_change_between_collect_and_mutation_is_rejected(self):
        before = state(True)
        before['api']['ProxyServer'] = '127.0.0.1:9999'
        with patch.object(app, 'collect_proxy', return_value=self.proxy), patch.object(app, 'proxy_snapshot', return_value=before), patch.object(
                app, 'set_wininet_flags') as setter:
            with self.assertRaisesRegex(RuntimeError, '代理內容已變更'):
                self.manager.disable_proxy(self.report, confirmed=True)
        setter.assert_not_called()

    def test_failed_journal_intent_prevents_mutation(self):
        with patch.object(app, 'collect_proxy', return_value=self.proxy), patch.object(app, 'proxy_snapshot', return_value=state(True)), patch.object(
                self.manager, '_record', side_effect=OSError('history disk full')), patch.object(app, 'set_wininet_flags') as setter:
            with self.assertRaises(OSError):
                self.manager.disable_proxy(self.report, confirmed=True)
        setter.assert_not_called()
        self.assertEqual('prepared', json.loads(next(Path(self.temp.name).glob('proxy_*.json')).read_text(encoding='utf-8'))['phase'])

    def test_missing_api_evidence_cannot_enable_automatic_fix(self):
        self.proxy.pop('wininet_api')
        self.assertFalse(app.proxy_repair_eligibility(self.proxy)['eligible'])

    def test_storage_permission_failure_prevents_collection_and_mutation(self):
        with patch.object(app, 'private_storage', side_effect=RuntimeError('backup ACL denied')), patch.object(
                app, 'collect_proxy') as collect, patch.object(app, 'set_wininet_flags') as setter:
            with self.assertRaisesRegex(RuntimeError, 'backup ACL denied'):
                self.manager.disable_proxy(self.report, confirmed=True)
        collect.assert_not_called()
        setter.assert_not_called()

    def test_disk_failure_after_mutation_does_not_prevent_rollback(self):
        real_write = app.atomic_json
        mutated = False
        def write(path, data):
            if mutated:
                raise OSError('disk became full after mutation')
            real_write(path, data)
        def change(_flags):
            nonlocal mutated
            mutated = True
        with patch.object(app, 'collect_proxy', return_value=self.proxy), patch.object(app, 'proxy_snapshot', side_effect=[state(True), state(True, 98), state(True, 99)]), patch.object(
                app, 'set_wininet_flags', side_effect=change), patch.object(app, 'atomic_json', side_effect=write), patch.object(
                app, 'restore_proxy_snapshot') as restore:
            with self.assertRaisesRegex(RuntimeError, 'True.*disk became full'):
                self.manager.disable_proxy(self.report, confirmed=True)
        restore.assert_called_once_with(state(True))
        self.assertIsNone(self.manager.last_backup())


@unittest.skipUnless(os.name == 'nt', 'Windows native API mock')
class WininetApiTests(unittest.TestCase):
    def test_restore_preserves_all_api_strings_without_registry_writes(self):
        snap = state(True)
        snap['api']['AutoConfigURL'] = 'https://pac.example/原設定.pac'
        snap['flags'] |= 4
        library = MagicMock()
        observed = {}
        def set_options(handle, code, pointer, size):
            options = pointer._obj
            self.assertEqual((None, 75, 4), (handle, code, options.dwOptionCount))
            for i in range(4):
                item = options.pOptions[i]
                observed[item.dwOption] = item.Value.dwValue if i == 0 else ctypes.wstring_at(item.Value.pszValue)
            return 1
        library.InternetSetOptionW.side_effect = set_options
        with patch.object(app.ctypes, 'WinDLL', return_value=library), patch.object(app, 'notify_wininet') as notify, patch.object(app, 'winreg') as registry:
            app.restore_proxy_snapshot(snap)
        self.assertEqual({1: 15, 2: SERVER, 3: '<local>', 4: 'https://pac.example/原設定.pac'}, observed)
        notify.assert_called_once()
        registry.OpenKey.assert_not_called()
        registry.SetValueEx.assert_not_called()
        registry.DeleteValue.assert_not_called()

    def test_query_uses_ui_flags_fallback_and_frees_allocated_strings(self):
        library, kernel = MagicMock(), MagicMock()
        buffers = [ctypes.create_unicode_buffer(x) for x in (SERVER, '<local>', 'https://pac.example/')]
        queried = []
        def query(handle, code, pointer, size):
            options = pointer._obj
            queried.append(options.pOptions[0].dwOption)
            if len(queried) == 1:
                return 0
            options.pOptions[0].Value.dwValue = 15
            for i, buffer in enumerate(buffers, 1):
                options.pOptions[i].Value.pszValue = ctypes.cast(buffer, ctypes.c_void_p).value
            return 1
        library.InternetQueryOptionW.side_effect = query
        with patch.object(windows.ctypes, 'WinDLL', side_effect=[library, kernel]):
            result = windows.query_wininet_proxy()
        self.assertEqual([10, 1], queried)
        self.assertEqual({'flags': 15, 'ProxyServer': SERVER, 'ProxyOverride': '<local>',
                          'AutoConfigURL': 'https://pac.example/'}, result)
        self.assertEqual({ctypes.cast(b, ctypes.c_void_p).value for b in buffers},
                         {call.args[0] for call in kernel.GlobalFree.call_args_list})

    def test_private_storage_acl_uses_native_token_sid_independent_of_backup_owner(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'current_sid', return_value='S-SYNTHETIC') as owner, patch.object(
                app, 'current_token_sid', return_value='S-1-5-21-987') as token, patch.object(app, 'protect_directory') as protect:
            app.private_storage(Path(directory))
        owner.assert_not_called()
        token.assert_called_once()
        protect.assert_called_once_with(Path(directory), 'S-1-5-21-987')


if __name__ == '__main__':
    unittest.main()
