"""WinNetDiff 2.1.0b1 independent RED-team regressions.

Read-only synthetic tests: do not modify Windows services, proxy settings,
network adapters, or the registry. Place this alongside the merged source, or set
WINNETDIFF_SOURCE=/path/to/windows_net_diffdiag.py to target a newly built file.

The original 2.1.0b1 is EXPECTED to fail several tests. Passing the old bundle's
10 embedded tests is not proof these regressions have been fixed.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch


HERE = Path(__file__).resolve().parent
SOURCE = Path(os.environ.get('WINNETDIFF_SOURCE') or HERE / 'WinNetDiff_2_1_0b1_source.py').resolve()
if not SOURCE.is_file():
    raise RuntimeError(f'Source file missing: {SOURCE}; set WINNETDIFF_SOURCE')
spec = importlib.util.spec_from_file_location('winnetdiff_regression_target', SOURCE)
assert spec is not None and spec.loader is not None
wnd = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = wnd
spec.loader.exec_module(wnd)


def proxy_snap(enable: int, flags: int, counter: int, server: str = '127.0.0.1:7890') -> dict:
    """Synthetic WinINET record: only the counter bytes change between snapshots."""
    binary = bytes((0x46, 0, 0, 0, counter, 0, 0, 0, flags, 0, 0, 0))
    keys = ['ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect']
    first = {}
    for key in keys:
        if key == 'ProxyEnable':
            first[key] = {'exists': True, 'type': 4, 'value': enable}
        elif key == 'ProxyServer':
            first[key] = {'exists': True, 'type': 1, 'value': server}
        else:
            first[key] = {'exists': False, 'type': None, 'value': None}
    connection_item = {'exists': True, 'type': 3,
                       'value': {'base64': base64.b64encode(binary).decode('ascii')}}
    return {wnd.INET_PATH: first,
            wnd.INET_PATH + r'\Connections': {
                'DefaultConnectionSettings': dict(connection_item),
                'SavedLegacySettings': dict(connection_item),
            }, 'flags': flags}


class ProxyRestoreRegression(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manager = wnd.RepairManager(self.root)

    def backup_path(self, before: dict, after: dict) -> Path:
        path = self.root / 'proxy_illustration.json'
        path.write_text(json.dumps({
            'schema': 2, 'kind': 'wininet_proxy', 'sid': 'S-SYNTHETIC',
            'machine': 'SYNTHETIC-PC', 'before': before, 'after': after,
            'phase': 'applied',
        }, ensure_ascii=False), encoding='utf-8')
        return path

    def test_p0_restore_ignores_counter_drift_but_really_restores(self):
        """Unlike Gemini's assertNotEqual, actually call restore_proxy and assert restoration."""
        before = proxy_snap(1, 3, 1)
        after = proxy_snap(0, 1, 2)
        current = proxy_snap(0, 1, 5)  # Same effective proxy settings, new blob counter
        backup = self.backup_path(before, after)
        with patch.object(wnd, 'current_sid', return_value='S-SYNTHETIC'), \
             patch.object(wnd.platform, 'node', return_value='SYNTHETIC-PC'), \
             patch.object(wnd, 'proxy_snapshot', side_effect=[current, before]), \
             patch.object(wnd, 'restore_proxy_snapshot') as actual_restore:
            result = self.manager.restore_proxy(backup, confirmed=True)
        self.assertTrue(result['ok'])
        self.assertTrue(result['changed'])
        actual_restore.assert_called_once_with(before)

    def test_restore_must_reject_genuine_external_proxy_change(self):
        before = proxy_snap(1, 3, 1)
        after = proxy_snap(0, 1, 2)
        current = proxy_snap(0, 1, 5, server='127.0.0.1:9999')  # External change
        backup = self.backup_path(before, after)
        with patch.object(wnd, 'current_sid', return_value='S-SYNTHETIC'), \
             patch.object(wnd.platform, 'node', return_value='SYNTHETIC-PC'), \
             patch.object(wnd, 'proxy_snapshot', return_value=current), \
             patch.object(wnd, 'restore_proxy_snapshot') as actual_restore:
            with self.assertRaises(RuntimeError):
                self.manager.restore_proxy(backup, confirmed=True)
        actual_restore.assert_not_called()

    def test_last_backup_does_not_return_prepared_or_failed_operation(self):
        logs = [
            {'operation': 'disable_proxy', 'phase': 'prepared', 'backup': 'a.json'},
            {'operation': 'disable_proxy', 'ok': False, 'changed': False, 'backup': 'b.json'},
        ]
        with patch.object(self.manager, 'history', return_value=logs):
            self.assertIsNone(self.manager.last_backup())

    def test_last_backup_does_not_return_already_restored_backup(self):
        logs = [
            {'operation': 'disable_proxy', 'ok': True, 'changed': True, 'backup': 'a.json'},
            {'operation': 'restore_proxy', 'ok': True, 'changed': True, 'backup': 'a.json'},
        ]
        with patch.object(self.manager, 'history', return_value=logs):
            self.assertIsNone(self.manager.last_backup())


class ProbeRegression(unittest.TestCase):
    def test_p0_overall_deadline_expired_after_tcp_is_not_tls_timeout(self):
        class Clock:
            t = 0.0
            def __call__(self):
                return self.t
        clock = Clock()
        raw = MagicMock()
        def slow_connect(_address):
            clock.t = 5.0  # TCP connect completed AFTER the 4.5s overall deadline
        raw.connect.side_effect = slow_connect
        addrinfo = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                    '', ('203.0.113.10', 443))
        with patch.object(wnd.time, 'perf_counter', side_effect=clock), \
             patch.object(wnd.socket, 'socket', return_value=raw), \
             patch.object(wnd.ssl, 'create_default_context', return_value=MagicMock()):
            result = wnd.probe_endpoint('example.com', socket.AF_INET, addrinfo,
                                        dns_ms=0, overall_timeout=4.5)
        self.assertEqual(result.stage, 'overall_timeout')
        self.assertEqual(result.timeout_stage, 'overall')
        self.assertIsNotNone(result.tcp_ms)

    def test_real_tls_socket_timeout_is_still_tls_timeout(self):
        raw = MagicMock()
        tls = MagicMock()
        tls.do_handshake.side_effect = TimeoutError('simulated TLS socket timeout')
        ctx = MagicMock()
        ctx.wrap_socket.return_value = tls
        addrinfo = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                    '', ('203.0.113.10', 443))
        with patch.object(wnd.socket, 'socket', return_value=raw), \
             patch.object(wnd.ssl, 'create_default_context', return_value=ctx):
            result = wnd.probe_endpoint('example.com', socket.AF_INET, addrinfo,
                                        dns_ms=0, overall_timeout=18)
        self.assertEqual(result.stage, 'tls_timeout')
        self.assertEqual(result.timeout_stage, 'tls')


class I18nRegression(unittest.TestCase):
    def test_english_translation_does_not_corrupt_chinese_device_identity(self):
        raw = '疑似孤兒安全／VPN 元件：深信服安全中心'
        localized = wnd.tr(raw, 'en')
        self.assertIn('深信服安全中心', localized)
        self.assertNotIn('Medium', localized)

    def test_simplified_character_map_does_not_corrupt_si(self):
        self.assertEqual('伺機而動'.translate(wnd.SIMPLIFIED_CHARACTERS), '伺机而动')

    def test_cli_english_help_language_options_not_corrupted(self):
        result = subprocess.run([sys.executable, str(SOURCE), '--lang', 'en', '--help'],
                                capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('Medium文', result.stdout)
        self.assertIn('简体中文', result.stdout)


class PrivacyRegression(unittest.TestCase):
    def test_mac_address_redaction_including_route_print_format(self):
        raw = (' 14...aa bb cc dd ee ff ......Intel(R) Wi-Fi\n'
               ' 18...AA-BB-CC-DD-EE-FF ......Virtual\n'
               ' card AA:BB:CC:DD:EE:FF')
        out = wnd.redact(raw).lower()
        for token in ('aa bb cc dd ee ff', 'aa-bb-cc-dd-ee-ff',
                      'aa:bb:cc:dd:ee:ff'):
            self.assertNotIn(token, out)

    def test_two_character_chinese_username_when_adjacent_to_chinese(self):
        with patch.dict(wnd.os.environ, {'USERNAME': '张三'}):
            out = wnd.redact(r'D:\Projects\张三的测试目录\app.exe')
        self.assertNotIn('张三', out)

    def test_computername_masked_inside_long_string(self):
        with patch.dict(wnd.os.environ, {'COMPUTERNAME': 'SYNTHETIC-LAPTOP-99'}), \
             patch.object(wnd.platform, 'node', return_value='SYNTHETIC-LAPTOP-99'):
            out = wnd.redact('route detected on SYNTHETIC-LAPTOP-99; continue')
        self.assertNotIn('SYNTHETIC-LAPTOP-99', out)

    def test_raw_columns_exposes_no_private_driver_directory(self):
        raw = {'raw_columns': ['sample.sys', r'D:\PrivateLab\Internal\bdnet.sys']}
        out = wnd.redacted_data(raw)
        self.assertNotIn('PrivateLab', json.dumps(out, ensure_ascii=False))
        self.assertNotIn('Internal', json.dumps(out, ensure_ascii=False))

    def test_display_version_not_treated_as_ipv4(self):
        result = wnd.redacted_data({'DisplayName': 'SyntheticVPN',
                                    'DisplayVersion': '4.5.5.0', 'version': '2.1.0.1'})
        self.assertEqual(result['DisplayVersion'], '4.5.5.0')
        self.assertEqual(result['version'], '2.1.0.1')


if __name__ == '__main__':
    unittest.main(verbosity=2)
