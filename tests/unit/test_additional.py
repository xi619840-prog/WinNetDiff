import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import windows_net_diffdiag as app


class DnsRepairTests(unittest.TestCase):
    def test_flush_requires_confirmation(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                app.RepairManager(Path(folder)).flush_dns()

    def test_flush_journals_before_command_and_checks_after(self):
        with tempfile.TemporaryDirectory() as folder:
            manager = app.RepairManager(Path(folder))
            def execute(args, timeout):
                self.assertEqual(args, ['ipconfig', '/flushdns'])
                self.assertEqual(manager.history()[-1]['phase'], 'prepared')
                return {'ok': True, 'returncode': 0, 'stdout': '已成功重新整理 DNS 快取', 'stderr': ''}
            with patch.object(app, 'private_storage'), patch.object(app, 'ps_json', side_effect=[([{'Count': 9}], ''), ([{'Count': 1}], '')]), patch.object(app, 'run_command', side_effect=execute):
                result = manager.flush_dns(confirmed=True, allow_irreversible=True)
            self.assertTrue(result['ok'])
            self.assertEqual(result['before'][0]['Count'], 9)
            self.assertEqual(result['after'][0]['Count'], 1)
            self.assertIn('無法', manager.history()[0]['rollback'])

    def test_flush_nonzero_exit_not_success(self):
        with tempfile.TemporaryDirectory() as folder:
            manager = app.RepairManager(Path(folder))
            with patch.object(app, 'private_storage'), patch.object(app, 'ps_json', return_value=([], 'Access denied')), patch.object(app, 'run_command', return_value={'ok': False, 'returncode': 5, 'stdout': '', 'stderr': '拒絕存取'}):
                result = manager.flush_dns(confirmed=True, allow_irreversible=True)
            self.assertFalse(result['ok'])
            self.assertFalse(result['changed'])
            self.assertEqual(result['command']['returncode'], 5)

    def test_explicit_proxy_management_policy_blocks_fix(self):
        for scope in ('policy', 'policy_user'):
            proxy = {'wininet': {'ProxyEnable': 1}, scope: {'values': {'Proxy': 1}}}
            self.assertFalse(app.proxy_repair_eligibility(proxy)['eligible'])


class FixtureFilesTests(unittest.TestCase):
    def test_cp936_fixture_roundtrip(self):
        raw = (Path(__file__).parents[1] / 'fixtures' / 'native_cp936.csv').read_bytes()
        text, encoding, error = app.decode_output(raw, 'cp936')
        rows = app.parse_driverquery_csv(text)
        self.assertEqual(rows[0]['Name'], 'BdNet')
        self.assertIn('中文測試', rows[0]['PathName'])

    def test_utf8_json_fixture(self):
        raw = (Path(__file__).parents[1] / 'fixtures' / 'powershell_utf8.json').read_bytes()
        text, encoding, error = app.decode_output(raw, 'powershell')
        self.assertEqual(json.loads(text)[0]['DisplayName'], '閃連 VPN 測試服務')


if __name__ == '__main__':
    unittest.main()
