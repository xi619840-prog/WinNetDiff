import json
import unittest

import windows_net_diffdiag as app


def routes():
    return {'defaults_ipv4': [{'InterfaceIndex': 3, 'InterfaceAlias': 'WLAN', 'Gateway': '192.168.1.1',
                              'EffectiveMetric': 35, 'ConnectionState': 'Connected'}],
            'defaults_ipv6': [], 'ipv6_addresses': [], 'ipv6_bindings': [], 'bindings': [],
            'adapters': [{'Name': 'WLAN', 'Classification': 'physical', 'Status': 'Up', 'ifIndex': 3}],
            'query_status': {'routes': 'ok', 'bindings': 'ok'}, 'errors': []}


def security():
    return {'evidence': [], 'errors': []}


class FinalPrivacyTests(unittest.TestCase):
    def make_private_report(self):
        raw = 'U0VDUkVUX1BST1hZX1BBU1NXT1JE'
        data = {'path': r'C:\Users\PrivateAlice\Private\secret.txt',
                'stdout_raw_base64': raw, 'proxy': 'http://alice:private_password@203.0.113.7:7890'}
        report = app.Report('2.0', '2026-10-24', 'Windows 11', False, ['example.com'],
                            data, routes(), [], security(),
                            [app.Finding('資訊', '安全/驅動', 'private evidence', json.dumps(data), 'explanation')], [])
        return report, raw

    def test_markdown_redacts_escaped_json_paths_credentials_and_base64(self):
        report, raw = self.make_private_report()
        result = app.markdown_report(report)
        for private in ('PrivateAlice', 'private_password', raw, '203.0.113.7'):
            self.assertNotIn(private, result)
        self.assertRegex(result, r'"stdout_raw_base64": "<[^>]*redacted>"')

    def test_summary_redacts_escaped_json_paths_credentials_and_base64(self):
        report, raw = self.make_private_report()
        result = app.summarize(report)
        for private in ('PrivateAlice', 'private_password', raw, '203.0.113.7'):
            self.assertNotIn(private, result)
        self.assertRegex(result, r'"stdout_raw_base64": "<[^>]*redacted>"')

    def test_full_local_markdown_and_summary_retain_evidence(self):
        report, raw = self.make_private_report()
        for render in (app.markdown_report, app.summarize):
            with self.subTest(renderer=render.__name__):
                result = render(report, full=True)
                self.assertIn('PrivateAlice', result)
                self.assertIn('private_password', result)
                self.assertIn(raw, result)

    def test_user_path_with_spaces_hides_entire_username(self):
        text = r'C:\Users\Unique PersonName\Private\file.txt'
        result = app.redact(text)
        self.assertNotIn('Unique', result)
        self.assertNotIn('PersonName', result)

    def test_plain_error_with_embedded_escaped_json_path_hides_username(self):
        text = 'PowerShell JSON parse error; raw output: ' + json.dumps({'path': r'C:\Users\OtherPrivateUser\file.txt'})
        self.assertNotIn('OtherPrivateUser', app.redact(text))


class FinalDiagnosisTests(unittest.TestCase):
    def test_ipv6_no_route_dns_failure_is_information_when_matching_ipv4_succeeds(self):
        probes = [app.Probe('example.com', 'IPv4', stage='http_ok', http_status=200),
                  app.Probe('example.com', 'IPv6', stage='dns_error', error='gaierror: no IPv6 address')]
        findings = app.analyze({}, routes(), probes, security())
        self.assertTrue(any('無預設路由' in finding.title for finding in findings))
        self.assertTrue(any('DNS' in finding.title for finding in findings))
        self.assertTrue(all(finding.severity == '資訊' for finding in findings))

    def repeated_tls_probes(self, count=2):
        probes = []
        for host in ('first.example.com', 'second.example.com'):
            probe = app.Probe(host, 'IPv4', ip='203.0.113.10', stage='tls_timeout', tcp_ms=10, tls_ms=6000)
            probe.context = {'port': 443, 'sni': host, 'method': 'HEAD', 'path': '/',
                             'connect_timeout': 5, 'tls_timeout': 6, 'http_timeout': 5}
            probe.attempts = [{'host': host, 'family': 'IPv4', 'ip': '203.0.113.10', 'stage': 'tls_timeout',
                               'tcp_ms': 10, 'tls_ms': 6000, 'attempt': index + 1} for index in range(count)]
            probes.append(probe)
        return probes

    def orphan_security(self):
        data = security()
        # Explicit independent synthetic runtime + complete absence inventory;
        # a running WFP service/driver need not appear in NDIS binding metadata.
        data.update(service_registry=[], drivers_wmi=[{'Name': 'BdNet', 'State': 'Running',
                    'PathName': r'C:\Windows\System32\drivers\BdNet.sys'}],
                    installed_apps=[],
                    completeness={'service_registry': True, 'drivers_wmi': True, 'installed_apps': True})
        data['evidence'] = [{'Name': 'BdNet', 'Status': 'registration_missing', 'Running': True,
                             'OwnerApps': [], 'Severity': '高優先級', 'Confidence': '中',
                             'Reasons': ['driver running, associated application not registered']}]
        return data

    def test_repeated_multi_target_tls_plus_orphan_has_highest_investigation_priority(self):
        route = routes()
        route['bindings'] = [{'Name': 'WLAN', 'ComponentID': 'synthetic_network_filter', 'Enabled': True,
                              'OwnerEvidence': {'Service': 'BdNet'}}]
        findings = app.analyze({}, route, self.repeated_tls_probes(), self.orphan_security())
        tls = next(finding for finding in findings if 'TCP 成功' in finding.title)
        self.assertEqual('高優先級', tls.severity)
        self.assertEqual(0, tls.priority)
        self.assertEqual('E3', tls.evidence_grade)
        self.assertIs(findings[0], tls)
        self.assertIn('MTU', tls.interpretation)
        self.assertIn('尚未證明', tls.interpretation)
        self.assertFalse(any('sc delete' in command.lower() for command in tls.commands))

    def test_single_attempt_per_target_does_not_claim_persistent_high_priority(self):
        findings = app.analyze({}, routes(), self.repeated_tls_probes(count=1), self.orphan_security())
        tls = next(finding for finding in findings if 'TCP 成功' in finding.title)
        self.assertEqual('可疑', tls.severity)
        self.assertNotEqual(0, tls.priority)

    def test_success_after_tls_failure_retains_evidence_without_persistent_claim(self):
        probes = self.repeated_tls_probes()
        probes[0].stage = 'http_ok'
        probes[0].intermittent = True
        probes[0].attempts[1].update(stage='http_ok', http_ms=10)
        findings = app.analyze({}, routes(), probes, self.orphan_security())
        tls = next(finding for finding in findings if 'TCP 成功' in finding.title)
        self.assertEqual('可疑', tls.severity)
        self.assertIn('first.example.com', tls.evidence)
        self.assertTrue(any('重試結果不一致' in finding.title for finding in findings))


if __name__ == '__main__':
    unittest.main()
