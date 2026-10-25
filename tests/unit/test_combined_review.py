"""Joint reviewer contracts, including native key ACLs in temporary directories."""
import copy
import dataclasses
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from winnetdiff.core import privacy, snapshots, engine
from winnetdiff.core.i18n import tr
from winnetdiff.core.messages import msg
from winnetdiff.probes import transport
from winnetdiff.reports.export import markdown_report
from tests.unit.test_markdown_export import hostile_report
from tests.unit.test_gemini_round_2_2 import realistic_security, fixture
from winnetdiff.analysis.evidence import corroborating_orphans, assess_phase_evidence
from winnetdiff.collectors.dns_audit import audit_dns_state

ROOT = Path(__file__).resolve().parents[2]


class CombinedPrivacyTests(unittest.TestCase):
    def tearDown(self):
        privacy.set_pseudonym_key(None)

    def test_directory_hmac_unicode_versions_across_three_exports_and_languages(self):
        for locale in ('en', 'zh-CN', 'zh-TW'):
            with self.subTest(locale=locale):
                privacy.set_pseudonym_key(bytes(range(32)))
                report = hostile_report(locale)
                report.security.update(installed_apps=[{'DisplayName': '服務_王濤', 'DisplayVersion': '4.5.5.0',
                    'InstallLocation': r'D:\Secret\Folder', 'InterfaceGuid': 'private-guid'}])
                report.findings[0].evidence = '服務_王濤 ' + r'D:\Secret\Folder' + ' 192.168.31.27 ```'
                data = privacy.redacted_data(dataclasses.asdict(report))
                rendered = markdown_report(report)
                snapshot = snapshots.create_snapshot(dataclasses.asdict(report))
                serialized = json.dumps([data, snapshot], ensure_ascii=False) + rendered
                for secret in ('Secret', 'Folder', 'private-guid', '192.168.31.27'):
                    self.assertNotIn(secret, serialized)
                self.assertIn('4.5.5.0', json.dumps(data))
                self.assertIn('服務_王濤', serialized)
                first = data['security']['installed_apps'][0]['InterfaceGuid']
                privacy.set_pseudonym_key(bytes(range(1, 33)))
                self.assertNotEqual(first, privacy.redacted_data(dataclasses.asdict(report))['security']['installed_apps'][0]['InterfaceGuid'])

    def test_brace_only_messages_survive_translation(self):
        value = '服務_{4d36e972-e325-11ce-bfc1-08002be10318}'
        for locale in ('en', 'zh-CN', 'zh-TW'):
            self.assertEqual(value, tr(msg(value), locale))

    def test_snapshot_compatibility_error_has_exact_three_language_message(self):
        message = 'Snapshots use different identity keys; create both on the same installation (baselines from earlier versions must be recreated)'
        translated = [tr(message, language) for language in ('en', 'zh-CN', 'zh-TW')]
        self.assertEqual(3, len(set(translated)))
        self.assertIn('旧版', translated[1]); self.assertIn('舊版', translated[2])


class ResolverBoundaryTests(unittest.TestCase):
    def test_cancel_winning_acquire_race_releases_slot_without_resolving(self):
        cancel = threading.Event()
        class Slot:
            released = 0
            def acquire(self, **kwargs):
                cancel.set()
                return True
            def release(self):
                self.released += 1
        slot = Slot()
        with patch.object(transport, '_DNS_SLOTS', slot), patch.object(transport.socket, 'getaddrinfo') as resolver:
            _, error, _ = transport.timeout_dns('test.example', socket.AF_INET, cancel=cancel)
        self.assertTrue(error.startswith('Cancelled:'))
        self.assertEqual(1, slot.released); resolver.assert_not_called()

    def test_dnsbusy_does_not_become_resolver_latency(self):
        slots = threading.BoundedSemaphore(1); slots.acquire()
        with patch.object(transport, '_DNS_SLOTS', slots):
            result = transport.probe_host_family('test.example', socket.AF_INET, dns_timeout=.01)
        self.assertEqual('dns_error', result.stage)
        self.assertEqual('DNSBusy', result.error_type)
        self.assertIsNone(result.dns_ms)

    def test_worker_start_failure_releases_exact_slot(self):
        slots = threading.BoundedSemaphore(1)
        with patch.object(transport, '_DNS_SLOTS', slots), patch.object(transport.threading.Thread, 'start', side_effect=RuntimeError('test')):
            _, error, _ = transport.timeout_dns('test.example', socket.AF_INET)
        self.assertTrue(error.startswith('DNSWorkerError:'))
        self.assertTrue(slots.acquire(blocking=False))
        slots.release()


class JointEvidenceTests(unittest.TestCase):
    def test_completion_order_preserves_joint_evidence_and_known_fake_ip_route(self):
        records = fixture()['probes']
        refs = corroborating_orphans(realistic_security(), {'bindings': []})
        forward = assess_phase_evidence(records, {'tls_timeout'}, corroboration=refs)
        reverse = assess_phase_evidence(list(reversed(records)), {'tls_timeout'}, corroboration=refs)
        self.assertEqual('E3', forward['grade']); self.assertEqual(forward['grade'], reverse['grade'])
        routes = {'query_status': {'routes': 'ok', 'interfaces': 'ok'},
            'interfaces': [{'InterfaceIndex': 2, 'AddressFamily': 2, 'ConnectionState': 'Connected', 'InterfaceMetric': 1}],
            'adapters': [{'ifIndex': 2, 'Status': 'Up', 'Classification': 'virtual'}],
            'routes': [{'InterfaceIndex': 2, 'DestinationPrefix': '198.18.0.0/15', 'RouteMetric': 1}],
            'dns_servers': [{'InterfaceIndex': 2, 'ServerAddresses': '127.0.0.1'}]}
        probes = [{'host': 'test.example', 'ip': '198.18.1.1', 'resolved_addresses': ['198.18.1.1'],
            'attempts': [{'ip': '198.18.1.1', 'stage': 'tls_timeout'}]}]
        runtime = {'cores': [{'Name': 'mihomo'}], 'core_query_complete': True}
        result = audit_dns_state(routes, probes, runtime, network_tested=True)
        self.assertEqual('fake_ip_indeterminate', result['targets'][0]['status'])
        self.assertEqual('127.0.0.1', result['targets'][0]['configured_dns'][0]['address'])
        probes[0]['attempts'][0]['stage'] = 'http_ok'
        result = audit_dns_state(routes, probes, runtime, network_tested=True)
        self.assertEqual('expected_fake_ip_active_proxy', result['targets'][0]['status'])


@unittest.skipUnless(os.name == 'nt', 'Native protected Windows key-file ACL')
class NativeKeyTests(unittest.TestCase):
    def test_unprotected_existing_key_is_untouched_and_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'pseudonym.key'; original = 'ab'*32 + '\n'
            path.write_text(original, encoding='ascii')
            key, source = privacy._load_install_key(path)
            self.assertEqual('ephemeral', source)
            self.assertNotEqual(bytes.fromhex('ab'*32), key)
            self.assertEqual(original, path.read_text(encoding='ascii'))

    def test_parallel_processes_publish_one_complete_acl_protected_key(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'中文目錄'/'pseudonym.key'
            env = dict(os.environ, WINNETDIFF_PSEUDONYM_KEY_FILE=str(path), PYTHONUTF8='1')
            code = 'from winnetdiff.core.privacy import pseudonym_key_id,pseudonym_key_source;print(pseudonym_key_id(),pseudonym_key_source())'
            children = [subprocess.Popen([sys.executable, '-c', code], cwd=ROOT, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(6)]
            outputs = []
            for child in children:
                stdout, stderr = child.communicate(timeout=20)
                self.assertEqual(0, child.returncode, stderr.decode(errors='replace'))
                outputs.append(stdout.decode().strip())
            self.assertEqual(1, len(set(outputs)), outputs); self.assertTrue(outputs[0].endswith(' install'), outputs)
            self.assertEqual('install', privacy._load_install_key(path)[1])
            self.assertEqual([], list(path.parent.glob('*.tmp')))

    def test_write_failure_uses_session_key_without_altering_existing_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'pseudonym.key'
            with patch.object(privacy, '_publish_install_key', side_effect=PermissionError('denied')):
                key, source = privacy._load_install_key(path)
            self.assertEqual('ephemeral', source); self.assertEqual(32, len(key))
            self.assertFalse(path.exists())

    def test_publisher_access_denied_adopts_only_the_valid_race_winner(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'pseudonym.key'
            publish = privacy._publish_install_key
            def lose_race(target, text):
                publish(target, bytes(range(32)).hex()+'\n')
                raise PermissionError('another process has the published destination open')
            with patch.object(privacy, '_publish_install_key', side_effect=lose_race):
                key, source = privacy._load_install_key(path)
            self.assertEqual('install', source)
            self.assertEqual(bytes(range(32)), key)
