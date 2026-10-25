"""Keyed pseudonyms: not reversible by enumeration, stable only within one install."""
import copy
import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import windows_net_diffdiag as app
from winnetdiff.core import privacy, snapshots

KEY_A = bytes(range(32))
KEY_B = bytes(range(1, 33))
NAMESPACES = (('standalone', app, app), ('modular', privacy, snapshots))


def legacy_token(value):
    """The 2.2.0a1 scheme: unkeyed SHA-256 of the raw value, 12 hex characters."""
    return hashlib.sha256(str(value).encode('utf-8')).hexdigest()[:12]


def token(text, kind):
    match = re.search('<' + kind + '-([0-9a-f]+)>', text)
    assert match, text
    return match.group(1)


class KeyedPseudonymTests(unittest.TestCase):
    def tearDown(self):
        for _, module, _ in NAMESPACES:
            module.set_pseudonym_key(None)

    def test_private_ipv4_is_not_recoverable_by_enumerating_the_range(self):
        for label, module, _ in NAMESPACES:
            with self.subTest(module=label):
                module.set_pseudonym_key(KEY_A)
                observed = token(module.redact('gateway 192.168.31.27 answered'), 'ip')
                self.assertNotEqual(legacy_token('192.168.31.27'), observed)
                # The attack that recovers the address from a 2.2.0a1 report in ~65k hashes.
                recovered = [str(a) for a in ipaddress.ip_network('192.168.0.0/16') if legacy_token(str(a)) == observed]
                self.assertEqual([], recovered)

    def test_same_install_is_stable_and_different_installs_are_unlinkable(self):
        values = {'ip': 'peer 10.20.30.40', 'mac': 'adapter a4-83-e7-12-34-56'}
        for label, module, _ in NAMESPACES:
            with self.subTest(module=label):
                module.set_pseudonym_key(KEY_A)
                first = {kind: token(module.redact(text), kind) for kind, text in values.items()}
                again = {kind: token(module.redact(text), kind) for kind, text in values.items()}
                guid = module.redacted_data({'InterfaceGuid': '{2C4E5A0B-1111-2222-3333-444455556666}'})['InterfaceGuid']
                module.set_pseudonym_key(KEY_B)
                other = {kind: token(module.redact(text), kind) for kind, text in values.items()}
                other_guid = module.redacted_data({'InterfaceGuid': '{2C4E5A0B-1111-2222-3333-444455556666}'})['InterfaceGuid']
                self.assertEqual(first, again)
                for kind in values:
                    self.assertNotEqual(first[kind], other[kind])
                self.assertNotEqual(guid, other_guid)
                self.assertRegex(guid, r'^<id-[0-9a-f]{12}>$')

    def test_existing_opaque_markers_are_idempotent(self):
        for label, module, _ in NAMESPACES:
            with self.subTest(module=label):
                module.set_pseudonym_key(KEY_A)
                once = module.redacted_data({'InterfaceGuid': 'synthetic-guid', 'note': 'host 172.16.5.4'})
                self.assertEqual(once, module.redacted_data(once))

    def test_modular_and_standalone_agree_under_one_key(self):
        privacy.set_pseudonym_key(KEY_A)
        app.set_pseudonym_key(KEY_A)
        text = 'route 192.168.1.0/24 via 192.168.1.1 mac 00:11:22:33:44:55'
        self.assertEqual(privacy.redact(text), app.redact(text))

    def test_short_or_non_bytes_keys_are_rejected(self):
        for value in (b'short', 'text-key-of-sufficient-length', 123):
            with self.subTest(value=value), self.assertRaises(ValueError):
                privacy.set_pseudonym_key(value)


class InstallKeyFileTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / 'nested' / 'pseudonym.key'

    def tearDown(self):
        privacy.set_pseudonym_key(None)
        app.set_pseudonym_key(None)
        self.folder.cleanup()

    def test_key_is_created_once_and_reused(self):
        key, source = privacy._load_install_key(self.path)
        self.assertEqual('install', source)
        self.assertEqual(32, len(key))
        self.assertRegex(self.path.read_text(encoding='ascii'), r'^[0-9a-f]{64}\n$')
        self.assertEqual((key, 'install'), privacy._load_install_key(self.path))
        if os.name != 'nt':
            self.assertEqual(0o600, stat.S_IMODE(self.path.stat().st_mode))

    def test_malformed_key_is_left_untouched_and_a_session_key_is_used(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text('not a key\n', encoding='ascii')
        key, source = privacy._load_install_key(self.path)
        self.assertEqual('ephemeral', source)
        self.assertEqual(32, len(key))
        self.assertEqual('not a key\n', self.path.read_text(encoding='ascii'))

    def test_concurrent_first_run_adopts_the_published_key(self):
        winner = bytes(range(100, 132))

        publish = privacy._publish_install_key
        def lose_race(path, text):
            publish(Path(path), winner.hex() + '\n')
            raise FileExistsError(path)

        with patch.object(privacy, '_publish_install_key', side_effect=lose_race):
            self.assertEqual((winner, 'install'), privacy._load_install_key(self.path))

    def test_environment_override_is_shared_by_all_module_instances(self):
        with patch.dict(os.environ, {'WINNETDIFF_PSEUDONYM_KEY_FILE': str(self.path)}):
            privacy.set_pseudonym_key(None)
            app.set_pseudonym_key(None)
            self.assertEqual(privacy.pseudonym_key_id(), app.pseudonym_key_id())
            self.assertEqual('install', app.pseudonym_key_source())
            self.assertTrue(self.path.is_file())


def sample_report():
    return {'version': '2.2.0a2', 'locale': 'en', 'generated_at': '2026-10-25T00:00:00+08:00',
            'route': {'adapters': [{'Name': 'Wi-Fi', 'InterfaceGuid': '{synthetic-guid}', 'Status': 'Up', 'ifIndex': 7}],
                      'routes': [{'AddressFamily': 2, 'DestinationPrefix': '0.0.0.0/0', 'InterfaceIndex': 7,
                                  'NextHop': '192.168.31.1', 'RouteMetric': 0}],
                      'query_status': {'adapters': 'ok', 'routes': 'ok', 'bindings': 'ok', 'dns_servers': 'ok'}},
            'proxy': {'errors': [], 'wininet': {'ProxyEnable': 0}},
            'security': {'completeness': {}, 'errors': []}}


class SnapshotIdentityTests(unittest.TestCase):
    def tearDown(self):
        for _, module, _ in NAMESPACES:
            module.set_pseudonym_key(None)

    def test_snapshot_records_scheme_and_compares_within_one_key(self):
        for label, privacy_module, snapshot_module in NAMESPACES:
            with self.subTest(module=label):
                privacy_module.set_pseudonym_key(KEY_A)
                first = snapshot_module.create_snapshot(sample_report())
                self.assertEqual('hmac-sha256-v1', first['identity_scheme'])
                self.assertRegex(first['identity_key_id'], r'^[0-9a-f]{16}$')
                changed = sample_report()
                changed['route']['routes'][0]['RouteMetric'] = 25
                result = snapshot_module.compare_snapshots(first, snapshot_module.create_snapshot(changed))
                self.assertEqual(['changed'], [c['kind'] for c in result['changes']])

    def test_snapshots_from_different_keys_refuse_to_compare(self):
        for label, privacy_module, snapshot_module in NAMESPACES:
            with self.subTest(module=label):
                privacy_module.set_pseudonym_key(KEY_A)
                first = snapshot_module.create_snapshot(sample_report())
                privacy_module.set_pseudonym_key(KEY_B)
                second = snapshot_module.create_snapshot(sample_report())
                with self.assertRaisesRegex(snapshot_module.SnapshotError, 'different identity keys'):
                    snapshot_module.compare_snapshots(first, second)

    def test_legacy_snapshots_compare_only_with_legacy_snapshots(self):
        privacy.set_pseudonym_key(KEY_A)
        current = snapshots.create_snapshot(sample_report())
        legacy = copy.deepcopy(current)
        legacy.pop('identity_scheme')
        legacy.pop('identity_key_id')
        self.assertEqual([], snapshots.compare_snapshots(legacy, copy.deepcopy(legacy))['changes'])
        with self.assertRaises(snapshots.SnapshotError):
            snapshots.compare_snapshots(legacy, current)

    def test_malformed_identity_fields_are_rejected_on_load(self):
        privacy.set_pseudonym_key(KEY_A)
        current = snapshots.create_snapshot(sample_report())
        for change in ({'identity_scheme': 'sha256-v0'}, {'identity_key_id': 'XYZ'}, {'identity_key_id': 7}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'snapshot.json'
                path.write_text(json.dumps(dict(current, **change)), encoding='utf-8')
                with self.assertRaises(snapshots.SnapshotError):
                    snapshots.load_snapshot(path)

    def test_row_ids_are_keyed(self):
        privacy.set_pseudonym_key(KEY_A)
        first = snapshots.create_snapshot(sample_report())
        privacy.set_pseudonym_key(KEY_B)
        second = snapshots.create_snapshot(sample_report())
        ids = lambda snap: [row['id'] for row in snap['categories']['routes']]
        self.assertNotEqual(ids(first), ids(second))
        unkeyed = hashlib.sha256(('routes\0' + snapshots._canonical([2, '0.0.0.0/0', 7, '192.168.31.1', None])).encode()).hexdigest()[:24]
        self.assertNotIn(unkeyed, ids(first))


if __name__ == '__main__':
    unittest.main()
