from __future__ import annotations
import argparse
import base64
import codecs
import csv
import ctypes
import datetime as dt
import io
import ipaddress
import json
import locale
import ntpath
import os
import platform
import queue
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional
if os.name == 'nt':
    import winreg
else:
    winreg = None
from winnetdiff.analysis.rules import analyze
from winnetdiff.analysis.evidence import assess_phase_evidence
from winnetdiff.collectors.proxy import proxy_endpoints
from winnetdiff.collectors.routes import binding_preview, parse_route_print
from winnetdiff.collectors.security import export_wfp
from winnetdiff.core.config import parse_hosts
from winnetdiff.core.engine import scan
from winnetdiff.core.models import APP_NAME, DEFAULT_HOSTS, INET_PATH, VERSION
from winnetdiff.core.process import decode_output, ps_json
from winnetdiff.probes.transport import probe_endpoint
from winnetdiff.repairs.manager import RepairManager, proxy_repair_eligibility
from winnetdiff.reports.export import evidence_text, markdown_code_block, markdown_report, redact, redacted_data, summarize
from winnetdiff.core.config import resolve_targets, load_settings, set_output_directory, normalize_language, default_profile
from winnetdiff.core.i18n import tr, set_language
from winnetdiff.core.snapshots import save_snapshot, load_snapshot, compare_snapshots
from winnetdiff.gui.app import gui
from winnetdiff.reports.share_card import compact_share_card
from winnetdiff.probes.pmtu import pmtu_candidates, probe_pmtu
from winnetdiff.core.atomic import atomic_write_text
from winnetdiff.core.privacy import set_pseudonym_key
from winnetdiff.core.engine import with_proxy_path_evidence
from winnetdiff.collectors.security import summarize_wfp_xml
from winnetdiff.collectors.dns_audit import is_fake_ip
from winnetdiff.probes.pmtu import parse_ping_result


def self_test() -> None:
    """Portable embedded tests; the runtime never needs the external tests folder."""
    import unittest
    import tempfile
    from unittest.mock import MagicMock, patch
    class EmbeddedTests(unittest.TestCase):
        def test_chinese_command_output(self):
            original = '中文服務 C:\\使用者\\測試\\閃連 VPN.exe'
            self.assertEqual(decode_output(original.encode('cp936'), 'cp936')[0], original)
            self.assertEqual(decode_output(original.encode('utf-8-sig'))[0], original)
        def test_powershell_json(self):
            with patch.dict(ps_json.__globals__, {'powershell': lambda *a, **k: {'ok': True, 'stdout': '[{"名稱":"中文"}]'}}):
                self.assertEqual(ps_json('query')[0][0]['名稱'], '中文')
        def test_proxy_parser(self):
            self.assertEqual(proxy_endpoints('http=127.0.0.1:7890;https=[::1]:7891'), [('127.0.0.1', 7890), ('::1', 7891)])
        def test_domain_validation(self):
            self.assertEqual(parse_hosts('www.baidu.com，www.qq.com'), ['www.baidu.com', 'www.qq.com'])
            with self.assertRaises(ValueError):
                parse_hosts('https://www.baidu.com')
        def test_route_parser(self):
            self.assertEqual(parse_route_print('0.0.0.0  0.0.0.0  192.168.1.1 192.168.1.2 35')[0]['EffectiveMetric'], 35)
        def test_inactive_proxy_not_repaired(self):
            self.assertFalse(proxy_repair_eligibility({'wininet': {'ProxyEnable': 0}})['eligible'])
        def test_tls_timeout_same_socket(self):
            raw, tls, ctx = MagicMock(), MagicMock(), MagicMock()
            tls.do_handshake.side_effect = TimeoutError('模擬 TLS 逾時')
            ctx.wrap_socket.return_value = tls
            info = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('203.0.113.1', 443))
            with patch.object(socket, 'socket', return_value=raw), patch.object(ssl, 'create_default_context', return_value=ctx):
                probe = probe_endpoint('example.com', socket.AF_INET, info, 1)
            self.assertEqual(probe.stage, 'tls_timeout')
            self.assertIsNotNone(probe.tcp_ms)
            self.assertIs(ctx.wrap_socket.call_args.args[0], raw)
            self.assertFalse(ctx.wrap_socket.call_args.kwargs['do_handshake_on_connect'])
            tls.close.assert_called_once()
        def test_overall_after_tcp_stays_overall(self):
            clock, raw, ctx = [0.0], MagicMock(), MagicMock()
            raw.connect.side_effect = lambda _address: clock.__setitem__(0, 5.0)
            info = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('203.0.113.1', 443))
            with patch.object(time, 'perf_counter', side_effect=lambda: clock[0]), \
                 patch.object(socket, 'socket', return_value=raw), \
                 patch.object(ssl, 'create_default_context', return_value=ctx):
                probe = probe_endpoint('example.com', socket.AF_INET, info, 1, overall_timeout=4.5)
            self.assertEqual((probe.stage, probe.timeout_stage), ('overall_timeout', 'overall'))
            self.assertEqual(probe.tcp_ms, 5000)
            self.assertIsNone(probe.tls_ms)
            ctx.wrap_socket.assert_not_called()
        def test_evidence_grade_requires_real_path_repetition(self):
            attempts = [{'host': 'example.com', 'family': 'IPv4', 'ip': ip,
                         'stage': 'tls_timeout', 'tcp_ms': 10, 'attempt': index + 1}
                        for index, ip in enumerate(('203.0.113.1', '203.0.113.2'))]
            probes = [{'host': 'example.com', 'family': 'IPv4', 'attempts': attempts,
                       'context': {'port': 443, 'sni': 'example.com', 'method': 'HEAD', 'path': '/',
                                   'connect_timeout': 5, 'tls_timeout': 6, 'http_timeout': 5}}]
            self.assertEqual(assess_phase_evidence(probes, {'tls_timeout'})['grade'], 'E1')
            attempts[1]['ip'] = attempts[0]['ip']
            self.assertEqual(assess_phase_evidence(probes, {'tls_timeout'})['grade'], 'E2')
        def test_redaction(self):
            text = redact('http://user:secret@127.0.0.1:7890 C:\\Users\\TestUser\\a.txt')
            self.assertNotIn('secret', text)
            self.assertNotIn('TestUser', text)
            self.assertNotIn('127.0.0.1', text)
        def test_query_failure_unknown(self):
            issues = analyze({}, {'errors': ['Access denied']}, [], {'errors': ['Access denied']})
            self.assertTrue(any('未知' in f.title for f in issues))
            self.assertFalse(any('未找到 IPv4' in f.title for f in issues))
        def test_safe_binding_preview(self):
            preview = binding_preview({'Name': 'WLAN [測試]', 'ComponentID': 'vbox_lwf', 'Enabled': True})
            self.assertIn('-ceq', preview['disable'])
            self.assertIn('-Confirm', preview['disable'])
            self.assertIn('Enable-NetAdapterBinding', preview['restore'])
        def _proxy_snapshot(self, enabled, counter=1, server='127.0.0.1:7890'):
            return {INET_PATH: {'ProxyEnable': {'exists': True, 'type': 4, 'value': int(enabled)},
                                'ProxyServer': {'exists': True, 'type': 1, 'value': server}},
                    INET_PATH + r'\Connections': {'counter': counter}, 'flags': 3 if enabled else 1}
        def test_proxy_restore_ignores_blob_counter_but_calls_restorer(self):
            before, after, current = self._proxy_snapshot(True), self._proxy_snapshot(False, 2), self._proxy_snapshot(False, 7)
            actual_restore = MagicMock()
            with tempfile.TemporaryDirectory() as directory:
                backup_path = Path(directory) / 'synthetic_proxy.json'
                backup_path.write_text(json.dumps({'schema': 2, 'kind': 'wininet_proxy', 'sid': 'synthetic',
                    'machine': platform.node(), 'before': before, 'after': after}), encoding='utf-8')
                with patch.dict(RepairManager.restore_proxy.__globals__, {
                        'private_storage': lambda _path: None, 'current_sid': lambda: 'synthetic',
                        'proxy_snapshot': MagicMock(side_effect=[current, before]),
                        'restore_proxy_snapshot': actual_restore}):
                    result = RepairManager(Path(directory)).restore_proxy(backup_path, confirmed=True)
            self.assertTrue(result['ok'])
            self.assertTrue(result['changed'])
            self.assertEqual('restored', result['phase'])
            actual_restore.assert_called_once_with(before)
        def test_proxy_restore_refuses_real_external_endpoint_change(self):
            before, after = self._proxy_snapshot(True), self._proxy_snapshot(False, 2)
            actual_restore = MagicMock()
            with tempfile.TemporaryDirectory() as directory:
                backup_path = Path(directory) / 'synthetic_proxy.json'
                backup_path.write_text(json.dumps({'schema': 2, 'kind': 'wininet_proxy', 'sid': 'synthetic',
                    'machine': platform.node(), 'before': before, 'after': after}), encoding='utf-8')
                with patch.dict(RepairManager.restore_proxy.__globals__, {
                        'private_storage': lambda _path: None, 'current_sid': lambda: 'synthetic',
                        'proxy_snapshot': lambda: self._proxy_snapshot(False, 8, '127.0.0.1:9999'),
                        'restore_proxy_snapshot': actual_restore}):
                    with self.assertRaises(RuntimeError):
                        RepairManager(Path(directory)).restore_proxy(backup_path, confirmed=True)
            actual_restore.assert_not_called()
        def test_proxy_preview_rejects_registry_api_disagreement(self):
            result = proxy_repair_eligibility({'wininet': {'ProxyEnable': 1}, 'wininet_api': {'flags': 1}})
            self.assertFalse(result['eligible'])
            self.assertIn('不一致', result['reason'])
        def test_proxy_last_backup_skips_failed_prepared_and_restored(self):
            with tempfile.TemporaryDirectory() as directory:
                manager = RepairManager(Path(directory))
                logs = [{'operation': 'disable_proxy', 'ok': True, 'changed': True, 'backup': 'done.json'},
                        {'operation': 'restore_proxy', 'ok': True, 'changed': True, 'backup': 'done.json'},
                        {'operation': 'disable_proxy', 'phase': 'prepared', 'backup': 'prepared.json'},
                        {'operation': 'disable_proxy', 'ok': False, 'changed': True, 'backup': 'failed.json'}]
                with patch.object(manager, 'history', return_value=logs):
                    self.assertIsNone(manager.last_backup())
        def test_fake_ip_is_a_clue_and_range_is_exact(self):
            self.assertTrue(is_fake_ip('198.19.1.5'))
            self.assertFalse(is_fake_ip('198.20.1.5'))
            self.assertFalse(is_fake_ip('::1'))
        def test_pmtu_explicit_fragment_feedback_and_exit_code(self):
            self.assertEqual(parse_ping_result({'ok': True, 'returncode': 0, 'stdout': 'Packet needs to be fragmented but DF set.'}), 'fragmentation_needed')
            self.assertEqual(parse_ping_result({'ok': True, 'returncode': 0, 'stdout': 'Request timed out.'}), 'icmp_timeout')
        def test_compact_card_is_bounded_and_excludes_raw_identity(self):
            card = compact_share_card({'version': VERSION, 'locale': 'en', 'device': 'SyntheticPrivateDevice', 'layers': {}, 'probes': [], 'findings': [], 'limitations': ['SyntheticPrivateToken']})
            self.assertLessEqual(len(card), 500)
            self.assertNotIn('SyntheticPrivate', card)
            self.assertIn('not run', card)
    # Side-effect free: an in-memory pseudonym key, never the install key file.
    set_pseudonym_key(os.urandom(32), 'self-test')
    try:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EmbeddedTests))
    finally:
        set_pseudonym_key(None)
    if not result.wasSuccessful():
        raise RuntimeError('內建自我測試失敗。')


def _live_audit_supported() -> bool:
    return os.name == 'nt'


def main(argv: Optional[list[str]] = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    for stream in (sys.stdout, sys.stderr):
        if stream and hasattr(stream, 'reconfigure') and not stream.isatty():
            stream.reconfigure(encoding='utf-8')
    preferences = load_settings()
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument('--lang')
    initial, _ = pre.parse_known_args(arguments)
    try:
        language = set_language(initial.lang or preferences.get('language', 'en'))
    except ValueError as exc:
        pre.error(str(exc))
    labels = {
        'en': {'saved': 'Saved', 'error': 'Error', 'cancel': 'Cancelled; no automatic system changes.',
               'description': 'Read-only differential network diagnostics. Repairs require GUI confirmation.'},
        'zh-CN': {'saved': '已保存', 'error': '错误', 'cancel': '已取消；未自动变更系统设置。',
                  'description': '只读网络差分诊断；修复须在 GUI 中明确确认。'},
        'zh-TW': {'saved': '已儲存', 'error': '錯誤', 'cancel': '已取消；未自動變更系統設定。',
                  'description': '唯讀網路差分診斷；修復須在 GUI 中明確確認。'},
    }[language]
    parser = argparse.ArgumentParser(prog=APP_NAME, description=APP_NAME + ' v' + VERSION + ' — ' + labels['description'])
    parser.add_argument('--lang', choices=['en', 'zh-CN', 'zh-TW'], default=language,
                        help='English / 简体中文 / 繁體中文')
    parser.add_argument('--profile', choices=['global', 'mainland', 'traditional'], help=tr('Target profile; independent of UI language', language))
    parser.add_argument('--cli', action='store_true', help=tr('Read-only terminal mode', language))
    parser.add_argument('--hosts', help=tr('1-3 comma-separated domains; overrides profile targets', language))
    parser.add_argument('--no-network', action='store_true', help=tr('Skip remote probes; local loopback proxy checks remain enabled', language))
    parser.add_argument('--json', metavar='PATH', help=tr('Save redacted JSON evidence', language))
    parser.add_argument('--markdown', metavar='PATH', help=tr('Save a readable report', language))
    parser.add_argument('--self-test', action='store_true', help=tr('Run embedded offline self-tests', language))
    parser.add_argument('--retries', type=int, choices=range(1, 5), default=preferences.get('retries', 2), help=tr('Total attempts per target/address family', language))
    parser.add_argument('--retry-mode', choices=['same-ip','rotate'], default=preferences.get('retry_mode','same-ip'), help=tr('Retry address selection: fixed IP or rotating DNS answers', language))
    parser.add_argument('--wfp-input', type=Path, help=tr('Import existing WFP XML as historical host-association context', language))
    parser.add_argument('--proxy-paths', action='store_true', help=tr('Compare direct results with up to two configured HTTP proxy paths', language))
    parser.add_argument('--confirm-proxy-paths', action='store_true', help=tr('Consent to credential-free CONNECT, TLS and HEAD proxy probes', language))
    parser.add_argument('--output-dir', type=Path, help=tr('Local output and repair journal root', language))
    parser.add_argument('--full-report', action='store_true', help=tr('Complete private output; requires --confirm-private', language))
    parser.add_argument('--confirm-private', action='store_true', help=tr('Explicitly acknowledge sensitive local data', language))
    parser.add_argument('--wfp-export', type=Path, metavar='PATH', help=tr('Private read-only WFP XML; requires --confirm-private', language))
    parser.add_argument('--snapshot', type=Path, metavar='PATH', help=tr('Save a versioned network snapshot', language))
    parser.add_argument('--snapshot-label', default='', help=tr('Snapshot label; avoid personal information', language))
    parser.add_argument('--compare', nargs=2, metavar=('BEFORE', 'AFTER'), help=tr('Compare existing snapshots without a live scan', language))
    parser.add_argument('--no-fake-ip-audit', action='store_true', default=not preferences.get('fake_ip_audit', True), help=tr('Disable optional local DNS/Fake-IP context audit', language))
    parser.add_argument('--fake-ip-audit', action='store_false', dest='no_fake_ip_audit', help=tr('Enable optional local DNS/Fake-IP context audit', language))
    parser.add_argument('--share-card', action='store_true', help=tr('Print a minimized diagnostic card (at most 500 characters); no clipboard or upload', language))
    parser.add_argument('--pmtu', action='store_true', help=tr('After repeated same-IP TLS timeouts, run optional bounded IPv4 DF ICMP probes', language))
    parser.add_argument('--confirm-pmtu', action='store_true', help=tr('Explicitly consent to optional ICMP traffic', language))
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args(arguments)
    if (args.full_report or args.wfp_export) and not args.confirm_private:
        parser.error(tr('Complete reports/WFP contain sensitive data. Add --confirm-private after review.', language))
    if args.pmtu and (not args.confirm_pmtu or args.no_network or args.compare):
        parser.error(tr('PMTU requires --confirm-pmtu and a network scan.', language))
    if args.share_card and args.compare:
        parser.error('--share-card requires a scan report')
    if args.proxy_paths and (not args.confirm_proxy_paths or args.no_network or args.compare or not args.cli):
        parser.error(tr('Proxy path probes require --cli, --confirm-proxy-paths and a network scan.', language))
    if args.wfp_input and args.compare:
        parser.error('--wfp-input requires a scan report')
    if args.output_dir:
        set_output_directory(args.output_dir)
    if args.self_test:
        self_test()
        return 0
    try:
        if args.compare:
            difference = compare_snapshots(load_snapshot(args.compare[0]), load_snapshot(args.compare[1]))
            data = difference if args.full_report else redacted_data(difference)
            text = json.dumps(data, ensure_ascii=False, indent=2)
            print(text)
            if args.json:
                target = Path(args.json)
                target.parent.mkdir(parents=True, exist_ok=True)
                atomic_write_text(target, text)
            if args.markdown:
                Path(args.markdown).parent.mkdir(parents=True, exist_ok=True)
                atomic_write_text(args.markdown, '\n'.join(['# WinNetDiff snapshot comparison', '', *markdown_code_block(text, 'json')]) + '\n')
            return 0
        context = summarize_wfp_xml(args.wfp_input) if args.wfp_input else None
        profile = args.profile or (default_profile(language) if initial.lang else preferences.get('profile') or default_profile(language))
        if not args.cli:
            # The terminal path relies on scan()'s own platform guard (same message), which
            # tests replace together with the collectors; only the GUI needs this early stop.
            if os.name != 'nt':
                raise RuntimeError(tr('實際稽核只支援 Windows 10/11；可執行 --self-test。', language))
            gui(initial_hosts=args.hosts, no_network=args.no_network, locale=language, profile=profile, retries=args.retries, fake_ip_audit=not args.no_fake_ip_audit, retry_mode=args.retry_mode, initial_wfp_context=context)
            return 0
        hosts = resolve_targets(language, profile, args.hosts)
        cancel = threading.Event()
        report = scan(hosts, not args.no_network, lambda text: None if args.share_card else print(text, flush=True), cancel,
                      args.retries, locale=language, profile=profile, fake_ip_audit=not args.no_fake_ip_audit, retry_mode=args.retry_mode,
                      **({'wfp_context': context} if context is not None else {}))
        if args.proxy_paths:
            report = with_proxy_path_evidence(report, confirmed=True, cancel=cancel)
        if args.pmtu:
            targets = pmtu_candidates(report.probes)
            if not targets:
                print(tr('No eligible repeated same-IP IPv4 TLS timeout. Run a network scan first; Fake-IP targets are skipped.', language), file=sys.stderr)
            for address in targets:
                if cancel.is_set():
                    break
                report.pmtu.append(probe_pmtu(address, confirmed=True, cancel=cancel))
        print(compact_share_card(report, language) if args.share_card else '\n' + summarize(report, full=args.full_report))
        for filename, contents in [(args.json, evidence_text(report, args.full_report)),
                                    (args.markdown, markdown_report(report, args.full_report))]:
            if filename:
                target = Path(filename)
                target.parent.mkdir(parents=True, exist_ok=True)
                atomic_write_text(target, contents)
                print(labels['saved'] + ': ' + (str(target) if args.full_report else redact(str(target))), file=sys.stderr if args.share_card else sys.stdout)
        if args.snapshot:
            save_snapshot(args.snapshot, report, label=args.snapshot_label, full=args.full_report)
            print(labels['saved'] + ': ' + (str(args.snapshot) if args.full_report else redact(str(args.snapshot))), file=sys.stderr if args.share_card else sys.stdout)
        if args.wfp_export:
            result = export_wfp(args.wfp_export, cancel=cancel)
            print(json.dumps(result if args.full_report else redacted_data(result), ensure_ascii=False, indent=2), file=sys.stderr if args.share_card else sys.stdout)
            if not result.get('ok'):
                return 1
        return 0
    except KeyboardInterrupt:
        print(labels['cancel'], file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError) as exc:
        print(labels['error'] + ': ' + redact(tr(exc, language)), file=sys.stderr)
        return 1
