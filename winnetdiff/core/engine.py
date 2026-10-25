from __future__ import annotations
import argparse
import base64
import codecs
import concurrent.futures
import contextvars
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
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Optional
if os.name == 'nt':
    import winreg
else:
    winreg = None
from winnetdiff.analysis.rules import analyze
from winnetdiff.collectors.proxy import collect_proxy
from winnetdiff.collectors.routes import collect_routes
from winnetdiff.collectors.security import collect_security
from winnetdiff.core.models import Probe, Report, SEVERITIES, VERSION
from winnetdiff.core.windows import is_admin
from winnetdiff.probes.transport import probe_host_family
from winnetdiff.analysis.ownership import associate_hosts, ownership_findings
from winnetdiff.probes.proxy_path import diagnose_proxy_paths, proxy_path_findings
from winnetdiff.core.config import normalize_language
from winnetdiff.core.i18n import set_language, tr
from winnetdiff.analysis.scenarios import evaluate_scenarios
from winnetdiff.analysis.evidence import EVIDENCE_GRADES
from winnetdiff.collectors.dns_audit import collect_dns_runtime, audit_dns_state
from winnetdiff.analysis.dns_rules import fake_ip_findings


def layer_overview(report: Report) -> dict[str, Any]:
    result = {}
    for name in ('代理', '路由', 'IPv4/IPv6', 'TCP/TLS', '安全/驅動'):
        items = [f for f in report.findings if f.layer == name]
        result[name] = {'status': '待核對' if any(SEVERITIES.get(f.severity, 3) < 3 for f in items) else '已稽核',
                        'confidence': '低' if any(f.confidence == '低' for f in items) else '中',
                        'evidence': [asdict(f) for f in items]}
        result[name]['interpretation'] = '依目前可用證據判讀；未完成查詢保留未知。'
        result[name]['suggested_action'] = '檢視原始證據；有異常時依逐項建議確認，修復後重新驗證。'
        if any(f.title == '部分檢查未完成' for f in items):
            result[name]['status'] = '檢查未完成'
        if report.cancelled:
            result[name]['status'] = '已取消，證據不完整'
    if not report.probes and not report.cancelled:
        for name in ('IPv4/IPv6', 'TCP/TLS'):
            result[name]['status'] = '未執行主動探針'
    result['代理']['raw_evidence'] = {**report.proxy, 'path_diagnosis': report.proxy_paths}
    result['路由']['raw_evidence'] = {k: report.route.get(k) for k in ('adapters', 'interfaces', 'routes', 'bindings', 'binding_components', 'metadata_errors', 'errors')}
    result['路由']['raw_evidence']['dns_audit'] = report.dns_audit
    result['IPv4/IPv6']['raw_evidence'] = {k: report.route.get(k) for k in ('ipv6_addresses', 'defaults_ipv6', 'ipv6_bindings')}
    result['IPv4/IPv6']['raw_evidence']['probes'] = [asdict(p) for p in report.probes]
    result['TCP/TLS']['raw_evidence'] = [asdict(p) for p in report.probes]
    result['安全/驅動']['raw_evidence'] = {k: report.security.get(k) for k in ('antivirus_products', 'evidence', 'ownership', 'completeness', 'errors')}
    return result


# Host/family pairs are independent measurements; each keeps its own sequential
# attempts on one connection per attempt. Running pairs concurrently bounds the
# worst case by the slowest pair instead of the sum (3 hosts x 2 families x 35 s
# overall budget was up to 210 s on a network that drops TLS). Resolver waits
# for slots are budgeted in timeout_dns and excluded from reported DNS time.
PROBE_CONCURRENCY = 6


def _association_context(context: dict | None) -> dict:
    # Raw XML samples/matches may repeat private GUIDs or arbitrary detail.
    # Retain only fields consumed by the typed ownership mapper. The caller's
    # original XML remains private and is never copied into the scan report.
    return {key: context[key] for key in ('ownership_records','ownership_truncated','counts','bytes','cancelled')
            if key in context} if context else {}


def with_proxy_path_evidence(report: Report, *, confirmed=False, cancel=None) -> Report:
    if not report.scan_options.get('do_network'):
        raise ValueError('Proxy path testing requires an online scan')
    context = diagnose_proxy_paths(report.proxy, report.probes, report.hosts[0], confirmed=confirmed, cancel=cancel)
    updated = replace(report, proxy_paths=context,
        findings=[f for f in report.findings if not f.code.startswith('proxy.paths.')] + proxy_path_findings(context))
    updated.findings.sort(key=lambda f: (SEVERITIES.get(f.severity, 3), f.priority))
    updated.layers = layer_overview(updated)
    return updated


def with_wfp_context(report: Report, context: dict) -> Report:
    context = _association_context(context)
    security = {**report.security, 'wfp_context': context}
    security['ownership'] = associate_hosts(security, report.route, context)
    updated = replace(report, security=security, findings=[f for f in report.findings if not f.code.startswith('ownership.')]
        + ownership_findings(security['ownership'], security.get('evidence')))
    updated.findings.sort(key=lambda f: (SEVERITIES.get(f.severity, 3), f.priority))
    updated.layers = layer_overview(updated)
    return updated


def run_probes(hosts: list[str], retries: int, cancel: threading.Event,
               progress: Callable[[str], None], retry_mode: str = 'same-ip') -> list[Probe]:
    """Probe every host/family pair concurrently; results keep host, IPv4, IPv6 order."""
    tasks = [(host, family, label) for host in hosts
             for family, label in [(socket.AF_INET, 'IPv4'), (socket.AF_INET6, 'IPv6')]]
    if not tasks:
        return []
    progress_lock = threading.Lock()

    def measure(host: str, family: int, label: str) -> Optional[Probe]:
        if cancel.is_set():
            return None  # Not started: absent, exactly like the former sequential loop.
        with progress_lock:
            progress(f'[3/5] {host} {label} DNS → TCP → TLS → HTTP…')
        try:
            return probe_host_family(host, family, retries=retries, cancel=cancel, retry_mode=retry_mode)
        except Exception as exc:
            return Probe(host, label, stage='probe_error', error=f'{type(exc).__name__}: {exc}')

    workers = max(1, min(PROBE_CONCURRENCY, len(tasks)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix='network-probe') as pool:
        # Each task runs in a copy of the caller's context so the UI language follows it.
        futures = [pool.submit(contextvars.copy_context().run, measure, *task) for task in tasks]
        results = [future.result() for future in futures]
    return [probe for probe in results if probe is not None]


def scan(hosts: list[str], do_network: bool = True, progress: Callable[[str], None] = lambda _: None,
         cancel: Optional[threading.Event] = None, retries: int = 2, locale: str = 'en',
         profile: Optional[str] = None, fake_ip_audit: bool = False,
         retry_mode: str = 'same-ip', wfp_context: dict | None = None) -> Report:
    if retry_mode not in ('same-ip', 'rotate'):
        raise ValueError('retry_mode must be same-ip or rotate')
    locale = set_language(locale)
    notify = progress
    progress = lambda text: notify(tr(text, locale))
    if os.name != 'nt':
        raise RuntimeError('實際稽核只支援 Windows 10/11；可執行 --self-test。')
    cancel = cancel or threading.Event()
    def collect(label: str, function: Callable) -> dict[str, Any]:
        progress(label)
        if cancel.is_set():
            return {'errors': ['cancelled: check not run']}
        try:
            return function(cancel=cancel)
        except Exception as exc:
            return {'errors': [f'{type(exc).__name__}: {exc}']}
    proxy = collect('[1/5] WinINET / WinHTTP / 環境代理及本機埠…', collect_proxy)
    routes = collect('[2/5] 路由、網卡及完整 NDIS 綁定…', collect_routes)
    probes = []
    if do_network:
        probes = run_probes(hosts, retries, cancel, progress, retry_mode=retry_mode)
    else:
        progress('[3/5] 已略過遠端探針，繼續本機稽核。')
    sec = collect('[4/5] 安全中心、服務、驅動與軟體歸屬…', collect_security)
    sec['wfp_context'] = _association_context(wfp_context)
    sec['ownership'] = associate_hosts(sec, routes, sec['wfp_context'])
    for binding in routes.get('bindings', []):
        service = str(binding.get('OwnerEvidence', {}).get('Service') or '').lower()
        if service:
            owners = [e for e in sec.get('evidence', []) if str(e.get('Name', '')).lower() == service]
            binding['OwnerEvidence']['SecurityCorrelation'] = owners
            for owner in owners:
                metadata = owner.get('File', {})
                if metadata.get('CompanyName'):
                    binding['OwnerEvidence']['ProviderName'] = metadata['CompanyName']
                if metadata.get('ProductName'):
                    binding['OwnerEvidence']['ProductName'] = metadata['ProductName']
    dns_context = {'enabled': False, 'network_tested': False}
    if fake_ip_audit:
        progress('Optional DNS/Fake-IP inventory...')
        try:
            runtime = collect_dns_runtime(routes, cancel=cancel)
            dns_context = audit_dns_state(routes, probes, runtime, network_tested=do_network and not cancel.is_set())
        except Exception as exc:
            dns_context = {'enabled': True, 'network_tested': do_network, 'errors': [f'{type(exc).__name__}: {exc}']}
    progress('[5/5] 交叉比對證據及產生報告…')
    report = Report(VERSION, dt.datetime.now().astimezone().isoformat(timespec='seconds'),
        platform.platform(), is_admin(), hosts, proxy, routes, probes, sec, analyze(proxy, routes, probes, sec),
        ['TCP/TLS/HTTP 於每次嘗試共用一個目標 IP 與同一條連線；原生 socket 探針不採用系統或環境代理。',
         '環境代理、PAC/WPAD 及應用程式內建代理可能與本工具直接連線結果不同；不執行 PAC。',
         'TLS 逾時不能證明核心死鎖，WFP/NDIS 元件也不能僅憑名稱判定故障。',
         '卸載清單不涵蓋所有可攜式或企業部署軟體；孤兒判斷為候選，需人工核對歸屬。',
         '取消會在目前命令或 socket 階段的有界逾時後生效；系統 DNS 執行緒不可強制終止，數量有上限。',
         '本機檢查可能需要管理員權限；權限失敗不等於設定不存在。',
         '修復必須由使用者確認；DNS 快取為暫態資料，無逐筆回復功能。',
         '預設報告會遮蔽憑證、使用者路徑與 IP；完整報告和回復備份只供本機保管。'],
        cancelled=cancel.is_set(), locale=locale,
        scan_options={'hosts': list(hosts), 'do_network': do_network, 'retries': retries, 'profile': profile, 'fake_ip_audit': fake_ip_audit, 'retry_mode': retry_mode}, dns_audit=dns_context)
    report.proxy_paths = diagnose_proxy_paths(proxy, probes, hosts[0]) if hosts else {}
    report.findings.extend(proxy_path_findings(report.proxy_paths))
    report.findings.extend(ownership_findings(sec['ownership'], sec.get('evidence')))
    report.findings.extend(fake_ip_findings(dns_context))
    report.findings.sort(key=lambda f: (SEVERITIES.get(f.severity, 3), f.priority))
    import hashlib
    alternatives = {
        '代理': ['The application may ignore this proxy, or use PAC, NO_PROXY or another proxy stack.'],
        '路由': ['The virtual route or binding may be intentional; more-specific routes take precedence.'],
        'IPv4/IPv6': ['The network may offer one address family only; destination policies and DNS records may differ.'],
        'TCP/TLS': ['Destination outages, MTU problems, middleboxes and intermittent path loss remain possible.'],
        '安全/驅動': ['A shared SDK, portable application or enterprise deployment may own the component.'],
    }
    for finding in report.findings:
        finding.code = finding.code or 'observation.' + hashlib.sha256((finding.layer + '|' + finding.title.split('：')[0]).encode()).hexdigest()[:12]
        finding.reasoning = finding.interpretation
        finding.alternatives = finding.alternatives or alternatives.get(finding.layer, ['Incomplete evidence may leave other causes unresolved.'])
        finding.conditions = ['Applies to the recorded targets, timestamp and completed queries only.']
        finding.verification = finding.verification or list(finding.commands) or ['Repeat the same-target scan and compare the relevant configuration or protocol stage.']
        finding.risk = 'low_reversible' if finding.action == 'disable_proxy' else 'manual_review' if finding.commands else 'read_only'
        # Rule priority controls review order; it is not evidence. The rules and
        # scenarios use the same explicit path/repetition/corroboration contract.
        if finding.evidence_grade not in EVIDENCE_GRADES:
            finding.evidence_grade = 'E1'
    report.scenarios = evaluate_scenarios(report)
    report.layers = layer_overview(report)
    return report
