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
from winnetdiff.collectors.proxy import proxy_endpoints
from winnetdiff.collectors.routes import binding_preview
from winnetdiff.collectors.security import security_findings
from winnetdiff.core.models import Finding, Probe, SEVERITIES, VIRTUAL_PATTERN
from winnetdiff.repairs.manager import proxy_repair_eligibility
from winnetdiff.analysis.evidence import assess_phase_evidence, corroborating_orphans, probe_attempts
from winnetdiff.core.messages import msg


def family_best(probes: list[Probe], family: str) -> list[Probe]:
    return [p for p in probes if p.family == family]


def analyze(proxy: dict[str, Any], routes: dict[str, Any], probes: list[Probe],
            sec: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for item in proxy.get('local_listeners', []):
        endpoint = f"{item['host']}:{item['port']}"
        refs = item.get('references', [])
        enabled = [r for r in refs if r.get('active') is True]
        if not refs:  # legacy caller compatibility, never infer an environment variable is enabled
            manual = proxy.get('wininet', {})
            enabled = [{'source': 'WinINET'}] if manual.get('ProxyEnable') == 1 and (
                item['host'], item['port']) in proxy_endpoints(manual.get('ProxyServer') or '') else []
        if item.get('accepts_tcp'):
            findings.append(Finding('資訊', '代理', msg('本機代理埠可連線：{endpoint}', endpoint=endpoint),
                f"PID={item.get('pid')}，程序={item.get('program')}；來源={refs}",
                '可連線只表示 TCP 接受連線；尚未驗證代理協定與上游連通性。', confidence='高'))
        elif enabled:
            confirmed = item.get('confirmed_dead', False)
            eligible = proxy_repair_eligibility(proxy)['eligible']
            findings.append(Finding('已確認設定異常' if confirmed else '可疑', '代理',
                msg('已啟用代理指向不可連線的本機埠：{endpoint}', endpoint=endpoint),
                f"來源={enabled}；{item.get('error')}；PID={item.get('pid')}",
                '連續拒絕連線支持代理殘留判斷；影響限於使用該代理的程式。' if confirmed else
                '連線失敗也可能由本機防火牆或逾時造成；需重試，尚不能確認客戶端已退出。',
                confidence='高' if confirmed else '中', action='disable_proxy' if eligible else 'manual_review',
                priority=0 if confirmed else 1))
        else:
            findings.append(Finding('資訊', '代理', msg('代理參照需由應用程式核對：{endpoint}', endpoint=endpoint),
                str(refs), '停用的手動設定不影響連線；環境變數只有在應用程式採用且未被 NO_PROXY 排除時才生效。', confidence='高'))
    wininet = proxy.get('wininet', {})
    if wininet.get('AutoConfigURL'):
        findings.append(Finding('資訊', '代理', '存在 PAC 自動代理設定', str(wininet['AutoConfigURL']),
                                proxy.get('pac_note', '未執行 PAC，請核對使用範圍。'), confidence='高'))
    for scope in ('user', 'machine', 'process'):
        env = proxy.get('environ_' + scope, {})
        if env.get('NODE_OPTIONS'):
            findings.append(Finding('資訊', '代理', msg('Node.js 啟動選項（{scope}）', scope=scope), str(env['NODE_OPTIONS']),
                '選項的支援情況取決於 Node.js 版本；與 HTTP_PROXY、HTTPS_PROXY、NO_PROXY 一起核對。'))

    defaults = routes.get('defaults_ipv4', [])
    status = routes.get('query_status', {})
    if not defaults:
        unknown = bool(routes.get('errors')) or status.get('routes') not in (None, 'ok')
        findings.append(Finding('資訊' if unknown else '高優先級', '路由',
            'IPv4 預設路由狀態未知' if unknown else '未找到 IPv4 預設路由', str(routes.get('errors') or '0.0.0.0/0 absent'),
            '查詢不完整，不能當作設定不存在。' if unknown else '外網通路可能受限；仍需檢查 VPN 的 /1 分流路由和更具體的目標路由。',
            confidence='低' if unknown else '中'))
    active_defaults = [r for r in defaults if str(r.get('ConnectionState', 'Connected')) in ('Connected', '1')]
    if len(active_defaults) > 1:
        ranked = sorted(active_defaults, key=lambda r: r.get('EffectiveMetric') if r.get('EffectiveMetric') is not None else 10**9)
        top = ranked[0]
        adapter = next((a for a in routes.get('adapters', []) if a.get('ifIndex') == top.get('InterfaceIndex')), {})
        virtual = adapter.get('Classification') == 'virtual' or bool(VIRTUAL_PATTERN.search(str(top.get('InterfaceAlias', ''))))
        findings.append(Finding('可疑' if virtual else '資訊', '路由', '存在多條活動 IPv4 預設路由',
            json.dumps(ranked, ensure_ascii=False),
            '同樣前綴長度下最低路由加介面躍點指向虛擬網卡，請核對 VPN 狀態；這可能符合預期。' if virtual else
            '同前綴路由按 RouteMetric + InterfaceMetric 選擇；完整路由表也包含更具體的 VPN 路由。', confidence='中'))
    for binding in routes.get('bindings', []):
        component = str(binding.get('ComponentID', ''))
        if component.lower().startswith('ms_') or binding.get('Classification') == 'windows':
            continue
        known = binding.get('Classification') == 'known-third-party' or bool(re.search(r'vbox|virtualbox|npcap|npf|vmware|docker', str(binding), re.I))
        related = [e for e in sec.get('evidence', []) if e.get('Status') in ('orphan_candidate', 'registration_missing')
                   and any(token.lower() in str(binding).lower() for token in [str(e.get('Name', ''))] if len(token) > 3)]
        preview = binding_preview(binding)
        findings.append(Finding('高優先級' if related and binding.get('Enabled') else '資訊' if known else '可疑', '路由',
            msg('已知第三方 綁定：{name} / {component}' if known else '待核對第三方 綁定：{name} / {component}', name=binding.get('Name'), component=component),
            json.dumps({'binding': binding, 'related_orphan_evidence': related}, ensure_ascii=False),
            '名稱命中不代表故障。核對軟體用途、發布者及物理 WLAN 綁定；只允許單項人工隔離測試。',
            [preview['disable']] if preview.get('eligible') else [], preview.get('restore', ''),
            confidence='中' if related else '低', action='manual_binding_review'))

    v4good = {p.host for p in probes if p.family == 'IPv4' and p.stage == 'http_ok'}
    v6good = {p.host for p in probes if p.family == 'IPv6' and p.stage == 'http_ok'}
    v6bindings = routes.get('ipv6_bindings', [])
    physical_names = {a.get('Name') for a in routes.get('adapters', []) if a.get('Classification') == 'physical' and str(a.get('Status')).lower() == 'up'}
    relevant_bindings = [b for b in v6bindings if b.get('Name') in physical_names] if physical_names else v6bindings
    disabled = bool(relevant_bindings) and all(not b.get('Enabled') for b in relevant_bindings)
    v6query_ok = status.get('routes', 'ok') == 'ok' and status.get('bindings', 'ok') == 'ok'
    mismatch_hosts = v4good - v6good
    if mismatch_hosts and any(p.family == 'IPv6' and p.host in mismatch_hosts for p in probes):
        if disabled and v6query_ok:
            findings.append(Finding('資訊', 'IPv4/IPv6', '活動介面的 IPv6 未啟用', str(relevant_bindings),
                'IPv4 正常；停用狀態本身不判為故障，未建議永久停用 IPv6。', confidence='高'))
        elif not routes.get('defaults_ipv6') and v6query_ok:
            findings.append(Finding('資訊', 'IPv4/IPv6', 'IPv4 正常，IPv6 無預設路由', str(routes.get('ipv6_addresses', [])),
                '這可表示目前網路只提供 IPv4。仍需考慮更具體的 IPv6 路由；不能僅因探針失敗判定系統故障。', confidence='中'))
        elif not v6query_ok:
            findings.append(Finding('資訊', 'IPv4/IPv6', 'IPv6 組態查詢不完整', str(routes.get('errors')),
                '先補齊路由與綁定證據，再判斷 IPv6 是否可用。', confidence='低'))
        else:
            for p in probes:
                if p.family == 'IPv6' and p.host in mismatch_hosts and p.stage != 'http_ok':
                    findings.append(Finding('可疑', 'IPv4/IPv6', msg('IPv4 正常，IPv6 停在 {stage}', stage=p.stage),
                        f'{p.host}: {p.error}', '同網域雙棧結果不同；先檢查 IPv6 路由、MTU 與上游。用本工具重試，不預設修改 IPv6 綁定。', confidence='中'))
    if probes and not v4good and not v6good:
        findings.append(Finding('可疑', 'IPv4/IPv6', '兩種協定均未取得有效 HTTP 回應',
            '; '.join(f'{p.host} {p.family} {p.stage}' for p in probes),
            '此輪結果只適用於列出的目標及時間；檢查 DNS、階段錯誤及目標策略。', confidence='中'))

    attempts = probe_attempts(probes)
    orphan = corroborating_orphans(sec, routes)
    tls_assessment = assess_phase_evidence(probes, {'tls_timeout'}, corroboration=orphan)
    tls_timeouts = tls_assessment['attempts']
    if tls_timeouts:
        corroborated = tls_assessment['grade'] == 'E3'
        findings.append(Finding('高優先級' if corroborated else '可疑', 'TCP/TLS',
            '同一連線 TCP 成功但 TLS 交握逾時' + ('，伴隨孤兒元件證據' if orphan else ''),
            json.dumps(tls_assessment, ensure_ascii=False),
            '優先調查 WFP/NDIS 網路過濾、安全軟體及 VPN 殘留；多目標持續異常並伴隨孤兒驅動會提高優先級。'
            '仍需排查 MTU、伺服器與 TLS 中間設備，尚未證明核心死鎖。',
            ['driverquery /v /fo csv', 'netsh wfp show state file=wfpstate.xml'],
            '以上唯讀；WFP 匯出可能包含敏感資料。', confidence='中', action='manual_driver_review',
            priority=0 if corroborated else 1, evidence_grade=tls_assessment['grade']))
    for stage, title, explanation in [
        ('tcp_timeout', 'TCP 建連逾時', '失敗發生在 TLS 前；檢查路由、防火牆及目標可達性。'),
        ('tcp_error', 'TCP 建連錯誤', '檢查錯誤碼、路由與目標服務。'),
        ('tls_cert_error', 'TLS 憑證驗證失敗', '檢查時間、信任鏈及 HTTPS 檢查；保留憑證驗證。'),
        ('tls_error', 'TLS 協定錯誤', '核對 TLS 協定、目標政策和中間設備。'),
        ('http_timeout', 'TLS 成功但 HTTP 回應逾時', 'TLS 已完成；調查應用程式、伺服器及內容過濾。'),
        ('http_error', 'HTTP 回應錯誤', '核對回應格式及應用層連線。'),
        ('http_protocol_error', 'HTTP 狀態列無效', 'TLS 已完成，但未收到完整合法的 HTTP 狀態列。'),
        ('http_empty', 'TLS 後伺服器未回應 HTTP', '遠端關閉連線；不當作 HTTP 成功。'),
        ('dns_error', 'DNS 未解析出目標位址', '核對解析錯誤、網域記錄和本機 DNS；不等同於路由故障。'),
        ('dns_timeout', 'DNS 解析逾時', '系統解析器逾時；本輪未進入 TCP。'),
        ('overall_timeout', '探針整體時間預算耗盡', '本次測量因總時間限制停止；未證明 TCP、TLS 或 HTTP 自身逾時，請按相同設定重測或調整整體預算。')]:
        selected = [a for a in attempts if a.get('stage') == stage]
        if selected:
            unavailable_ipv6 = (stage in ('dns_error', 'dns_timeout', 'tcp_error', 'tcp_timeout')
                and v6query_ok and (disabled or not routes.get('defaults_ipv6'))
                and all(a.get('family') == 'IPv6' and a.get('host') in v4good for a in selected))
            findings.append(Finding('資訊' if unavailable_ipv6 or stage == 'overall_timeout' else '可疑', 'TCP/TLS', title,
                json.dumps(selected, ensure_ascii=False), explanation +
                (' 此網路未提供可用的 IPv6 預設通路或相關綁定未啟用，IPv4 正常；本項不判定為系統故障。' if unavailable_ipv6 else ''), confidence='高',
                evidence_grade='E1' if stage == 'overall_timeout' else assess_phase_evidence(probes, {stage},
                    corroboration=orphan if stage in ('tls_error', 'tls_cert_error') else None)['grade']))
    for p in probes:
        if p.intermittent:
            findings.append(Finding('可疑', 'TCP/TLS', '重試結果不一致', json.dumps(p.attempts, ensure_ascii=False),
                '此輪有成功與失敗交替，亦可能是目標 IP 差異；保留每次位址和階段，需追加時間序列驗證。', confidence='中'))
        if p.http_status and p.http_status >= 400:
            findings.append(Finding('資訊', 'TCP/TLS', msg('HTTP 回應狀態 {status}', status=p.http_status), p.host + ' ' + p.http_line,
                'TCP 和 TLS 已成功，狀態碼代表應用層回應；不能據此宣告所有網路功能正常。', confidence='高'))
    findings.extend(security_findings(sec))
    for layer, data in [('代理', proxy), ('路由', routes), ('安全/驅動', sec)]:
        if data.get('errors'):
            findings.append(Finding('資訊', layer, '部分檢查未完成', '\n'.join(map(str, data['errors'])),
                '查詢失敗或權限不足均保留為未知；需要時由使用者主動申請管理員權限後重試。', confidence='低'))
    if not findings:
        findings.append(Finding('資訊', '綜合', '未發現明確異常', '本輪可用證據未觸發規則',
            '不排除間歇性故障、特定程式代理或需要封包擷取的問題。', confidence='中'))
    return sorted(findings, key=lambda f: (SEVERITIES.get(f.severity, 3), f.priority))
