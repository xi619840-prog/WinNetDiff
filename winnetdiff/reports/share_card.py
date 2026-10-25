"""Minimized public card: fixed labels/enums/numbers only, no raw report text."""
from __future__ import annotations
import math
import re
from ..core.models import VERSION

CARD_TEXT = {
    'en': {'title':'diagnostic card', 'layers':('Proxy','Route','IP','TCP/TLS','Security'),
           'states':('checked','review','incomplete','not tested','cancelled','unknown'),
           'offline':'Probes: not run', 'limits':'Limited evidence; correlation is not causation. Review before sharing.',
           'hypotheses':('Local proxy refused','Virtual route review','IPv6 mismatch','TCP succeeds / TLS fails',
                         'TLS succeeds / HTTP stalls','DNS resolves / TCP fails','Component ownership review',
                         'Security providers review','NDIS ownership review','Fake-IP route suspect')},
    'zh-CN': {'title':'精简诊断卡', 'layers':('代理','路由','IP','TCP/TLS','安全'),
           'states':('已查','待核对','未完成','未测试','已取消','未知'),
           'offline':'探针：未执行', 'limits':'证据有限，相关不代表因果。分享前请审阅。',
           'hypotheses':('本地代理拒绝连接','虚拟路由待核对','IPv6 差异','TCP 成功／TLS 失败',
                         'TLS 成功／HTTP 未返回','DNS 解析／TCP 失败','组件归属待核对',
                         '安全提供者待核对','NDIS 归属待核对','疑似 Fake-IP 残留')},
    'zh-TW': {'title':'精簡診斷卡', 'layers':('代理','路由','IP','TCP/TLS','安全'),
           'states':('已查','待核對','未完成','未測試','已取消','未知'),
           'offline':'探針：未執行', 'limits':'證據有限，相關不代表因果。分享前請審閱。',
           'hypotheses':('本機代理拒絕連線','虛擬路由待核對','IPv6 差異','TCP 成功／TLS 失敗',
                         'TLS 成功／HTTP 未返回','DNS 解析／TCP 失敗','元件歸屬待核對',
                         '安全提供者待核對','NDIS 歸屬待核對','疑似 Fake-IP 殘留')},
}
CARD_SCENARIO_CODES = ('stale_local_proxy','virtual_default_route','ipv6_reachability_mismatch',
    'tcp_ok_tls_failure','tls_ok_http_timeout','dns_ok_connect_unreachable','orphaned_service_or_driver',
    'multiple_security_providers','ndis_binding_corroborated','dns.fake_ip_unroutable_suspected')
CARD_LAYER_KEYS = (('代理','Proxy'),('路由','Route'),('IPv4/IPv6','IPv4/IPv6'),('TCP/TLS','TCP/TLS'),('安全/驅動','Security/drivers'))
CARD_STATUS_GROUPS = (
    {'已稽核','已审核','Audited','Checked'}, {'待核對','待核对','Needs review'},
    {'檢查未完成','检查未完成','Incomplete checks'}, {'未執行主動探針','未执行主动探针','Active probes not run'},
    {'已取消，證據不完整','已取消，证据不完整','Cancelled; incomplete evidence'},
)
CARD_STAGE_ALLOWLIST = frozenset({'http_ok','http_timeout','http_error','http_empty','http_protocol_error',
    'tls_ok','tls_timeout','tls_error','tls_cert_error','tcp_ok','tcp_timeout','tcp_error',
    'dns_error','dns_timeout','overall_timeout','cancelled','probe_error','unrun'})


def _card_field(value, key, default=None):
    return value.get(key, default) if isinstance(value, dict) else getattr(value, key, default)


def _card_time(value):
    if type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= 600000:
        return '-'
    return str(round(value))


def compact_share_card(report, locale=None):
    locale = locale or _card_field(report, 'locale', 'en')
    labels = CARD_TEXT.get(locale, CARD_TEXT['en'])
    version = _card_field(report, 'version', VERSION)
    if not isinstance(version, str) or not re.fullmatch(r'\d{1,4}(?:\.\d{1,4}){2,3}(?:[abrc]+\d{1,4})?', version):
        version = VERSION
    lines = ['### WinNetDiff v' + version + ' ' + labels['title']]
    layers = _card_field(report, 'layers', {})
    statuses = []
    for name, keys in zip(labels['layers'], CARD_LAYER_KEYS):
        layer = next((layers[k] for k in keys if k in layers), {})
        raw = _card_field(layer, 'status', '')
        index = next((i for i, values in enumerate(CARD_STATUS_GROUPS) if isinstance(raw, str) and raw in values), 5)
        statuses.append(name + ':' + labels['states'][index])
    lines.append('- ' + '; '.join(statuses))
    footer = ['> ' + labels['limits'], 'WinNetDiff / Alden / MIT']
    candidates = []
    for scenario in list(_card_field(report, 'scenarios', [])) + list(_card_field(report, 'findings', [])):
        code = _card_field(scenario, 'code')
        high = _card_field(scenario, 'priority') in ('high', 0, 1)
        grade = _card_field(scenario, 'grade', _card_field(scenario, 'evidence_grade', 'E1'))
        if code in CARD_SCENARIO_CODES and high and grade in ('E1','E2','E3'):
            text = '- ' + labels['hypotheses'][CARD_SCENARIO_CODES.index(code)] + ' [' + grade + ']'
            if text not in candidates:
                candidates.append(text)
    for hypothesis in candidates[:2]:
        if len('\n'.join(lines+[hypothesis]+footer)) <= 500:
            lines.append(hypothesis)
    probes = _card_field(report, 'probes', [])
    if not probes:
        lines.append('- ' + labels['offline'])
    for probe in probes[:3]:
        family, stage = _card_field(probe, 'family'), _card_field(probe, 'stage')
        family = family if family in ('IPv4','IPv6') else '?'
        stage = stage if isinstance(stage, str) and stage in CARD_STAGE_ALLOWLIST else 'unknown'
        timing = '/'.join(_card_time(_card_field(probe, key)) for key in ('dns_ms','tcp_ms','tls_ms','http_ms'))
        line = '- ' + family + ' D/T/L/H=' + timing + ' ms; ' + stage
        if len('\n'.join(lines+[line]+footer)) <= 500:
            lines.append(line)
    card = '\n'.join(lines+footer)
    # Every variable part is a bounded enum/number/version. Trim complete lines
    # only if a future catalog expansion exceeds the public compact contract.
    while len(card) > 500 and len(lines) > 1:
        lines.pop()
        card = '\n'.join(lines+footer)
    if len(card) > 500:
        raise ValueError('Card catalog exceeds compact character budget')
    return card
