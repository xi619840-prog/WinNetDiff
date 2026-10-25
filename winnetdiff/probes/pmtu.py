"""Opt-in, bounded IPv4 DF Echo evidence; never diagnoses a PMTUD black hole."""
from __future__ import annotations
import datetime as dt
import ipaddress
import math
import re
import threading
import time
from typing import Any
from ..core.process import run_command
from ..analysis.evidence import assess_phase_evidence
from ..collectors.dns_audit import is_fake_ip
from ..core.i18n import tr

PMTU_LIMITATION = 'ICMP Echo may be filtered and may follow a different policy from TLS. Fragmentation Needed means feedback arrived; neither silence nor size differences prove a PMTUD black hole. No MTU, MSS or registry setting was changed.'
PMTU_STATUS_TEXT = {
    'mtu_limited_feedback_present': 'A tested size exceeded the path limit; ICMP feedback arrived.',
    'size_or_icmp_inconclusive': 'Size-dependent silence or ICMP filtering; MTU cause unconfirmed.',
    'icmp_no_result': 'No ICMP result; the target may filter Echo.',
    'tested_sizes_replied': 'All tested payload sizes received Echo replies.',
    'unreachable': 'The local host or route reported unreachable.',
    'permission_denied': 'The probe was denied permission.',
    'cancelled': 'The auxiliary probe was cancelled.',
    'overall_timeout': 'The auxiliary probe exhausted its time budget.',
    'inconclusive': 'Auxiliary evidence is inconclusive.',
}


def pmtu_summary(result, locale='en'):
    lines = [tr(PMTU_STATUS_TEXT.get(result.get('status'), 'Auxiliary evidence is inconclusive.'), locale)]
    for sample in result.get('samples', []):
        lines.append(tr('ICMP payload {payload} B; estimated IPv4 packet {packet} B: {status}', locale,
                        payload=sample['payload_bytes'], packet=sample['estimated_ipv4_packet_bytes'], status=sample['status']))
    lines.append(tr(PMTU_LIMITATION, locale))
    return '\n'.join(lines)


def parse_ping_result(result: dict[str, Any]) -> str:
    text = str(result.get('stdout', '')) + '\n' + str(result.get('stderr', ''))
    if re.search(r'(?i)needs? to be fragment|fragmentation needed|需要(?:拆分|分片|分段)|必須(?:分割|分段)|需要分割|需(?:要)?片段', text):
        return 'fragmentation_needed'
    if re.search(r'(?i)access (?:is )?denied|permission denied|requires elevation|拒[絕绝](?:存取|访问)|權限不足|权限不足', text):
        return 'permission_denied'
    if re.search(r'(?i)unreachable|general failure|transmit failed|無法連線|无法访问|无法传输|一般故障|常見失敗|一般失敗|目的地主機無法連線|网络不可达', text):
        return 'unreachable'
    # TTL is present in actual IPv4 Echo replies, including Chinese Windows.
    # The process exit code alone cannot establish an Echo reply.
    if re.search(r'(?i)\bTTL\s*[=:]\s*\d+', text):
        return 'echo_reply'
    if result.get('timed_out') or re.search(r'(?i)timed? out|request timeout|請求等候逾時|要求等候逾時|请求超时|要求逾時', text):
        return 'icmp_timeout'
    if result.get('returncode') is None:
        return 'execution_error'
    return 'unrecognized'


def classify_pmtu(samples: list[dict[str, Any]]) -> str:
    if not samples:
        return 'not_tested'
    statuses = {s['status'] for s in samples}
    if 'permission_denied' in statuses:
        return 'permission_denied'
    if 'fragmentation_needed' in statuses:
        return 'mtu_limited_feedback_present'
    replies = [s['payload_bytes'] for s in samples if s['status'] == 'echo_reply']
    timeouts = [s['payload_bytes'] for s in samples if s['status'] == 'icmp_timeout']
    if replies and timeouts and max(timeouts) > min(replies):
        return 'size_or_icmp_inconclusive'
    if statuses == {'echo_reply'}:
        return 'tested_sizes_replied'
    if statuses <= {'icmp_timeout'}:
        return 'icmp_no_result'
    if 'unreachable' in statuses:
        return 'unreachable'
    return 'inconclusive'


def pmtu_candidates(probes: list[Any]) -> list[str]:
    evidence = assess_phase_evidence(probes, {'tls_timeout'})
    candidates = []
    for path in evidence['persistent_paths']:
        address = path['ip']
        if path['family'] == 'IPv4' and not is_fake_ip(address) and address not in candidates:
            candidates.append(address)
    return candidates[:2]


def probe_pmtu(address: str, *, confirmed: bool = False, payload_sizes=(1200, 1472), retries=1,
               timeout_ms=800, overall_timeout=4.0, cancel: threading.Event | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {'address': address, 'tested': False, 'status': 'not_tested', 'samples': [],
                              'limitation': PMTU_LIMITATION, 'blackhole_confirmed': False, 'measured_at': dt.datetime.now().astimezone().isoformat(timespec='seconds')}
    if confirmed is not True:
        return {**result, 'status': 'consent_required'}
    try:
        target = ipaddress.ip_address(address)
    except ValueError:
        return {**result, 'status': 'invalid_address'}
    if target.version != 4:
        return {**result, 'status': 'ipv6_not_supported'}
    if target.is_multicast or target.is_unspecified or is_fake_ip(address):
        return {**result, 'status': 'unsuitable_target'}
    if (type(retries) is not int or not 1 <= retries <= 2 or type(timeout_ms) is not int or not 100 <= timeout_ms <= 2000 or
            not isinstance(overall_timeout, (int, float)) or isinstance(overall_timeout, bool) or not math.isfinite(overall_timeout) or not 0.1 <= overall_timeout <= 10):
        raise ValueError('Invalid PMTU time/retry budget')
    sizes = tuple(payload_sizes)
    if not 1 <= len(sizes) <= 4 or any(type(s) is not int or not 32 <= s <= 65000 for s in sizes):
        raise ValueError('Invalid PMTU ICMP payload sizes')
    started = time.perf_counter()
    deadline = started + overall_timeout
    stopped = ''
    for size in sorted(set(sizes)):
        for index in range(retries):
            if cancel and cancel.is_set():
                stopped = 'cancelled'; break
            remaining = deadline - time.perf_counter()
            if remaining <= 0.05:
                stopped = 'overall_timeout'; break
            wait_ms = min(timeout_ms, max(1, int(remaining * 1000)))
            command = ['ping.exe', '-4', '-f', '-l', str(size), '-n', '1', '-w', str(wait_ms), str(target)]
            # Each command is bounded too. Cancellation is checked between
            # commands, at most one <=2.4-second ping wait from this boundary.
            response = run_command(command, timeout=min(remaining, wait_ms / 1000 + 0.4))
            result['samples'].append({'payload_bytes': size, 'estimated_ipv4_packet_bytes': size + 28,
                'attempt': index + 1, 'status': parse_ping_result(response), 'command': command,
                'response': response})
            if cancel and cancel.is_set():
                stopped = 'cancelled'; break
            if time.perf_counter() >= deadline:
                stopped = 'overall_timeout'; break
        if stopped:
            break
    result.update(tested=bool(result['samples']), status=stopped or classify_pmtu(result['samples']),
                  elapsed_ms=round((time.perf_counter()-started)*1000, 1), configured_overall_seconds=overall_timeout)
    if cancel and cancel.is_set():
        result['status'] = 'cancelled'
    return result
