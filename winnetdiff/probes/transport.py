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
from winnetdiff.core.models import Probe, VERSION


DNS_RESOLVER_SLOTS = 4
_DNS_SLOTS = threading.BoundedSemaphore(DNS_RESOLVER_SLOTS)


def timeout_dns(host: str, family: int, timeout: float = 6,
                cancel: threading.Event | None = None) -> tuple[list[Any], str, float]:
    """Bound GUI wait and abandoned OS resolvers; never create unlimited threads.

    Concurrent probes may briefly wait for a free resolver slot. The wait counts
    against this DNS budget, but the returned duration starts when resolution
    starts, so local contention is never reported as resolver latency. DNSBusy
    means no slot freed within the budget (earlier resolvers are still blocked).
    """
    started = time.perf_counter()
    deadline = started + max(0.001, timeout)
    if cancel is not None and cancel.is_set():
        return [], "Cancelled: 已取消 DNS 查詢", 0.0
    slots = _DNS_SLOTS  # Release exactly the semaphore that was acquired.
    while not slots.acquire(timeout=max(0.0, min(0.05, deadline - time.perf_counter()))):
        waited = round((time.perf_counter() - started) * 1000, 1)
        if cancel is not None and cancel.is_set():
            return [], "Cancelled: 已取消 DNS 查詢", waited
        if time.perf_counter() >= deadline:
            return [], "DNSBusy: 前次系統 DNS 查詢尚未返回，已達 4 個背景查詢上限", waited
    # A slot may become available at the same instant cancellation/deadline wins.
    # Do not launch another uncancellable OS resolver after either boundary.
    if cancel is not None and cancel.is_set():
        slots.release()
        return [], "Cancelled: 已取消 DNS 查詢", 0.0
    if time.perf_counter() >= deadline:
        slots.release()
        return [], "DNSBusy: 前次系統 DNS 查詢尚未返回，已達 4 個背景查詢上限", 0.0
    started = time.perf_counter()
    q: queue.Queue = queue.Queue(maxsize=1)

    def resolve():
        try:
            q.put((socket.getaddrinfo(host, 443, family, socket.SOCK_STREAM, socket.IPPROTO_TCP), ""))
        except Exception as exc:
            q.put(([], f"{type(exc).__name__}: {exc}"))
        finally:
            slots.release()

    try:
        threading.Thread(target=resolve, daemon=True, name="network-dns").start()
    except RuntimeError as exc:
        slots.release()
        return [], f"DNSWorkerError: {exc}", round((time.perf_counter() - started) * 1000, 1)
    addresses, error = [], ""
    while True:
        if cancel is not None and cancel.is_set():
            error = "Cancelled: 已取消 DNS 查詢"
            break
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            error = f"DNSTimeout: DNS 查詢超過 {timeout:g} 秒"
            break
        try:
            addresses, error = q.get(timeout=min(remaining, 0.1))
            break
        except queue.Empty:
            pass
    seen, unique = set(), []
    for info in addresses:
        key = (info[0], info[4])
        if key not in seen:
            unique.append(info)
            seen.add(key)
    return unique[:8], error, round((time.perf_counter() - started) * 1000, 1)


class _ProbeCancelled(Exception):
    pass


class _OverallTimeout(TimeoutError):
    """The measurement stopped at its overall deadline, not a protocol error."""


class _PhaseTimeout(TimeoutError):
    pass


def probe_endpoint(host: str, family: int, addrinfo: Any, dns_ms: float,
                   connect_timeout: float = 5, tls_timeout: float = 6,
                   http_timeout: float = 5, overall_timeout: float = 18,
                   cancel: threading.Event | None = None) -> Probe:
    """One IP and TCP connection through verified TLS to an HTTP status line."""
    started = time.perf_counter()
    deadline = started + max(0.001, overall_timeout)
    p = Probe(host=host, family="IPv4" if family == socket.AF_INET else "IPv6",
              ip=addrinfo[4][0], stage="tcp_connect", dns_ms=dns_ms,
              context={"port": addrinfo[4][1], "sni": host, "method": "HEAD", "path": "/",
                       "connect_timeout": connect_timeout, "tls_timeout": tls_timeout,
                       "http_timeout": http_timeout})
    sock, tls = None, None
    phase, phase_started = "tcp", started
    phase_deadline = started + max(0.001, connect_timeout)

    def budget() -> float:
        if cancel is not None and cancel.is_set():
            raise _ProbeCancelled("使用者取消")
        now = time.perf_counter()
        # Keep the original phase deadline: clamping it to the overall deadline
        # would lose which budget expired first. Overall wins an equal deadline.
        if now >= deadline and deadline <= phase_deadline:
            raise _OverallTimeout("整體時間預算已耗盡")
        if now >= phase_deadline:
            raise _PhaseTimeout("目前階段時間預算已耗盡")
        if now >= deadline:
            raise _OverallTimeout("整體時間預算已耗盡")
        return min(deadline, phase_deadline) - now

    def check_overall() -> None:
        if time.perf_counter() >= deadline:
            raise _OverallTimeout("整體時間預算已耗盡")

    try:
        budget()
        sock = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        sock.settimeout(budget())
        phase_started = time.perf_counter()
        sock.connect(addrinfo[4])
        p.tcp_ms = round((time.perf_counter() - phase_started) * 1000, 1)
        p.stage = "tcp_ok"
        check_overall()
        phase = "tls"
        phase_started = time.perf_counter()
        phase_deadline = phase_started + max(0.001, tls_timeout)
        ctx = ssl.create_default_context()
        sock.settimeout(budget())
        tls = ctx.wrap_socket(sock, server_hostname=host, do_handshake_on_connect=False)
        tls.settimeout(budget())
        tls.do_handshake()
        p.tls_ms = round((time.perf_counter() - phase_started) * 1000, 1)
        p.tls_version = tls.version() or ""
        p.stage = "tls_ok"
        check_overall()
        phase = "http"
        phase_started = time.perf_counter()
        phase_deadline = phase_started + max(0.001, http_timeout)
        packet = (f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
                  f"User-Agent: WindowsNetDiffDiag/{VERSION}\r\n\r\n").encode("ascii")
        tls.settimeout(budget())
        tls.sendall(packet)
        response = bytearray()
        while b"\r\n" not in response and len(response) < 8192:
            tls.settimeout(budget())
            chunk = tls.recv(min(1024, 8192 - len(response)))
            check_overall()
            if not chunk:
                break
            response.extend(chunk)
        p.http_ms = round((time.perf_counter() - phase_started) * 1000, 1)
        if not response:
            p.stage, p.error = "http_empty", "TLS 成功，但對端未傳回 HTTP 回應即關閉連線"
        else:
            p.http_line = bytes(response).split(b"\r\n", 1)[0].decode("iso-8859-1")
            match = re.fullmatch(r"HTTP/1\.[01] ([1-5][0-9]{2})(?:[ \t].*)?", p.http_line)
            if b"\r\n" not in response or not match:
                p.stage, p.error = "http_protocol_error", "TLS 成功，但未收到完整有效的 HTTP 狀態列"
            else:
                p.http_status, p.stage = int(match[1]), "http_ok"
        return p
    except _ProbeCancelled as exc:
        p.stage, p.error_type, p.error = "cancelled", "Cancelled", str(exc)
    except _OverallTimeout as exc:
        p.stage, p.timeout_stage = "overall_timeout", "overall"
        p.error_type, p.error = type(exc).__name__, str(exc)
        if getattr(p, phase + "_ms") is None:
            setattr(p, phase + "_ms", round((time.perf_counter() - phase_started) * 1000, 1))
    except ssl.SSLCertVerificationError as exc:
        p.stage, p.error_type = "tls_cert_error", type(exc).__name__
        p.error = f"{exc}; verify_code={getattr(exc, 'verify_code', None)}"
        p.tls_ms = round((time.perf_counter() - phase_started) * 1000, 1)
    except (OSError, ssl.SSLError, ValueError) as exc:
        elapsed = round((time.perf_counter() - phase_started) * 1000, 1)
        setattr(p, phase + "_ms", elapsed)
        p.error_type, p.error = type(exc).__name__, f"{type(exc).__name__}: {exc}"
        # A socket timeout can also be caused by its timeout having been clipped
        # to the remaining overall budget. Inspect actual absolute deadlines.
        overall_expired_first = (isinstance(exc, TimeoutError) and
                                  time.perf_counter() >= deadline and deadline <= phase_deadline)
        p.stage = "overall_timeout" if overall_expired_first else phase + ("_timeout" if isinstance(exc, TimeoutError) else "_error")
        if isinstance(exc, TimeoutError):
            p.timeout_stage = "overall" if overall_expired_first else phase
        # A pending bounded socket call may return only after cancellation.
        # Its final timeout must not become evidence of a persistent TLS fault.
        if cancel is not None and cancel.is_set():
            p.stage, p.error_type, p.timeout_stage = 'cancelled', 'Cancelled', ''
    finally:
        for connection in (tls, sock):
            if connection is not None:
                try:
                    connection.close()
                except OSError as exc:
                    p.error += f"; close: {type(exc).__name__}: {exc}"
        p.total_ms = round((time.perf_counter() - started) * 1000, 1)
    return p


def probe_host_family(host: str, family: int, retries: int = 2,
                      cancel: threading.Event | None = None,
                      overall_timeout: float = 35, *, dns_timeout: float = 6,
                      connect_timeout: float = 5, tls_timeout: float = 6,
                      http_timeout: float = 5, retry_mode: str = 'same-ip') -> Probe:
    if retry_mode not in ('same-ip', 'rotate'):
        raise ValueError('retry_mode must be same-ip or rotate')
    started = time.perf_counter()
    deadline = started + max(0.001, overall_timeout)
    label = "IPv4" if family == socket.AF_INET else "IPv6"
    dns_remaining = max(0.001, deadline - time.perf_counter())
    dns_overall_first = dns_remaining <= dns_timeout
    addresses, error, dns_ms = timeout_dns(host, family, min(dns_timeout, dns_remaining), cancel)
    if not addresses:
        stage = "cancelled" if error.startswith("Cancelled:") else "dns_timeout" if error.startswith("DNSTimeout:") else "dns_error"
        if stage == "dns_timeout" and time.perf_counter() >= deadline and dns_overall_first:
            stage = "overall_timeout"
        return Probe(host=host, family=label, dns_ms=None if error.startswith('DNSBusy:') else dns_ms, stage=stage,
                     error=error or "DNS 未傳回此協定位址", error_type=error.split(":", 1)[0],
                     timeout_stage="overall" if stage == "overall_timeout" else "dns" if stage == "dns_timeout" else "",
                     total_ms=round((time.perf_counter() - started) * 1000, 1))
    outcomes = []
    for index in range(max(1, min(4, retries))):
        remaining = deadline - time.perf_counter()
        if remaining <= 0 or (cancel is not None and cancel.is_set()):
            break
        # A retry must have enough budget for its configured TCP and TLS stages.
        # The first attempt may still report a bounded overall_timeout; do not
        # start further attempts with an arbitrary fixed minimum such as 6s.
        if index > 0 and remaining < max(0.001, connect_timeout) + max(0.001, tls_timeout):
            break
        selected_address = addresses[0] if retry_mode == 'same-ip' else addresses[index % len(addresses)]
        p = probe_endpoint(host, family, selected_address, dns_ms,
                           connect_timeout=connect_timeout, tls_timeout=tls_timeout,
                           http_timeout=http_timeout,
                           overall_timeout=min(max(0.001, connect_timeout) + max(0.001, tls_timeout) +
                                               max(0.001, http_timeout), remaining), cancel=cancel)
        p.resolved_addresses = list(dict.fromkeys(info[4][0] for info in addresses))
        p.context['retry_mode'] = retry_mode
        p.attempt = index + 1
        outcomes.append(p)
        if p.stage == "cancelled":
            break
    if not outcomes:
        return Probe(host=host, family=label, dns_ms=dns_ms,
                     stage="cancelled" if cancel is not None and cancel.is_set() else "overall_timeout",
                     error="未開始連線，查詢後取消或時間預算已耗盡", timeout_stage="overall",
                     resolved_addresses=list(dict.fromkeys(info[4][0] for info in addresses)))
    rank = {"http_ok": 12, "http_protocol_error": 11, "http_empty": 10,
            "http_timeout": 9, "http_error": 8, "tls_ok": 7,
            "tls_cert_error": 6, "tls_timeout": 5, "tls_error": 4,
            "tcp_ok": 3, "tcp_timeout": 2, "tcp_error": 1,
            "overall_timeout": -1, "cancelled": -2}
    best = max(outcomes, key=lambda item: rank.get(item.stage, 0))
    best.attempts = [{k: v for k, v in asdict(item).items() if k != "attempts"} for item in outcomes]
    stages = {p.stage for p in outcomes}
    # Different failure phases or success mixed with failure merit follow-up.
    best.intermittent = len(stages) > 1
    best.total_ms = round((time.perf_counter() - started) * 1000, 1)
    return best
