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
from winnetdiff.core.models import ENV_KEYS, INET_PATH, LOCAL_IPS, POLICY_PATH, PROXY_KEYS
from winnetdiff.core.process import ps_json, run_command
from winnetdiff.core.windows import proxy_policy_snapshot, query_wininet_proxy, registry_values, query_winhttp_proxy


def proxy_endpoints(value: str) -> list[tuple[str, int]]:
    endpoints = []
    for item in re.split(r'[;\s]+', str(value or '')):
        item = re.sub(r'^(?:http|https|socks|socks4|socks5)=', '', item, flags=re.I)
        if not item:
            continue
        if not re.match(r'^[a-z][a-z0-9+.-]*://', item, re.I):
            item = 'http://' + item
        try:
            parsed = urllib.parse.urlsplit(item)
            host, port = (parsed.hostname or '').lower(), parsed.port
            local = host in LOCAL_IPS
            try:
                local = local or ipaddress.ip_address(host).is_loopback
            except ValueError:
                pass
            if local and port and 1 <= port <= 65535:
                endpoints.append((host, port))
        except ValueError:
            continue
    return list(dict.fromkeys(endpoints))


def inspect_listener(host: str, port: int) -> dict[str, Any]:
    result: dict[str, Any] = {'host': host, 'port': port, 'accepts_tcp': False,
                              'pid': None, 'program': None, 'error': '', 'confirmed_dead': False}
    # A refusal on both checks is stronger than a timeout (firewall/overload unknown).
    errors = []
    for _ in range(2):
        try:
            with socket.create_connection((host, port), timeout=0.45):
                result['accepts_tcp'] = True
            break
        except OSError as exc:
            errors.append(exc)
    result['confirmed_dead'] = len(errors) == 2 and all(
        isinstance(e, ConnectionRefusedError) or getattr(e, 'winerror', None) == 10061
        for e in errors)
    result['error'] = '; '.join(f'{type(e).__name__}: {e}' for e in errors)
    # Get-NetTCPConnection State Listen avoids localized netstat state labels.
    rows, error = ps_json(
        f'ConvertTo-Json -InputObject @(Get-NetTCPConnection -State Listen -LocalPort {port} '
        '-ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess) -Compress', 6)
    acceptable = {'0.0.0.0', '::', host}
    if host == 'localhost':
        acceptable |= {'127.0.0.1', '::1'}
    for row in rows:
        if row.get('LocalAddress') in acceptable:
            result['pid'] = row.get('OwningProcess')
            result['confirmed_dead'] = False
            break
    if result['pid'] is None:
        ns = run_command(['netstat', '-ano', '-p', 'tcp'], timeout=5)
        for line in ns['stdout'].splitlines():
            fields = line.split()
            if len(fields) < 5 or fields[0].upper() != 'TCP' or not fields[-1].isdigit():
                continue
            address, _, p = fields[1].rpartition(':')
            # Listen is identified by wildcard remote endpoint, independent of language.
            if p == str(port) and fields[2] in ('0.0.0.0:0', '[::]:0') and address.strip('[]') in acceptable:
                result['pid'] = int(fields[-1])
                result['confirmed_dead'] = False
                break
        if error:
            result['inventory_error'] = error
    if result['pid'] is not None:
        task = run_command(['tasklist', '/FI', f"PID eq {int(result['pid'])}", '/FO', 'CSV', '/NH'], 5)
        for row in csv.reader(io.StringIO(task['stdout'])):
            if len(row) > 1 and row[1].isdigit() and int(row[1]) == int(result['pid']):
                result['program'] = row[0]
                break
    return result


def collect_proxy(cancel: Optional[threading.Event] = None) -> dict[str, Any]:
    user = registry_values(winreg.HKEY_CURRENT_USER, INET_PATH, PROXY_KEYS)
    machine = registry_values(winreg.HKEY_LOCAL_MACHINE, INET_PATH, PROXY_KEYS)
    policy = registry_values(winreg.HKEY_LOCAL_MACHINE, POLICY_PATH, ['ProxySettingsPerUser', 'Proxy'])
    userpolicy = registry_values(winreg.HKEY_CURRENT_USER, POLICY_PATH, ['Proxy', 'ProxySettingsPerUser'])
    machine_mode = policy['values'].get('ProxySettingsPerUser') == 0
    effective = machine if machine_mode else user
    result: dict[str, Any] = {
        'wininet': effective['values'], 'wininet_user': user, 'wininet_machine': machine,
        'policy': policy, 'policy_user': userpolicy, 'effective_scope': 'HKLM' if machine_mode else 'HKCU',
        'errors': [f'{label}: {x["error"]}' for label, x in
                   [('HKCU', user), ('HKLM', machine), ('policy', policy), ('user policy', userpolicy)] if x['error']]}
    try:
        result['wininet_api'] = query_wininet_proxy()
    except (OSError, RuntimeError, AttributeError) as exc:
        result['wininet_api'] = {'error': f'{type(exc).__name__}: {exc}'}
        result['errors'].append('WinINET API: ' + result['wininet_api']['error'])
    result['applicable_policy'] = proxy_policy_snapshot()
    for label, item in result['applicable_policy'].items():
        if item.get('error'):
            result['errors'].append(label + ': ' + item['error'])
    wh = run_command(['netsh', 'winhttp', 'show', 'proxy'], 8)
    direct = bool(re.search(r'direct access|直接访问|直接存取|没有代理服务器|no proxy server', wh['stdout'], re.I))
    result['winhttp'] = {'raw': wh['stdout'], 'is_direct': direct if wh['ok'] else None,
                         'error': '' if wh['ok'] else wh['stderr'], 'ok': wh['ok'],
                         'command_evidence': wh}
    try:
        result['winhttp_config'] = query_winhttp_proxy()
    except (OSError, AttributeError) as exc:
        result['winhttp_config'] = {'ok': False, 'error': f'{type(exc).__name__}: {exc}'}
    if not wh['ok']:
        result['errors'].append('WinHTTP: ' + wh['stderr'])
    envpath = r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    for label, root, path in [('user', winreg.HKEY_CURRENT_USER, 'Environment'),
                               ('machine', winreg.HKEY_LOCAL_MACHINE, envpath)]:
        snap = registry_values(root, path, ENV_KEYS)
        result['environ_' + label] = snap['values']
        if snap['error']:
            result['errors'].append(f'Environment {label}: {snap["error"]}')
    result['environ_process'] = {k: os.environ.get(k) or os.environ.get(k.lower()) for k in ENV_KEYS}
    references: list[dict[str, Any]] = []
    for host, port in proxy_endpoints(effective['values'].get('ProxyServer') or ''):
        references.append({'host': host, 'port': port, 'source': 'WinINET',
                           'active': (effective['values'].get('ProxyEnable') == 1
                                      and bool(result['wininet_api'].get('flags', 0) & 2))})
    if wh['ok'] and not direct:
        pairs = re.findall(r'(127(?:\.\d{1,3}){3}|localhost|\[::1\]):(\d{1,5})', wh['stdout'], re.I)
        for host, port in pairs:
            if 0 < int(port) < 65536:
                references.append({'host': host.strip('[]').lower(), 'port': int(port),
                                   'source': 'WinHTTP', 'active': True})
    for scope in ('user', 'machine', 'process'):
        for key in ENV_KEYS[:3]:
            for host, port in proxy_endpoints(result['environ_' + scope].get(key) or ''):
                references.append({'host': host, 'port': port, 'source': f'env:{scope}:{key}',
                                   'active': 'application-dependent'})
    listeners = []
    for host, port in dict.fromkeys((r['host'], r['port']) for r in references):
        if cancel and cancel.is_set():
            result['errors'].append('cancelled: local proxy checks incomplete')
            break
        item = inspect_listener(host, port)
        item['references'] = [r for r in references if r['host'] == host and r['port'] == port]
        listeners.append(item)
    result['references'], result['local_listeners'] = references, listeners
    # PAC is recorded only, never downloaded/executed by this tool.
    result['pac_note'] = 'PAC/WPAD 實際行為由應用程式及每條連線設定決定；不下載或執行 PAC。'
    return result
