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
from winnetdiff.collectors.proxy import collect_proxy, proxy_endpoints
from winnetdiff.core.models import INET_PATH, PROXY_KEYS, Report
from winnetdiff.core.process import ps_json, run_command
from winnetdiff.core.windows import (current_token_sid, proxy_policy_snapshot, query_wininet_proxy,
                                    registry_values, wininet_option_types)


def atomic_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temp.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(obj, stream, ensure_ascii=False, indent=2, default=str)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def current_sid() -> str:
    result = run_command(['whoami', '/user', '/fo', 'csv', '/nh'], 5)
    for row in csv.reader(io.StringIO(result['stdout'])):
        if len(row) >= 2 and re.fullmatch(r'S-1-[0-9-]+', row[1]):
            return row[1]
    raise RuntimeError('無法取得目前使用者 SID；為避免回復至其他帳戶，未修改設定。')


def protect_directory(path: Path, sid: str) -> None:
    """Atomically replace DACL with current user + SYSTEM, including child inheritance."""
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
    advapi.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
                                                ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int)]
    advapi.GetSecurityDescriptorDacl.restype = ctypes.c_int
    advapi.SetNamedSecurityInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.c_ulong,
                                            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    advapi.SetNamedSecurityInfoW.restype = ctypes.c_ulong
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    sddl = f'D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)'
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        present, defaulted, acl = ctypes.c_int(), ctypes.c_int(), ctypes.c_void_p()
        if not advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(acl), ctypes.byref(defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not present.value or not acl.value:
            raise RuntimeError('拒絕套用空白 DACL。')
        code = advapi.SetNamedSecurityInfoW(str(path), 1, 0x80000004, None, None, acl, None)
        if code:
            raise ctypes.WinError(code)
    finally:
        kernel.LocalFree(descriptor)


def private_storage(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == 'nt':
        try:
            # ACLs must identify the process actually writing the private files;
            # backup ownership validation is a separate restore precondition.
            protect_directory(path, current_token_sid())
        except OSError as exc:
            raise RuntimeError('備份資料夾權限設定失敗：' + str(exc)) from exc


def _packed_value(value: Any) -> Any:
    return {'base64': base64.b64encode(value).decode('ascii')} if isinstance(value, bytes) else value


def _unpacked_value(value: Any) -> Any:
    return base64.b64decode(value['base64'], validate=True) if isinstance(value, dict) and 'base64' in value else value


def proxy_snapshot() -> dict[str, Any]:
    result: dict[str, Any] = {}
    for path, names in [(INET_PATH, PROXY_KEYS), (INET_PATH + r'\Connections',
                                                ['DefaultConnectionSettings', 'SavedLegacySettings'])]:
        snap = registry_values(winreg.HKEY_CURRENT_USER, path, names)
        if snap['error']:
            raise RuntimeError(snap['error'])
        result[path] = {name: {'exists': name in snap['types'], 'type': snap['types'].get(name),
                               'value': _packed_value(snap['values'].get(name))} for name in names}
    result['api'] = query_wininet_proxy()
    result['flags'] = result['api']['flags']
    result['policy'] = proxy_policy_snapshot()
    if any(item.get('error') for item in result['policy'].values()):
        raise RuntimeError('代理原則查詢未完整；拒絕修改。')
    return result


def _wininet_options() -> tuple[Any, Any, Any]:
    Option, Options = wininet_option_types()
    option = Option()
    option.dwOption = 1  # INTERNET_PER_CONN_FLAGS, no allocated string buffer
    options = Options(ctypes.sizeof(Options), None, 1, 0, ctypes.pointer(option))
    return ctypes.WinDLL('wininet', use_last_error=True), option, options


def wininet_flags() -> int:
    return int(query_wininet_proxy()['flags'])


def set_wininet_flags(flags: int) -> None:
    library, option, options = _wininet_options()
    option.Value.dwValue = flags
    library.InternetSetOptionW.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong]
    library.InternetSetOptionW.restype = ctypes.c_int
    if not library.InternetSetOptionW(None, 75, ctypes.byref(options), ctypes.sizeof(options)):
        raise ctypes.WinError(ctypes.get_last_error())
    notify_wininet()


def notify_wininet() -> None:
    library = ctypes.WinDLL('wininet', use_last_error=True)
    library.InternetSetOptionW.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong]
    library.InternetSetOptionW.restype = ctypes.c_int
    for code in (39, 37):
        if not library.InternetSetOptionW(None, code, None, 0):
            raise ctypes.WinError(ctypes.get_last_error())


def restore_proxy_snapshot(snapshot: dict[str, Any]) -> None:
    """Restore supported settings, never write archived Connections blobs."""
    state = proxy_semantics(snapshot)
    if state['scope'] != 'HKCU':
        raise RuntimeError('拒絕自動回復電腦層級代理。')
    Option, Options = wininet_option_types()
    array = (Option * 4)()
    array[0].dwOption, array[0].Value.dwValue = 1, state['flags']
    # Keep buffers alive until InternetSetOptionW returns. Empty means no value;
    # missing-vs-empty registry representation is not an effective setting.
    buffers = []
    for item, code, key in zip(array[1:], (2, 3, 4), ('ProxyServer', 'ProxyOverride', 'AutoConfigURL')):
        item.dwOption = code
        buffer = ctypes.create_unicode_buffer(state['api'][key])
        buffers.append(buffer)
        item.Value.pszValue = ctypes.cast(buffer, ctypes.c_void_p).value
    options = Options(ctypes.sizeof(Options), None, 4, 0, array)
    library = ctypes.WinDLL('wininet', use_last_error=True)
    library.InternetSetOptionW.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong]
    library.InternetSetOptionW.restype = ctypes.c_int
    if not library.InternetSetOptionW(None, 75, ctypes.byref(options), ctypes.sizeof(options)):
        raise ctypes.WinError(ctypes.get_last_error())
    notify_wininet()


def proxy_semantics(snapshot: dict[str, Any]) -> dict[str, Any]:
    """CAS/verification state. Binary counters and storage types are archival only.

    Schema-2 backups created before API strings/policies were archived remain
    readable. An absent old policy section only matches an empty current policy.
    """
    values = snapshot[INET_PATH]
    flags = int(snapshot['flags'])
    registry = {}
    for key in PROXY_KEYS:
        value = values.get(key, {}).get('value')
        if key == 'ProxyEnable':
            registry[key] = int(value or 0)
        elif key == 'AutoDetect':
            registry[key] = int(bool(value)) if value is not None else int(bool(flags & 8))
        else:
            registry[key] = str(value or '')
    api = snapshot.get('api', {})
    if api.get('error'):
        raise RuntimeError('WinINET API 查詢未完整；拒絕修改。')
    api_values = {key: str(api.get(key, registry[key]) or '')
                  for key in ('ProxyServer', 'ProxyOverride', 'AutoConfigURL')}
    policies = {}
    for path, item in snapshot.get('policy', {}).items():
        if item.get('error'):
            raise RuntimeError('代理原則查詢未完整；拒絕修改。')
        # Missing key/value has no applicable policy. Presence of an actual
        # value (including zero) does participate in CAS.
        active = {key: value for key, value in item.get('values', {}).items() if value is not None}
        if active:
            policies[path] = active
    machine_policy = any(path.startswith('HKLM\\') and item.get('ProxySettingsPerUser') == 0
                         for path, item in policies.items())
    return {'flags': flags, 'registry': registry, 'api': api_values, 'policy': policies,
            'scope': 'HKLM' if machine_policy else 'HKCU'}


def _report_proxy_semantics(proxy: dict[str, Any]) -> dict[str, Any]:
    """Use the same effective inputs for preview and the fresh mutation guard."""
    return {'registry': {key: proxy.get('wininet', {}).get(key) for key in PROXY_KEYS},
            'api': proxy.get('wininet_api'), 'scope': proxy.get('effective_scope', 'HKCU'),
            'policy': proxy.get('applicable_policy', {}),
            'policy_machine': proxy.get('policy', {}), 'policy_user': proxy.get('policy_user', {})}


def _snapshot_manual_consistency(snapshot: dict[str, Any]) -> bool:
    state = proxy_semantics(snapshot)
    return state['registry']['ProxyEnable'] == int(bool(state['flags'] & 2))


def _rollback_proxy_guard(observed: dict[str, Any], reference: dict[str, Any]) -> bool:
    """Our transaction owns only manual enable and direct-fallback bits.

    Do not recover over an endpoint, PAC, autodetect, bypass or policy changed
    by another process while a settings call or verification was in flight.
    """
    states = [proxy_semantics(value) for value in (observed, reference)]
    for state in states:
        state['flags'] &= ~3
        state['registry'].pop('ProxyEnable')
    return states[0] == states[1]


def proxy_repair_eligibility(proxy: dict[str, Any]) -> dict[str, Any]:
    value = proxy.get('wininet', {})
    if proxy.get('effective_scope', 'HKCU') != 'HKCU':
        return {'eligible': False, 'reason': '目前套用電腦層級代理；請交由管理員檢查原則。', 'objects': []}
    if proxy.get('errors') or proxy.get('policy', {}).get('error') or proxy.get('policy_user', {}).get('error'):
        return {'eligible': False, 'reason': '代理或原則查詢未完整，無法安全修復。', 'objects': []}
    if any(p.get('values', {}).get('Proxy') for p in (proxy.get('policy', {}), proxy.get('policy_user', {}))):
        return {'eligible': False, 'reason': '偵測到代理管理原則，請由管理員人工審閱。', 'objects': []}
    if any(p.get('error') or any(v is not None for v in p.get('values', {}).values())
           for p in proxy.get('applicable_policy', {}).values()):
        return {'eligible': False, 'reason': '偵測到代理管理原則，請由管理員人工審閱。', 'objects': []}
    api = proxy.get('wininet_api', {})
    if api.get('error') or not isinstance(api.get('flags'), int):
        return {'eligible': False, 'reason': 'WinINET API 查詢未完整，無法安全修復。', 'objects': []}
    if (value.get('ProxyEnable') == 1) != bool(api['flags'] & 2):
        return {'eligible': False, 'reason': '登錄與 WinINET API 手動代理狀態不一致；請重新整理設定並人工核對。', 'objects': []}
    if any(str(api.get(key, '') or '') != str(value.get(key, '') or '')
           for key in ('ProxyServer', 'ProxyOverride', 'AutoConfigURL') if key in api):
        return {'eligible': False, 'reason': '登錄與 WinINET API 代理內容不一致；請重新診斷。', 'objects': []}
    if value.get('ProxyEnable') != 1:
        return {'eligible': False, 'reason': '手動代理未啟用，無需變更。', 'objects': []}
    if value.get('AutoConfigURL') or api['flags'] & 4:
        return {'eligible': False, 'reason': '同時存在 PAC；須先人工核對實際代理優先順序。', 'objects': []}
    raw = str(value.get('ProxyServer') or '')
    endpoints = proxy_endpoints(raw)
    # Require every manual entry to resolve to an explicit loopback endpoint.
    entries = [x for x in re.split(r'[;\s]+', raw) if x]
    if not endpoints or any(not proxy_endpoints(x) for x in entries):
        return {'eligible': False, 'reason': '含遠端或無法解析的代理項目，不提供自動變更。', 'objects': []}
    for host, port in endpoints:
        evidence = next((x for x in proxy.get('local_listeners', []) if x['host'] == host and x['port'] == port), {})
        if not evidence.get('confirmed_dead'):
            return {'eligible': False, 'reason': '尚未確認全部手動代理埠持續拒絕連線。', 'objects': []}
    return {'eligible': True, 'reason': '已啟用的 HKCU 手動代理全部指向持續拒絕連線的本機埠。',
            'objects': [{'hive': 'HKCU', 'path': INET_PATH, 'ProxyEnable': '1 → 0',
                         'ProxyServer': raw, 'endpoints': endpoints}],
            'risk': '使用此代理的應用程式會改走直接連線；原始設定與連線旗標均會備份。'}


class RepairManager:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self._lock = threading.Lock()

    def history(self) -> list[dict[str, Any]]:
        path = self.directory / 'history.json'
        return json.loads(path.read_text(encoding='utf-8')) if path.exists() else []

    def _record(self, record: dict[str, Any]) -> dict[str, Any]:
        records = self.history()
        records.append({'at': dt.datetime.now().astimezone().isoformat(), **record})
        atomic_json(self.directory / 'history.json', records)
        return record

    def last_backup(self) -> Optional[Path]:
        unavailable = set()
        for entry in reversed(self.history()):
            path = entry.get('backup')
            if not path:
                continue
            if entry.get('operation') == 'restore_proxy' and entry.get('ok') is True:
                unavailable.add(path)
            if entry.get('operation') == 'disable_proxy':
                if (path not in unavailable and entry.get('ok') is True and entry.get('changed') is True
                        and entry.get('phase') in (None, 'verified')):
                    candidate = Path(path)
                    if not candidate.is_file():
                        unavailable.add(path)
                        continue
                    try:
                        state = json.loads(candidate.read_text(encoding='utf-8'))
                    except (OSError, ValueError):
                        unavailable.add(path)
                        continue
                    if state.get('phase') not in (None, 'verified', 'applied'):
                        unavailable.add(path)
                        continue
                    return candidate
                # Terminal failure consumes any earlier success for this file.
                if entry.get('ok') is False or entry.get('phase') in ('restored', 'rollback_failed'):
                    unavailable.add(path)
        return None

    def preview_disable_proxy(self, report: Report) -> dict[str, Any]:
        return proxy_repair_eligibility(report.proxy)

    def disable_proxy(self, report: Report, confirmed: bool = False) -> dict[str, Any]:
        if not confirmed:
            raise ValueError('修復必須先顯示預覽並取得使用者確認。')
        with self._lock:
            private_storage(self.directory)
            fresh = collect_proxy()
            preview = proxy_repair_eligibility(fresh)
            if not preview['eligible']:
                return self._record({'operation': 'disable_proxy', 'ok': False, 'changed': False, 'reason': preview['reason']})
            if _report_proxy_semantics(fresh) != _report_proxy_semantics(report.proxy):
                raise RuntimeError('掃描後代理設定已變更；請重新診斷並確認。')
            before = proxy_snapshot()
            if not _snapshot_manual_consistency(before) or not before['flags'] & 2:
                return self._record({'operation': 'disable_proxy', 'ok': False, 'changed': False,
                                     'reason': '登錄與 WinINET API 狀態不一致或已變更；請重新診斷。'})
            # The collection and snapshot are separate reads: do not overwrite
            # an intervening change to an endpoint, PAC, auto-detect or policy.
            before_state = proxy_semantics(before)
            for key in PROXY_KEYS:
                expected = fresh.get('wininet', {}).get(key)
                if key == 'AutoDetect' and expected is None:
                    expected = int(bool(fresh['wininet_api']['flags'] & 8))
                elif key == 'ProxyEnable':
                    expected = int(expected or 0)
                elif key == 'AutoDetect':
                    expected = int(bool(expected))
                else:
                    expected = str(expected or '')
                if before_state['registry'][key] != expected:
                    raise RuntimeError('掃描後代理設定已變更；請重新診斷並確認。')
            if before_state['flags'] != fresh['wininet_api']['flags']:
                raise RuntimeError('掃描後 WinINET API 設定已變更；請重新診斷並確認。')
            if any(before_state['api'][key] != str(fresh['wininet_api'][key] or '')
                   for key in before_state['api'] if key in fresh['wininet_api']):
                raise RuntimeError('掃描後 WinINET API 代理內容已變更；請重新診斷並確認。')
            if before.get('policy') is not None:
                policy_at_collection = {key: {'values': item.get('values', {}), 'error': item.get('error', '')}
                                        for key, item in fresh.get('applicable_policy', {}).items()}
                collection_state = dict(before, policy=policy_at_collection)
                if before_state['policy'] != proxy_semantics(collection_state)['policy']:
                    raise RuntimeError('掃描後代理管理原則已變更；請重新診斷並確認。')
            backup_path = self.directory / ('proxy_' + uuid.uuid4().hex + '.json')
            expected_after = json.loads(json.dumps(before))
            expected_after['flags'] = (before['flags'] & ~2) | 1
            expected_after[INET_PATH]['ProxyEnable']['value'] = 0
            if 'api' in expected_after:
                expected_after['api']['flags'] = expected_after['flags']
            backup = {'schema': 2, 'kind': 'wininet_proxy', 'sid': current_sid(),
                      'machine': platform.node(), 'before': before, 'after': None,
                      'expected_after': expected_after, 'phase': 'prepared'}
            atomic_json(backup_path, backup)
            # Intent journal is durable before the mutation; prepared backups survive interruption.
            self._record({'operation': 'disable_proxy', 'phase': 'prepared', 'backup': str(backup_path), 'before': before})
            after = None
            try:
                # Preserve PAC/auto-detect bits, and keep direct fallback enabled.
                set_wininet_flags((before['flags'] & ~2) | 1)
                backup['phase'] = 'applied'
                atomic_json(backup_path, backup)
                self._record({'operation': 'disable_proxy', 'phase': 'applied', 'backup': str(backup_path)})
                after = proxy_snapshot()
                ok = (not (after['flags'] & 2) and after[INET_PATH]['ProxyEnable']['value'] == 0
                      and proxy_semantics(after) == proxy_semantics(expected_after))
                if not ok:
                    raise RuntimeError('代理變更後驗證失敗。')
                backup.update(after=after, phase='verified')
                atomic_json(backup_path, backup)
                return self._record({'operation': 'disable_proxy', 'ok': True, 'changed': True,
                                     'phase': 'verified',
                                     'backup': str(backup_path), 'before': before, 'after': after,
                                     'verification': 'WinINET API flags and registry reread; rerun differential probes for network effect'})
            except Exception as exc:
                # A failed notification may still have changed settings, so try original state.
                journal_errors = []
                backup['phase'] = 'restore_started'
                try:
                    atomic_json(backup_path, backup)
                    self._record({'operation': 'disable_proxy', 'phase': 'restore_started', 'backup': str(backup_path)})
                except Exception as audit_error:
                    # Once a mutation was attempted, disk errors must not stop
                    # best-effort rollback of the settings already backed up.
                    journal_errors.append(str(audit_error))
                try:
                    observed = after if after is not None else proxy_snapshot()
                    if not _rollback_proxy_guard(observed, before):
                        backup['recovery_observed'] = observed
                        raise RuntimeError('代理內容或原則已被外部變更；拒絕以自動回復覆蓋。')
                    restore_proxy_snapshot(before)
                    rollback = proxy_semantics(proxy_snapshot()) == proxy_semantics(before)
                except Exception as recovery:
                    rollback = False
                    backup['recovery_error'] = str(recovery)
                backup.update(phase='restored' if rollback else 'rollback_failed', error=str(exc))
                try:
                    atomic_json(backup_path, backup)
                except Exception as audit_error:
                    journal_errors.append(str(audit_error))
                try:
                    self._record({'operation': 'disable_proxy', 'ok': False, 'changed': not rollback,
                                  'backup': str(backup_path), 'phase': backup['phase'],
                                  'error': str(exc), 'rollback_verified': rollback,
                                  'journal_errors': journal_errors})
                except Exception as audit_error:
                    journal_errors.append(str(audit_error))
                raise RuntimeError(f'{exc}；自動回復驗證={rollback}；備份={backup_path}；日誌錯誤={journal_errors}') from exc

    def restore_proxy(self, backup_path: Path, confirmed: bool = False) -> dict[str, Any]:
        if not confirmed:
            raise ValueError('回復必須先取得使用者確認。')
        with self._lock:
            private_storage(self.directory)
            backup = json.loads(Path(backup_path).read_text(encoding='utf-8'))
            if (backup.get('schema') != 2 or backup.get('kind') != 'wininet_proxy'
                    or backup.get('sid') != current_sid() or backup.get('machine') != platform.node()):
                raise RuntimeError('備份格式、電腦或使用者不符；拒絕回復。')
            current = proxy_snapshot()
            current_state = proxy_semantics(current)
            if current_state == proxy_semantics(backup['before']):
                backup['phase'] = 'restored'
                atomic_json(Path(backup_path), backup)
                return self._record({'operation': 'restore_proxy', 'ok': True, 'changed': False,
                                     'phase': 'restored', 'backup': str(backup_path)})
            expected = backup.get('after') or backup.get('expected_after')
            if expected is None or current_state != proxy_semantics(expected):
                raise RuntimeError('目前設定已不同於工具修改後狀態，或上次操作中斷；請人工比對備份，避免覆蓋新設定。')
            if current_state['scope'] != 'HKCU' or not _snapshot_manual_consistency(backup['before']):
                raise RuntimeError('備份範圍或有效代理狀態不一致；拒絕回復。')
            backup['phase'] = 'restore_started'
            atomic_json(Path(backup_path), backup)
            self._record({'operation': 'restore_proxy', 'phase': 'restore_started', 'backup': str(backup_path), 'before': current})
            after = None
            try:
                restore_proxy_snapshot(backup['before'])
                after = proxy_snapshot()
                if proxy_semantics(after) != proxy_semantics(backup['before']):
                    raise RuntimeError('回復後狀態驗證失敗。')
                backup['phase'] = 'restored'
                atomic_json(Path(backup_path), backup)
                return self._record({'operation': 'restore_proxy', 'ok': True, 'changed': True,
                                     'phase': 'restored',
                                     'before': current, 'after': after, 'backup': str(backup_path)})
            except Exception as exc:
                try:
                    observed = after if after is not None else proxy_snapshot()
                    if not _rollback_proxy_guard(observed, current):
                        backup['recovery_observed'] = observed
                        raise RuntimeError('代理內容或原則已被外部變更；拒絕以自動回復覆蓋。')
                    restore_proxy_snapshot(current)
                    observed = proxy_snapshot()
                    recovered = proxy_semantics(observed) == current_state
                except Exception as recovery:
                    observed, recovered = {'query_error': str(recovery)}, False
                backup['phase'] = 'verified' if recovered else 'rollback_failed'
                backup['restore_error'] = str(exc)
                journal_errors = []
                try:
                    atomic_json(Path(backup_path), backup)
                except Exception as audit_error:
                    journal_errors.append(str(audit_error))
                try:
                    self._record({'operation': 'restore_proxy', 'ok': False, 'changed': not recovered,
                                  'before': current, 'after': observed, 'backup': str(backup_path),
                                  'error': str(exc), 'rollback_verified': recovered, 'phase': 'rollback_failed',
                                  'journal_errors': journal_errors})
                except Exception as audit_error:
                    journal_errors.append(str(audit_error))
                raise RuntimeError(f'{exc}；回復前狀態重新驗證={recovered}；日誌錯誤={journal_errors}') from exc

    def flush_dns(self, confirmed: bool = False, allow_irreversible: bool = False) -> dict[str, Any]:
        if not confirmed:
            raise ValueError('清除 DNS 快取必須先取得確認。')
        if not allow_irreversible:
            raise RuntimeError('DNS cache cannot be faithfully rolled back. Automatic cache clearing is disabled; use the reviewed manual guidance.')
        with self._lock:
            private_storage(self.directory)
            # Cache is volatile: no faithful restore exists; retain counts and command evidence.
            before, err = ps_json('ConvertTo-Json -InputObject @([pscustomobject]@{Count=@(Get-DnsClientCache).Count}) -Compress', 8)
            self._record({'operation': 'flush_dns', 'phase': 'prepared', 'before': before, 'query_error': err,
                          'rollback': 'DNS 快取無法逐筆回復；後續名稱查詢會重新建立。'})
            result = run_command(['ipconfig', '/flushdns'], 10)
            after, check_error = ps_json('ConvertTo-Json -InputObject @([pscustomobject]@{Count=@(Get-DnsClientCache).Count}) -Compress', 8)
            return self._record({'operation': 'flush_dns', 'ok': result['ok'], 'changed': result['ok'],
                                 'before': before, 'after': after, 'command': result,
                                 'verification_error': check_error,
                                 'verification': 'exit code plus cache reread; concurrent queries may repopulate cache'})


def elevation_command(argv: Optional[list[str]] = None) -> tuple[str, str]:
    arguments = list(sys.argv[1:] if argv is None else argv)
    executable = sys.executable
    if not getattr(sys, 'frozen', False):
        if globals().get('_STANDALONE_BUILD', False):
            arguments.insert(0, str(Path(__file__).resolve()))
        else:
            arguments = ['-m', 'winnetdiff'] + arguments
    return executable, subprocess.list2cmdline(arguments)


def relaunch_as_admin(argv: Optional[list[str]] = None, hwnd: Optional[int] = None) -> dict[str, Any]:
    if os.name != 'nt':
        return {'ok': False, 'cancelled': False, 'error': 'Windows only'}
    executable, parameters = elevation_command(argv)
    working_directory = Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    shell.ShellExecuteW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                    ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int]
    shell.ShellExecuteW.restype = ctypes.c_void_p
    ctypes.set_last_error(0)
    result = shell.ShellExecuteW(hwnd, 'runas', executable, parameters, str(working_directory), 1)
    value = int(result or 0)
    error = ctypes.get_last_error()
    return {'ok': value > 32, 'cancelled': value <= 32 and error == 1223,
            'error': '' if value > 32 else f'UAC 未啟動新程序，ShellExecute={value}, Win32={error}'}
