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
from winnetdiff.core.models import INET_PATH, POLICY_PATH


def query_winhttp_proxy() -> dict[str, Any]:
    """Read the default WinHTTP configuration, never a session or PAC result."""
    if os.name != 'nt':
        raise OSError('WinHTTP configuration requires Windows')
    from ctypes import wintypes
    class ProxyInfo(ctypes.Structure):
        _fields_ = [('access_type', wintypes.DWORD), ('proxy', ctypes.c_void_p), ('bypass', ctypes.c_void_p)]
    # Restrict this new API's DLL lookup to System32, including after UAC.
    api = ctypes.WinDLL('winhttp', use_last_error=True, winmode=0x800)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True, winmode=0x800)
    api.WinHttpGetDefaultProxyConfiguration.argtypes = [ctypes.POINTER(ProxyInfo)]
    api.WinHttpGetDefaultProxyConfiguration.restype = wintypes.BOOL
    kernel.GlobalFree.argtypes = [ctypes.c_void_p]
    kernel.GlobalFree.restype = ctypes.c_void_p
    info = ProxyInfo()
    if not api.WinHttpGetDefaultProxyConfiguration(ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return {'ok': True, 'access_type': info.access_type,
                'proxy': ctypes.wstring_at(info.proxy) if info.proxy else '',
                'bypass': ctypes.wstring_at(info.bypass) if info.bypass else '',
                'scope': 'WinHTTP default configuration; sessions may override it'}
    finally:
        for pointer in (info.proxy, info.bypass):
            if pointer:
                kernel.GlobalFree(pointer)


def current_token_sid() -> str:
    """SID of the actual process token, used for backup directory ACLs."""
    from ctypes import wintypes
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                          wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        required = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
        if not required.value:
            raise ctypes.WinError(ctypes.get_last_error())
        data = ctypes.create_string_buffer(required.value)
        if not advapi.GetTokenInformation(token, 1, data, required, ctypes.byref(required)):
            raise ctypes.WinError(ctypes.get_last_error())
        # TOKEN_USER starts with SID_AND_ATTRIBUTES; its first member is PSID.
        sid = ctypes.cast(data, ctypes.POINTER(ctypes.c_void_p))[0]
        text_sid = ctypes.c_void_p()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text_sid)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(text_sid)
        finally:
            kernel.LocalFree(text_sid)
    finally:
        kernel.CloseHandle(token)


def wininet_option_types() -> tuple[Any, Any]:
    from ctypes import wintypes
    class Value(ctypes.Union):
        # A void pointer preserves the allocated address for GlobalFree on query.
        _fields_ = [('dwValue', wintypes.DWORD), ('pszValue', ctypes.c_void_p), ('ftValue', wintypes.FILETIME)]
    class Option(ctypes.Structure):
        _fields_ = [('dwOption', wintypes.DWORD), ('Value', Value)]
    class Options(ctypes.Structure):
        _fields_ = [('dwSize', wintypes.DWORD), ('pszConnection', wintypes.LPWSTR),
                    ('dwOptionCount', wintypes.DWORD), ('dwOptionError', wintypes.DWORD),
                    ('pOptions', ctypes.POINTER(Option))]
    return Option, Options


def query_wininet_proxy() -> dict[str, Any]:
    """Read the LAN/default connection through the supported WinINET API only."""
    Option, Options = wininet_option_types()
    library = ctypes.WinDLL('wininet', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    library.InternetQueryOptionW.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
                                            ctypes.POINTER(ctypes.c_ulong)]
    library.InternetQueryOptionW.restype = ctypes.c_int
    kernel.GlobalFree.argtypes = [ctypes.c_void_p]
    kernel.GlobalFree.restype = ctypes.c_void_p
    # Microsoft documents FLAGS_UI for reads on Windows 7+, FLAGS as fallback.
    for flag_option in (10, 1):
        array = (Option * 4)()
        for item, code in zip(array, (flag_option, 2, 3, 4)):
            item.dwOption = code
        options = Options(ctypes.sizeof(Options), None, 4, 0, array)
        size = ctypes.c_ulong(ctypes.sizeof(options))
        try:
            if not library.InternetQueryOptionW(None, 75, ctypes.byref(options), ctypes.byref(size)):
                if flag_option == 10:
                    continue
                raise ctypes.WinError(ctypes.get_last_error())
            return {'flags': int(array[0].Value.dwValue),
                    **{key: ctypes.wstring_at(item.Value.pszValue) if item.Value.pszValue else ''
                       for key, item in zip(('ProxyServer', 'ProxyOverride', 'AutoConfigURL'), array[1:])}}
        finally:
            # InternetQueryOption allocates each returned string; even failed
            # multi-option queries may have populated an earlier string.
            for pointer in {item.Value.pszValue for item in array[1:] if item.Value.pszValue}:
                kernel.GlobalFree(pointer)
    raise RuntimeError('WinINET query did not return connection options')


def proxy_policy_snapshot() -> dict[str, Any]:
    """Policies relevant to scope/configuration, including UI management locks."""
    names = ['ProxySettingsPerUser', 'Proxy', 'ProxyEnable', 'ProxyServer', 'ProxyOverride',
             'AutoConfigURL', 'AutoDetect']
    result = {}
    for label, hive in [('HKLM', winreg.HKEY_LOCAL_MACHINE), ('HKCU', winreg.HKEY_CURRENT_USER)]:
        for path, fields in [(POLICY_PATH, names),
                             (r'Software\Policies\Microsoft\Internet Explorer\Control Panel',
                              ['Proxy', 'Autoconfig', 'AutoConfig'])]:
            result[label + '\\' + path] = registry_values(hive, path, fields)
    return result


def is_admin() -> bool:
    try:
        return os.name == 'nt' and bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def reg_get(root: Any, path: str, name: str) -> Any:
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def registry_values(root: Any, path: str, names: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {'values': {}, 'types': {}, 'error': '', 'missing': False}
    if winreg is None:
        result['error'] = 'Windows registry unavailable'
        return result
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
            for name in names:
                try:
                    value, typ = winreg.QueryValueEx(key, name)
                    result['values'][name], result['types'][name] = value, typ
                except FileNotFoundError:
                    result['values'][name] = None
    except FileNotFoundError:
        result['missing'] = True
    except OSError as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
    return result
