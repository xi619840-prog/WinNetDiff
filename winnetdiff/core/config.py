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
from winnetdiff.core.messages import msg
if os.name == 'nt':
    import winreg
else:
    winreg = None


def safe_host(host: str) -> str:
    host = host.strip().rstrip('.')
    try:
        host = host.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError(msg('無效網域名稱：{host}', host=host)) from exc
    labels = host.split('.')
    if (len(host) > 253 or not re.fullmatch(r'[A-Za-z0-9.-]+', host) or len(labels) < 2
            or any(not x or len(x) > 63 or x.startswith('-') or x.endswith('-') for x in labels)):
        raise ValueError(msg('請輸入網域名稱，不含 URL 或埠號：{host}', host=host))
    return host.lower()


def parse_hosts(value: str) -> list[str]:
    values = [v for v in re.split(r'[,，;；\s]+', value.strip()) if v]
    if not 1 <= len(values) <= 3:
        raise ValueError('請輸入 1～3 個網域名稱，以逗號分隔。')
    return list(dict.fromkeys(safe_host(v) for v in values))


def default_output_dir() -> Path:
    # Product defaults are per-user; --output-dir can select any local destination.
    if globals().get('_OUTPUT_DIR_OVERRIDE'):
        return Path(_OUTPUT_DIR_OVERRIDE)
    return Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'WinNetDiff' / 'Results'


TARGET_PROFILES = {
    'global': {'hosts': ['www.microsoft.com', 'www.cloudflare.com', 'www.wikipedia.org'], 'label': 'Global'},
    'mainland': {'hosts': ['www.baidu.com', 'www.qq.com', 'www.bilibili.com'], 'label': 'Mainland China'},
    'traditional': {'hosts': ['www.microsoft.com', 'www.cloudflare.com', 'www.yahoo.com'], 'label': 'Traditional Chinese networks'},
}
LANGUAGES = ('en', 'zh-CN', 'zh-TW')


def normalize_language(value: str | None) -> str:
    value = str(value or 'en').replace('_', '-').lower()
    if value.startswith(('zh-tw', 'zh-hk', 'zh-hant')):
        return 'zh-TW'
    if value.startswith('zh'):
        return 'zh-CN'
    if value.startswith('en'):
        return 'en'
    raise ValueError('Unsupported language. Choose en, zh-CN or zh-TW.')


def default_profile(locale: str) -> str:
    return {'en': 'global', 'zh-CN': 'mainland', 'zh-TW': 'traditional'}[normalize_language(locale)]


def resolve_targets(locale: str, profile: str | None = None, custom_hosts: Any = None) -> list[str]:
    if custom_hosts:
        return parse_hosts(','.join(custom_hosts) if isinstance(custom_hosts, (list, tuple)) else str(custom_hosts))
    profile = profile or default_profile(locale)
    if profile not in TARGET_PROFILES:
        raise ValueError(msg('Unknown target profile: {profile}', profile=profile))
    return list(TARGET_PROFILES[profile]['hosts'])


def settings_path() -> Path:
    return Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.config'))) / 'WinNetDiff' / 'settings.json'


def load_settings() -> dict[str, Any]:
    try:
        path = settings_path()
        if path.stat().st_size > 32768:
            return {}
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            return {}
        result = {}
        if data.get('language'):
            result['language'] = normalize_language(data['language'])
        if data.get('profile') in TARGET_PROFILES:
            result['profile'] = data['profile']
        if data.get('hosts'):
            result['hosts'] = parse_hosts(','.join(data['hosts']))
        if data.get('mode') in ('basic', 'expert'):
            result['mode'] = data['mode']
        if type(data.get('retries')) is int and 1 <= data['retries'] <= 4:
            result['retries'] = data['retries']
        if type(data.get('no_network')) is bool:
            result['no_network'] = data['no_network']
        if type(data.get('fake_ip_audit')) is bool:
            result['fake_ip_audit'] = data['fake_ip_audit']
        if data.get('retry_mode') in ('same-ip', 'rotate'):
            result['retry_mode'] = data['retry_mode']
        return result
    except (OSError, ValueError, TypeError):
        return {}


def save_settings(data: dict[str, Any]) -> None:
    allowed = {}
    if data.get('language'):
        allowed['language'] = normalize_language(data['language'])
    if data.get('profile') in TARGET_PROFILES:
        allowed['profile'] = data['profile']
    if data.get('hosts'):
        allowed['hosts'] = parse_hosts(','.join(data['hosts']) if isinstance(data['hosts'], list) else data['hosts'])
    if data.get('mode') in ('basic', 'expert'):
        allowed['mode'] = data['mode']
    if type(data.get('retries')) is int and 1 <= data['retries'] <= 4:
        allowed['retries'] = data['retries']
    if type(data.get('no_network')) is bool:
        allowed['no_network'] = data['no_network']
    if type(data.get('fake_ip_audit')) is bool:
        allowed['fake_ip_audit'] = data['fake_ip_audit']
    if data.get('retry_mode') in ('same-ip', 'rotate'):
        allowed['retry_mode'] = data['retry_mode']
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.' + uuid.uuid4().hex + '.tmp')
    try:
        temp.write_text(json.dumps(allowed, ensure_ascii=False, indent=2), encoding='utf-8')
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def set_output_directory(path: Any) -> None:
    globals()['_OUTPUT_DIR_OVERRIDE'] = Path(path).resolve() if path else None
