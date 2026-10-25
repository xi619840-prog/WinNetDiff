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


APP_NAME = 'WinNetDiff'


VERSION = '2.2.0a3'


DEFAULT_HOSTS = 'www.microsoft.com,www.cloudflare.com,www.wikipedia.org'


VENDOR_PATTERN = re.compile(
    r'surfshark|avira|bdnet|bdsentry|endpointprotection|sangfor|深信服|'
    r'ruijie|锐捷|銳捷|geevpn|闪连|閃連|flclash|clash|proton|wintun|wireguard|'
    r'openvpn|\btap\b|\btun\b', re.I)


VIRTUAL_PATTERN = re.compile(
    r'wintun|wireguard|\btap\b|\btun\b|vpn|clash|vethernet|hyper-v|virtualbox|'
    r'vmware|tailscale|zerotier|docker', re.I)


LOCAL_IPS = {'127.0.0.1', '::1', 'localhost'}


INET_PATH = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'


POLICY_PATH = r'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'


PROXY_KEYS = ['ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect']


ENV_KEYS = ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'NODE_OPTIONS']


SEVERITIES = {'已確認設定異常': 0, '高優先級': 1, '可疑': 2, '資訊': 3,
              '高': 1, '中': 2, '信息': 3}


@dataclass
class Finding:
    severity: str
    layer: str
    title: str
    evidence: str
    interpretation: str
    commands: list[str] = field(default_factory=list)
    rollback: str = ''
    confidence: str = '中'
    action: str = ''
    priority: int = 3
    code: str = ''
    evidence_grade: str = 'E1'
    reasoning: str = ''
    alternatives: list[str] = field(default_factory=list)
    verification: list[str] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)
    risk: str = 'read_only'


@dataclass
class Probe:
    host: str
    family: str
    ip: str = ''
    stage: str = 'unrun'
    dns_ms: Optional[float] = None
    tcp_ms: Optional[float] = None
    tls_ms: Optional[float] = None
    http_ms: Optional[float] = None
    tls_version: str = ''
    http_line: str = ''
    error: str = ''
    error_type: str = ''
    timeout_stage: str = ''
    attempt: int = 1
    total_ms: Optional[float] = None
    http_status: Optional[int] = None
    attempts: list[dict[str, Any]] = field(default_factory=list)
    intermittent: bool = False
    context: dict[str, Any] = field(default_factory=dict)
    resolved_addresses: list[str] = field(default_factory=list)


@dataclass
class Report:
    version: str
    generated_at: str
    device: str
    administrator: bool
    hosts: list[str]
    proxy: dict[str, Any]
    route: dict[str, Any]
    probes: list[Probe]
    security: dict[str, Any]
    findings: list[Finding]
    limitations: list[str]
    layers: dict[str, Any] = field(default_factory=dict)
    repair_history: list[dict[str, Any]] = field(default_factory=list)
    cancelled: bool = False
    locale: str = 'en'
    scan_options: dict[str, Any] = field(default_factory=dict)
    scenarios: list[dict[str, Any]] = field(default_factory=list)
    verification: dict[str, Any] = field(default_factory=dict)
    dns_audit: dict[str, Any] = field(default_factory=dict)
    pmtu: list[dict[str, Any]] = field(default_factory=list)
    proxy_paths: dict[str, Any] = field(default_factory=dict)
