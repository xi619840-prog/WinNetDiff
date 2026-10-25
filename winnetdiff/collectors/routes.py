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
from winnetdiff.collectors.security import inspect_inf_provider
from winnetdiff.core.models import VIRTUAL_PATTERN
from winnetdiff.core.process import ps_json, run_command


def parse_route_print(raw: str) -> list[dict[str, Any]]:
    result = []
    for line in raw.splitlines():
        match = re.match(r'^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\S+)\s+(\d+)\s*$', line)
        if match:
            result.append({'Gateway': match[1], 'SourceIP': match[2], 'EffectiveMetric': int(match[3]),
                           'InterfaceAlias': '(route print fallback)', 'InterfaceIndex': None})
    return result


def ps_quote(value: Any) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def binding_preview(binding: dict[str, Any]) -> dict[str, Any]:
    name, component = str(binding.get('Name', '')), str(binding.get('ComponentID', ''))
    if not name or not component or any(c in name + component for c in '\r\n\x00'):
        return {'eligible': False, 'reason': 'Invalid binding identity'}
    # -Name accepts wildcards even in quotes; use an exact filtered InputObject instead.
    select = (f"$b = Get-NetAdapterBinding -IncludeHidden -AllBindings | Where-Object {{ "
              f"$_.Name -ceq {ps_quote(name)} -and $_.ComponentID -ceq {ps_quote(component)} }}; "
              "if (@($b).Count -ne 1) { throw 'Binding identity not unique' }; ")
    return {'eligible': bool(binding.get('Enabled')), 'original': {k: v for k, v in binding.items() if k != 'IsolationPreview'},
            'disable': select + '$b | Disable-NetAdapterBinding -Confirm',
            'restore': select + '$b | Enable-NetAdapterBinding -Confirm',
            'warning': '需額外人工確認；先將 original 匯出為 JSON 並備妥本機管理權限，可能立即斷線。'}


# Fixed-depth reads: classes -> instances -> exact Ndi child, never Ndi/params.
BINDING_COMPONENT_QUERY = r"""
$roots=@('HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}',
         'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e973-e325-11ce-bfc1-08002be10318}',
         'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}',
         'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e975-e325-11ce-bfc1-08002be10318}',
         'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}')
$count=0
foreach($root in $roots) {
  try { $classes=@(Get-Item -LiteralPath $root -ErrorAction Stop) } catch { [pscustomobject]@{MetadataError='Metadata class unavailable'}; continue }
  foreach($class in $classes) {
    try { $metadataReadErrors=@(); $instances=@(Get-ChildItem -LiteralPath $class.PSPath -ErrorAction SilentlyContinue -ErrorVariable metadataReadErrors); if($metadataReadErrors.Count) { [pscustomobject]@{MetadataError='Some metadata instance entries unavailable'} } } catch { [pscustomobject]@{MetadataError='Metadata class enumeration denied'}; continue }
    foreach($instance in $instances) {
      $count++; if($count -gt 2048) { throw 'Network metadata instance limit exceeded' }
      if($instance.PSChildName -notmatch '^(\{[0-9a-f-]{36}\}|[0-9]{4})$') { continue }
      $ndi=Join-Path $instance.PSPath 'Ndi'
      try { if(Test-Path -LiteralPath $ndi -ErrorAction Stop) {
        $p=Get-ItemProperty -LiteralPath $instance.PSPath -ErrorAction Stop
        $n=Get-ItemProperty -LiteralPath $ndi -ErrorAction Stop
        if($p.ComponentId) { [pscustomobject]@{ComponentID=$p.ComponentId;ProviderName=$p.ProviderName;Description=$p.Description;Service=$n.Service;CoServices=$n.CoServices;InfPath=$p.InfPath} }
      } } catch { [pscustomobject]@{MetadataError='Metadata component read denied'} }
    }
  }
}
"""


def collect_routes(cancel: Optional[threading.Event] = None) -> dict[str, Any]:
    result: dict[str, Any] = {'errors': [], 'metadata_errors': [], 'query_status': {}}
    queries = {
        'adapters': 'Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,Status,ifIndex,HardwareInterface,Virtual,PhysicalMediaType,InterfaceGuid',
        'interfaces': 'Get-NetIPInterface | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,InterfaceMetric,ConnectionState,NlMtu,Dhcp',
        'routes': 'Get-NetRoute -PolicyStore ActiveStore | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,DestinationPrefix,NextHop,RouteMetric,State,PolicyStore',
        'bindings': 'Get-NetAdapterBinding -IncludeHidden -AllBindings | Select-Object Name,InterfaceDescription,DisplayName,ComponentID,Enabled',
        'ipv6_addresses': 'Get-NetIPAddress -AddressFamily IPv6 | Select-Object InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength,AddressState',
        'binding_components': BINDING_COMPONENT_QUERY,
    }
    # Component metadata is a bounded best effort; no missing publisher implies malware.
    for key, query in queries.items():
        if cancel and cancel.is_set():
            result[key] = []
            result['query_status'][key] = 'cancelled'
            result['metadata_errors' if key == 'binding_components' else 'errors'].append(key + ': cancelled')
            continue
        rows, err = ps_json(f'ConvertTo-Json -InputObject @({query}) -Depth 5 -Compress', 14)
        if key == 'binding_components':
            notes = [str(row['MetadataError']) for row in rows if row.get('MetadataError')]
            result['metadata_errors'].extend(notes)
            rows = [row for row in rows if not row.get('MetadataError')]
            if notes and not err:
                err = 'Optional metadata partly unavailable'
        result[key] = rows
        result['query_status'][key] = 'error' if err else 'ok'
        if err:
            result['metadata_errors' if key == 'binding_components' else 'errors'].append(key + ': ' + err)
    for adapter in result['adapters']:
        text = f"{adapter.get('Name')} {adapter.get('InterfaceDescription')}"
        adapter['Classification'] = ('physical' if adapter.get('HardwareInterface') is True
                                     else 'virtual' if adapter.get('Virtual') is True or VIRTUAL_PATTERN.search(text)
                                     else 'unknown')
    for row in result['routes']:
        interface = next((i for i in result['interfaces'] if i.get('InterfaceIndex') == row.get('InterfaceIndex')
                          and i.get('AddressFamily') == row.get('AddressFamily')), {})
        row['InterfaceMetric'] = interface.get('InterfaceMetric')
        row['EffectiveMetric'] = (int(row.get('RouteMetric', 0)) + int(row['InterfaceMetric'])
                                  if row['InterfaceMetric'] is not None else None)
        row['Gateway'] = row.get('NextHop')
        row['ConnectionState'] = interface.get('ConnectionState')
    result['defaults_ipv4'] = [r for r in result['routes'] if r.get('DestinationPrefix') == '0.0.0.0/0']
    result['defaults_ipv6'] = [r for r in result['routes'] if r.get('DestinationPrefix') == '::/0']
    raw = run_command(['route', 'print', '-4'], 8)
    result['route_print_raw'] = raw['stdout']
    result['route_print_command'] = raw
    if result['query_status']['routes'] != 'ok' and raw['ok']:
        result['defaults_ipv4'] = parse_route_print(raw['stdout'])
        result['query_status']['defaults_ipv4_fallback'] = 'ok'
    for binding in result['bindings']:
        component = str(binding.get('ComponentID', ''))
        meta = next((m for m in result['binding_components'] if str(m.get('ComponentID', '')).lower() == component.lower()), {})
        if meta.get('InfPath') and not meta.get('ProviderName'):
            owner = inspect_inf_provider(meta['InfPath'])
            if owner.get('ProviderName'):
                meta.update(ProviderName=owner['ProviderName'], ProviderSource=owner.get('ProviderSource'))
            elif owner.get('Error'):
                meta['ProviderQueryError'] = owner['Error']
        binding['OwnerEvidence'] = meta
        binding['Classification'] = ('windows' if component.lower().startswith('ms_') or component.lower() in ('vms_pp', 'vms_vsp') else
                                     'known-third-party' if re.search(r'vbox|virtualbox|npcap|npf|vmware|docker|hyper', component + str(binding.get('DisplayName')), re.I)
                                     else 'unknown-third-party')
        if binding['Classification'] != 'windows':
            binding['IsolationPreview'] = binding_preview(binding)
    result['ipv6_bindings'] = [b for b in result['bindings'] if b.get('ComponentID') == 'ms_tcpip6']
    if not (cancel and cancel.is_set()):
        dns, dns_error = ps_json('ConvertTo-Json -InputObject @(Get-DnsClientServerAddress | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,ServerAddresses) -Depth 4 -Compress', 12)
        result['dns_servers'] = dns
        result['query_status']['dns_servers'] = 'error' if dns_error else 'ok'
        if dns_error:
            result['errors'].append('dns_servers: ' + dns_error)
    else:
        result['dns_servers'] = []
        result['query_status']['dns_servers'] = 'cancelled'
    return result
