"""Optional read-only DNS context. Reserved/private addresses alone are not faults."""
from __future__ import annotations
import dataclasses
import ipaddress
import threading
from typing import Any
from ..core.process import ps_json

FAKE_IP_NETWORK = ipaddress.ip_network('198.18.0.0/15')
PROXY_CORE_PATTERN = r'(?i)^(clash(?:-meta|-win64)?|mihomo|sing-box|singbox|xray|v2ray)(?:\.exe)?$'


def is_fake_ip(address: str) -> bool:
    try:
        return ipaddress.ip_address(address) in FAKE_IP_NETWORK
    except (ValueError, TypeError):
        return False


def dns_probe_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else dataclasses.asdict(value)


def select_target_route(address: str, inventory: dict[str, Any]) -> dict[str, Any]:
    """Longest prefix then effective metric, tied to the actual target interface."""
    try:
        target = ipaddress.ip_address(address)
    except ValueError:
        return {'status': 'invalid_address'}
    if inventory.get('query_status', {}).get('routes') != 'ok' or inventory.get('query_status', {}).get('interfaces') != 'ok':
        return {'status': 'unknown', 'reason': 'Route or interface inventory incomplete'}
    candidates, uncertain_prefixes = [], []
    for row in inventory.get('routes', []):
        network = None
        try:
            network = ipaddress.ip_network(str(row.get('DestinationPrefix')), strict=False)
            if target not in network:
                continue
            interfaces = [i for i in inventory.get('interfaces', []) if i.get('InterfaceIndex') == row.get('InterfaceIndex')
                          and str(i.get('AddressFamily')) in (str(2 if target.version == 4 else 23), 'IPv'+str(target.version))]
            interface = interfaces[0] if len(interfaces) == 1 else None
            if not interface:
                uncertain_prefixes.append(network.prefixlen)
                continue
            connection_state = str(interface.get('ConnectionState', '')).lower()
            if connection_state not in ('connected', '1'):
                if connection_state not in ('disconnected', '0'):
                    uncertain_prefixes.append(network.prefixlen)
                continue
            if str(row.get('State', '')).lower() in ('dead', 'invalid', 'unreachable'):
                continue
            metric = int(row.get('RouteMetric', 0)) + int(interface['InterfaceMetric'])
            adapter = next((a for a in inventory.get('adapters', []) if a.get('ifIndex') == row.get('InterfaceIndex')), {})
            if str(adapter.get('Status', '')).lower() in ('down', 'disconnected', 'disabled', 'not present'):
                continue
            candidates.append((network.prefixlen, metric, row, adapter))
        except (ValueError, TypeError, KeyError):
            uncertain_prefixes.append(network.prefixlen if network is not None else 128)
            continue
    if not candidates:
        return {'status': 'unknown' if uncertain_prefixes else 'no_usable_route'}
    candidates.sort(key=lambda item: (-item[0], item[1], str(item[2].get('InterfaceIndex'))))
    best = candidates[0]
    if any(prefix >= best[0] for prefix in uncertain_prefixes):
        return {'status': 'unknown', 'reason': 'A matching route could not be evaluated'}
    tied = [c for c in candidates if c[:2] == best[:2]]
    if len({(c[2].get('InterfaceIndex'), c[2].get('NextHop')) for c in tied}) > 1:
        return {'status': 'ambiguous', 'candidate_count': len(tied)}
    classification = best[3].get('Classification')
    virtual = True if classification == 'virtual' or best[3].get('Virtual') is True else False if classification == 'physical' else None
    return {'status': 'selected', 'route': best[2], 'effective_metric': best[1],
            'adapter': best[3], 'virtual': virtual}


def collect_dns_runtime(routes: dict[str, Any], cancel: threading.Event | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {'cores': [], 'core_query_complete': False, 'listeners': [],
                              'listener_query_complete': False, 'errors': [], 'core_search_scope': 'Known core process names only; renamed or embedded cores can be missed.'}
    if cancel and cancel.is_set():
        return {**result, 'cancelled': True}
    # Names are clues that a core is present; they never prove a healthy mapping.
    core_query = ("ConvertTo-Json -InputObject @(Get-CimInstance Win32_Process | Where-Object {$_.Name -match '" +
                  PROXY_CORE_PATTERN + "'} | Select-Object Name,ProcessId) -Compress")
    cores, error = ps_json(core_query, 5)
    result.update(cores=cores, core_query_complete=not bool(error))
    if error:
        result['errors'].append('proxy_core_inventory: ' + error)
    loopback_configured = any(_dns_loopback(str(server)) for row in routes.get('dns_servers', [])
                              for server in _server_addresses(row.get('ServerAddresses')))
    if loopback_configured and not (cancel and cancel.is_set()):
        # UDP connect success cannot prove a DNS listener. Enumerate endpoints.
        listeners, error = ps_json("ConvertTo-Json -InputObject @(& { Get-NetUDPEndpoint -ErrorAction Stop | Where-Object {$_.LocalPort -eq 53} | Select-Object LocalAddress,LocalPort,OwningProcess; Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {$_.LocalPort -eq 53} | Select-Object LocalAddress,LocalPort,OwningProcess }) -Compress", 5)
        result.update(listeners=listeners, listener_query_complete=not bool(error))
        if error:
            result['errors'].append('local_dns_listeners: ' + error)
    return result


def _server_addresses(value: Any) -> list[str]:
    """Normalize PowerShell's singleton-or-array DNS server address contract."""
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [address for address in value if isinstance(address, str) and address.strip()]
    return []


def _dns_loopback(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def audit_dns_state(routes: dict[str, Any], probes: list[Any], runtime: dict[str, Any], *,
                    network_tested: bool) -> dict[str, Any]:
    measured = [dns_probe_mapping(p) for p in probes]
    result: dict[str, Any] = {'enabled': True, 'network_tested': network_tested, 'targets': [], 'dns_servers': [],
        'runtime': runtime, 'limitations': ['System resolver results are correlated with configured DNS servers; the actual server answering each query was not captured.',
        '198.18.0.0/15 is a benchmarking range and a Fake-IP clue, not proof of DNS hijacking.']}
    for row in routes.get('dns_servers', []):
        for address in _server_addresses(row.get('ServerAddresses')):
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            status = 'configured_only'
            if parsed.is_loopback:
                listeners = [r for r in runtime.get('listeners', []) if r.get('LocalAddress') in (address, '0.0.0.0' if parsed.version == 4 else '::')]
                status = 'local_listener_present' if listeners else 'local_listener_missing' if runtime.get('listener_query_complete') else 'local_listener_unknown'
            elif parsed.is_private:
                status = 'private_dns_configured'
            adapter = next((a for a in routes.get('adapters', []) if a.get('ifIndex') == row.get('InterfaceIndex')), {})
            interface_states = [i for i in routes.get('interfaces', []) if i.get('InterfaceIndex') == row.get('InterfaceIndex') and str(i.get('AddressFamily')) in (str(2 if parsed.version == 4 else 23), 'IPv'+str(parsed.version))]
            active = any(str(i.get('ConnectionState', '')).lower() in ('connected', '1') for i in interface_states) if interface_states else None
            result['dns_servers'].append({'address': address, 'active_interface': active,
                'adapter_state': adapter.get('Status'), 'virtual': adapter.get('Classification') == 'virtual' if adapter else None, 'interface_index': row.get('InterfaceIndex'),
                'interface_alias': row.get('InterfaceAlias'), 'status': status,
                'address_kind': 'loopback' if parsed.is_loopback else 'benchmarking' if is_fake_ip(address) else 'private' if parsed.is_private else 'public',
                'resolution_observed': any(p.get('resolved_addresses') or p.get('ip') for p in measured),
                'note': 'A configured private/local DNS address alone does not establish a fault.'})
    seen = set()
    for probe in measured:
        addresses = probe.get('resolved_addresses') or [probe.get('ip')]
        for address in addresses:
            if not is_fake_ip(address) or (probe.get('host'), address) in seen:
                continue
            seen.add((probe.get('host'), address))
            route = select_target_route(address, routes)
            attempts = probe.get('attempts') or [probe]
            matching = [a for a in attempts if a.get('ip') == address]
            success = any(str(a.get('stage', '')).startswith('http_') or a.get('stage') == 'tls_ok' for a in matching)
            failed = bool(matching) and all(a.get('stage') in ('tcp_timeout', 'tcp_error') for a in matching)
            core_present = bool(runtime.get('cores'))
            core_absent = runtime.get('core_query_complete') is True and not core_present
            status = 'fake_ip_indeterminate'
            if network_tested and success and (core_present or route.get('virtual')):
                status = 'expected_fake_ip_active_proxy'
            elif network_tested and failed and core_absent and route.get('status') == 'no_usable_route':
                status = 'fake_ip_unroutable_suspected'
            result['targets'].append({'host': probe.get('host'), 'address': address, 'status': status,
                'route_context': route, 'core_present': core_present, 'known_core_absence_observed': core_absent,
                'matching_attempts': matching, 'dns_source': 'system_getaddrinfo',
                'configured_dns': [d for d in result['dns_servers'] if (
                    d['interface_index'] == route['route'].get('InterfaceIndex')
                    if isinstance(route.get('route'), dict) else
                    route.get('status') == 'no_usable_route' and d.get('active_interface') is True)]})
    return result
