"""Explicit, credential-free HTTP CONNECT evidence, separate from direct probes."""
from __future__ import annotations
import dataclasses
import datetime as dt
import fnmatch
import ipaddress
import re
import socket
import ssl
import time
import urllib.parse
from typing import Any
from winnetdiff.probes.transport import timeout_dns
from winnetdiff.core.config import parse_hosts
from winnetdiff.core.models import Finding, VERSION
from winnetdiff.core.messages import msg


def _proxy_target(target: str) -> str:
    hosts = parse_hosts(target)
    if len(hosts) != 1:
        raise ValueError('Proxy path target must be one domain')
    return hosts[0]


def proxy_bypass(host: str, rules: str, *, windows: bool = False, port: int = 443) -> bool:
    """Documented diagnostic matching, not a claim about every client library."""
    host = host.casefold().rstrip('.')
    for rule in re.split(r'[;,]', str(rules or '')):
        rule = rule.strip().casefold()
        if not rule: continue
        if rule == '*': return True
        if windows and rule == '<local>' and '.' not in host and ':' not in host: return True
        try:
            if '/' in rule and ipaddress.ip_address(host) in ipaddress.ip_network(rule, strict=False): return True
        except ValueError: pass
        if rule.count(':') == 1 and rule.rsplit(':', 1)[1].isdigit():
            rule, selected_port = rule.rsplit(':', 1)
            if int(selected_port) != port: continue
        if windows:
            if fnmatch.fnmatchcase(host, rule): return True
        elif host == rule.lstrip('.') or host.endswith('.' + rule.lstrip('.')):
            return True
    return False


def _proxy_endpoint(value: str) -> dict:
    """Drop credentials before returning any data; reject ambiguous URL syntax."""
    try:
        explicit = '://' in value
        url = urllib.parse.urlsplit(value if explicit else 'http://' + value)
        host, port = url.hostname, url.port
        if not host or any(c.isspace() or ord(c) < 32 for c in value) or url.path not in ('', '/') or url.query or url.fragment:
            return {'status': 'invalid_proxy_configuration'}
        credentials = url.username is not None or url.password is not None
        scheme = url.scheme.casefold()
        port = port or (80 if explicit and scheme == 'http' else 443 if explicit and scheme == 'https' else None)
        if not port or not 1 <= port <= 65535: return {'status': 'invalid_proxy_configuration'}
        status = ('credentials_not_sent' if credentials else 'unsupported_proxy_scheme' if scheme != 'http' else 'eligible')
        return {'status': status, 'scheme': scheme, 'host': host, 'port': port,
                'credentials_sent': False, 'credentials_configured': credentials}
    except (ValueError, TypeError):
        return {'status': 'invalid_proxy_configuration'}


def proxy_path_plan(proxy: dict, target: str) -> dict:
    target = _proxy_target(target)
    rows = []
    def add(source, value, bypass='', windows=False, active=True, automatic=False):
        if automatic:
            rows.append({'source': source, 'status': 'auto_proxy_unresolved', 'eligible': False})
        if not value: return
        candidates = []
        for token in re.split(r'[;\s]+', str(value)):
            if not token: continue
            if '=' in token and '://' not in token.split('=', 1)[0]:
                mapping, token = token.split('=', 1)
                if mapping.casefold() != 'https': continue
            candidates.append(token)
        for value in candidates[:8]:
            row = {'source': source, **_proxy_endpoint(value), 'target': target}
            if not active: row['status'] = 'stored_or_inactive'
            elif automatic: row['status'] = 'auto_proxy_unresolved'
            elif proxy_bypass(target, bypass, windows=windows): row['status'] = 'bypassed_for_target'
            row['eligible'] = row['status'] == 'eligible'
            rows.append(row)
        if len(candidates) > 8: rows.append({'source':source, 'status':'configuration_limit', 'eligible':False})
    manual = proxy.get('wininet', {})
    api = proxy.get('wininet_api', {})
    flags = api.get('flags', 0) if not api.get('error') else 0
    add('WinINET', manual.get('ProxyServer') or api.get('ProxyServer'), manual.get('ProxyOverride') or api.get('ProxyOverride') or '',
        windows=True, active=manual.get('ProxyEnable') == 1 and bool(flags & 2),
        automatic=bool(manual.get('AutoConfigURL') or api.get('AutoConfigURL') or flags & 12))
    winhttp = proxy.get('winhttp_config', {})
    if winhttp.get('ok'):
        add('WinHTTP-default', winhttp.get('proxy'), winhttp.get('bypass', ''), windows=True, active=winhttp.get('access_type') == 3)
    else:
        rows.append({'source':'WinHTTP-default','status':'configuration_unknown','eligible':False})
    for scope in ('process', 'user', 'machine'):
        environment = proxy.get('environ_' + scope, {})
        add('env:' + scope, environment.get('HTTPS_PROXY') or environment.get('ALL_PROXY'), environment.get('NO_PROXY', ''), active=scope == 'process')
    return {'target': target, 'paths': rows[:64], 'network_tested': False,
            'limitations': ['Direct socket results do not establish application proxy behaviour.',
                'PAC/WPAD is not downloaded or executed. WinHTTP sessions and applications may override defaults.',
                'NO_PROXY and bypass matching vary by application; these are diagnostic interpretations.',
                'Only explicit HTTP CONNECT is supported; no credentials or automatic authentication are sent.']}


class _ProxyPathStop(Exception): pass


def _proxy_tls_context():
    return ssl.create_default_context()


def probe_proxy_path(target: str, endpoint: dict, *, confirmed: bool = False, cancel=None,
                     phase_timeout: float = 3, overall_timeout: float = 12) -> dict:
    target = _proxy_target(target)
    result = {'target': target, 'proxy': {k:endpoint[k] for k in ('scheme','host','port') if k in endpoint},
        'status':'not_confirmed', 'credentials_sent':False, 'target_ip_observed':False,
        'observed_at':dt.datetime.now(dt.timezone.utc).isoformat(), 'timings_ms':{}, 'tls_verified':False,
        'budgets': {'phase_seconds': phase_timeout, 'overall_seconds': overall_timeout}}
    if not confirmed: return result
    # Re-validate structured callers too, so neither CRLF nor credentials enter argv/headers.
    host, port = endpoint.get('host'), endpoint.get('port')
    if endpoint.get('scheme') != 'http' or not isinstance(host,str) or any(c.isspace() or ord(c)<32 or c in '/@\\?#' for c in host) or not host or type(port) is not int or not 1 <= port <= 65535 or endpoint.get('credentials_configured'):
        result['status']='unsupported_or_invalid_proxy'; return result
    if not 0 < phase_timeout <= 10 or not 0 < overall_timeout <= 30:
        raise ValueError('Proxy probe timeout is outside the bounded budget')
    started=time.perf_counter(); deadline=started+overall_timeout
    phase, phase_end, raw, secure = 'dns', min(deadline,started+phase_timeout), None, None
    def budget():
        if cancel and cancel.is_set(): raise _ProxyPathStop('cancelled')
        now=time.perf_counter()
        if now >= deadline and deadline <= phase_end: raise _ProxyPathStop('overall_timeout')
        if now >= phase_end: raise _ProxyPathStop('proxy_' + phase + '_timeout')
        if now >= deadline: raise _ProxyPathStop('overall_timeout')
        return min(deadline,phase_end)-now
    def headers(connection):
        data=bytearray()
        while not data.endswith(b'\r\n\r\n') and len(data)<16384:
            connection.settimeout(budget()); chunk=connection.recv(1)
            if not chunk: break
            data.extend(chunk)
        if not data.endswith(b'\r\n\r\n'): raise ValueError('Incomplete or oversized HTTP headers')
        line=bytes(data).split(b'\r\n',1)[0]
        match=re.fullmatch(rb'HTTP/1\.[01] ([1-5][0-9]{2})(?:[ \t].*)?',line)
        if not match: raise ValueError('Malformed HTTP status')
        return int(match[1]),bytes(data)
    try:
        budget()
        addresses,error,dns_ms=timeout_dns(host,socket.AF_UNSPEC,min(phase_timeout,budget()),cancel)
        result['timings_ms']['dns']=dns_ms
        budget()
        if error or not addresses:
            result['status']='cancelled' if error.startswith('Cancelled:') else 'proxy_dns_busy' if error.startswith('DNSBusy:') else 'proxy_dns_timeout' if error.startswith('DNSTimeout:') else 'proxy_dns_error'
            result['error_type']=error.split(':',1)[0] if error else 'NoAddress';return result
        info=addresses[0]; address=(info[4][0],port,*info[4][2:])
        phase='tcp';phase_start=time.perf_counter();phase_end=phase_start+phase_timeout
        raw=socket.socket(info[0],socket.SOCK_STREAM,socket.IPPROTO_TCP);raw.settimeout(budget());raw.connect(address)
        result['timings_ms']['tcp']=round((time.perf_counter()-phase_start)*1000,1)
        phase='connect';phase_start=time.perf_counter();phase_end=phase_start+phase_timeout
        raw.settimeout(budget());raw.sendall((f'CONNECT {target}:443 HTTP/1.1\r\nHost: {target}:443\r\nUser-Agent: WinNetDiff/{VERSION}\r\n\r\n').encode('ascii'))
        for _ in range(4):
            status,header=headers(raw)
            if status>=200: break
        result['connect_status']=status;result['timings_ms']['connect']=round((time.perf_counter()-phase_start)*1000,1)
        if status==407:
            result['status']='proxy_auth_required'
            result['auth_schemes']=sorted({match.decode('ascii').lower() for match in re.findall(rb'(?im)^Proxy-Authenticate:\s*(Basic|Digest|NTLM|Negotiate)\b',header)})
            return result
        if not 200<=status<300:
            result['status']='proxy_policy_denied' if status==403 else 'proxy_connect_rejected';return result
        phase='tls';phase_start=time.perf_counter();phase_end=phase_start+phase_timeout
        raw.settimeout(budget());secure=_proxy_tls_context().wrap_socket(raw,server_hostname=target,do_handshake_on_connect=False)
        secure.settimeout(budget());secure.do_handshake();budget()
        result['tls_verified']=True;result['tls_version']=secure.version()
        result['timings_ms']['tls']=round((time.perf_counter()-phase_start)*1000,1)
        phase='http';phase_start=time.perf_counter();phase_end=phase_start+phase_timeout
        secure.settimeout(budget());secure.sendall((f'HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\nUser-Agent: WinNetDiff/{VERSION}\r\n\r\n').encode('ascii'))
        status,_=headers(secure);budget();result['http_status']=status;result['status']='proxy_http_observed'
        result['timings_ms']['http']=round((time.perf_counter()-phase_start)*1000,1)
    except _ProxyPathStop as exc: result['status']=str(exc)
    except ssl.SSLCertVerificationError: result['status']='proxy_tls_cert_error'
    except (OSError,ValueError) as exc:
        result['status']='proxy_' + phase + ('_timeout' if isinstance(exc,TimeoutError) else '_error')
        if isinstance(exc,TimeoutError) and time.perf_counter()>=deadline and deadline<=phase_end: result['status']='overall_timeout'
        result['error_type']=type(exc).__name__
    finally:
        if cancel and cancel.is_set(): result['status']='cancelled'
        for connection in (secure,raw):
            if connection is not None:
                try: connection.close()
                except OSError: pass
        result['total_ms']=round((time.perf_counter()-started)*1000,1)
    return result


def diagnose_proxy_paths(proxy: dict, probes: list, target: str, *, confirmed: bool = False, cancel=None) -> dict:
    target = _proxy_target(target)
    plan=proxy_path_plan(proxy,target); tested=[];seen=set()
    direct=[dataclasses.asdict(p) if dataclasses.is_dataclass(p) else p for p in probes]
    direct=[p for p in direct if p.get('host')==target]
    for row in plan['paths']:
        if not confirmed or not row['eligible'] or len(tested)>=2 or cancel and cancel.is_set(): continue
        identity=row['host'],row['port']
        if identity in seen: continue
        seen.add(identity)
        result=probe_proxy_path(target,row,confirmed=True,cancel=cancel);result['source']=row['source'];tested.append(result)
    plan['network_tested']=bool(tested);plan['tests']=tested;plan['cancelled']=bool(cancel and cancel.is_set())
    direct_ok=any(p.get('stage')=='http_ok' for p in direct)
    proxy_ok=any(p.get('status')=='proxy_http_observed' for p in tested)
    plan['direct_stages']=[{'family':p.get('family'),'stage':p.get('stage')} for p in direct]
    plan['comparison']=('both_paths_http_observed' if direct_ok and proxy_ok else 'proxy_only_http_observed' if proxy_ok else
        'authentication_required' if any(p['status']=='proxy_auth_required' for p in tested) else
        'direct_only_http_observed' if direct_ok and any(p['status'] not in ('cancelled','overall_timeout','proxy_dns_busy') for p in tested) else 'not_compared')
    plan['limitations'].append('The proxy resolves the CONNECT target; target IP and route equivalence are unknown. Latencies and E2/E3 are not compared across these paths.')
    return plan


def proxy_path_findings(context: dict) -> list[Finding]:
    if not context: return []
    explanations = {
        'both_paths_http_observed': 'HTTP was observed on both direct and proxy paths; this does not verify every application.',
        'proxy_only_http_observed': 'HTTP was observed through the proxy while direct HTTP was not observed; path differences do not prove a cause.',
        'authentication_required': 'The proxy requires authentication. No credentials were sent; this is not evidence of a dead proxy.',
        'direct_only_http_observed': 'Direct HTTP was observed but the tested proxy path did not complete HTTP; review its separate protocol stages.',
        'not_compared': 'No comparable proxy test was completed. Review static configuration, bypass rules and unresolved PAC.'}
    return [Finding('資訊','代理',msg('Proxy path comparison'),__import__('json').dumps(context,ensure_ascii=False),
        msg('{summary} {scope}', summary=msg(explanations.get(context.get('comparison'),'No comparable proxy test was completed. Review static configuration, bypass rules and unresolved PAC.')),
            scope=msg('Proxy settings and direct socket results describe different paths. Authentication, PAC and application overrides must be interpreted separately.')),
        code='proxy.paths.'+context.get('comparison','not_compared'),risk='read_only')]
