"""Local F6/F7 sockets with an explicitly trusted temporary test certificate.

The certificate is supplied by the operator, not installed in Windows trust.
No real proxy configuration, security components, PAC or credentials are used.
"""
from __future__ import annotations
import argparse
import dataclasses
import hashlib
import json
from pathlib import Path
import socket
import ssl
import sys
import threading
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cert',type=Path,required=True)
    parser.add_argument('--key',type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    from winnetdiff.probes import proxy_path,transport
    from winnetdiff.analysis.evidence import assess_phase_evidence
    source=hashlib.sha256((ROOT/'windows_net_diffdiag.py').read_bytes()).hexdigest()
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(args.cert,args.key)
    original_factory=ssl.create_default_context
    trust=lambda:original_factory(cafile=str(args.cert.resolve()))
    stop=threading.Event();servers=[];children=[];requests=[];errors=[]
    def read_header(connection):
        connection.settimeout(3);data=bytearray()
        while not data.endswith(b'\r\n\r\n') and len(data)<16384:
            value=connection.recv(1)
            if not value:break
            data.extend(value)
        return bytes(data)
    def listen(mode,address='127.0.0.1',port=0):
        server=socket.socket(socket.AF_INET,socket.SOCK_STREAM);server.bind((address,port));server.listen(12);server.settimeout(.1);servers.append(server)
        def handle(connection):
            try:
                if mode in ('connect','auth','denied','silence'):
                    header=read_header(connection);requests.append({'kind':mode,'head':header.decode('ascii','replace')})
                    if mode=='auth':connection.sendall(b'HTTP/1.1 407 Authentication Required\r\nProxy-Authenticate: Negotiate\r\n\r\n');return
                    if mode=='denied':connection.sendall(b'HTTP/1.1 403 Forbidden\r\n\r\n');return
                    if mode=='silence':stop.wait(3);return
                    connection.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                with context.wrap_socket(connection,server_side=True) as secure:
                    header=read_header(secure);requests.append({'kind':'origin','head':header.decode('ascii','replace')})
                    secure.sendall(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            except (OSError,ssl.SSLError) as exc:
                # Untrusted-certificate negative controls intentionally abort TLS.
                errors.append(type(exc).__name__)
            finally:
                connection.close()
        def accept():
            while not stop.is_set():
                try: connection,_=server.accept()
                except socket.timeout:continue
                except OSError:break
                worker=threading.Thread(target=handle,args=(connection,),daemon=True);children.append(worker);worker.start()
        threading.Thread(target=accept,daemon=True).start()
        return server.getsockname()[1]
    ports={mode:listen(mode) for mode in ('direct','connect','auth','denied','silence')}
    checks={}
    try:
        info=(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',ports['direct']))
        with patch.object(transport.ssl,'create_default_context',side_effect=trust):
            direct=transport.probe_endpoint('localhost.test',socket.AF_INET,info,0,connect_timeout=1,tls_timeout=1,http_timeout=1,overall_timeout=4)
        endpoints={name:{'scheme':'http','host':'127.0.0.1','port':port} for name,port in ports.items()}
        with patch.object(proxy_path,'_proxy_tls_context',side_effect=trust):
            successful=proxy_path.probe_proxy_path('localhost.test',endpoints['connect'],confirmed=True,phase_timeout=1,overall_timeout=4)
        auth=proxy_path.probe_proxy_path('localhost.test',endpoints['auth'],confirmed=True)
        denied=proxy_path.probe_proxy_path('localhost.test',endpoints['denied'],confirmed=True)
        untrusted=proxy_path.probe_proxy_path('localhost.test',endpoints['connect'],confirmed=True,phase_timeout=1,overall_timeout=4)
        cancel=threading.Event();timer=threading.Timer(.1,cancel.set);timer.start();started=time.perf_counter()
        cancelled=proxy_path.probe_proxy_path('localhost.test',endpoints['silence'],confirmed=True,cancel=cancel,phase_timeout=.5,overall_timeout=2)
        cancel_seconds=time.perf_counter()-started;timer.join()
        limited=proxy_path.probe_proxy_path('localhost.test',endpoints['silence'],confirmed=True,phase_timeout=1,overall_timeout=.2)
        checks['proxy_protocol']={'direct_stage':direct.stage,'connect_result':successful,'auth_result':auth,'denied_result':denied,
            'untrusted_certificate_result':untrusted,'cancel_status':cancelled['status'],'cancel_seconds':round(cancel_seconds,3),
            'overall_status':limited['status'],'credentials_seen':any('proxy-authorization:' in item['head'].lower() for item in requests),
            'passed':direct.stage=='http_ok' and successful['status']=='proxy_http_observed' and successful['tls_verified'] and
                auth['status']=='proxy_auth_required' and denied['status']=='proxy_policy_denied' and untrusted['status']=='proxy_tls_cert_error' and
                cancelled['status']=='cancelled' and cancel_seconds<2 and limited['status']=='overall_timeout' and not any('proxy-authorization:' in item['head'].lower() for item in requests)}
        # The first loopback address refuses; the second serves verified TLS on
        # the exact same port. DNS answer injection is the only test boundary.
        # Sockets, TLS, HTTP and timers below are real, with no network settings.
        alternate_port=listen('direct','127.0.0.2')
        answers=[(socket.AF_INET,socket.SOCK_STREAM,6,'',(host,alternate_port)) for host in ('127.0.0.1','127.0.0.2')]
        modes=[]
        for mode in ('same-ip','rotate'):
            with patch.object(transport,'timeout_dns',return_value=(answers,'',0)),patch.object(transport.ssl,'create_default_context',side_effect=trust):
                result=transport.probe_host_family('localhost.test',socket.AF_INET,retries=2,retry_mode=mode,
                    dns_timeout=1,connect_timeout=.3,tls_timeout=.5,http_timeout=.5,overall_timeout=4)
            modes.append({'mode':mode,'attempt_ips':[a['ip'] for a in result.attempts],
                          'attempt_stages':[a['stage'] for a in result.attempts],'selected_stage':result.stage,
                          'grade':assess_phase_evidence([result],{'tcp_error','tcp_timeout'})['grade']})
        # Windows may defer refusal beyond the chosen 300 ms TCP budget. Both
        # outcomes are measured failures; require one identical stage on one IP.
        pinned_failures=modes[0]['attempt_stages']
        checks['native_retry_paths']={'cases':modes,'passed':modes[0]['attempt_ips']==['127.0.0.1']*2 and len(pinned_failures)==2 and len(set(pinned_failures))==1 and pinned_failures[0] in ('tcp_error','tcp_timeout') and modes[0]['grade']=='E2' and modes[1]['attempt_ips']==['127.0.0.1','127.0.0.2'] and modes[1]['selected_stage']=='http_ok' and modes[1]['grade']=='E1'}
    finally:
        stop.set()
        for server in servers:server.close()
        for child in children:child.join(4)
    summary={'source_sha256':source,'scope':'Controlled loopback listeners and temporary TLS trust; no system network/security configuration, real proxy credentials or PAC. Fixed DNS answers only in the retry experiment.',
             'test_certificate_sha256':hashlib.sha256(args.cert.read_bytes()).hexdigest(),'checks':checks,
             'server_expected_tls_rejections':errors,'source_changed_during_run':source!=hashlib.sha256((ROOT/'windows_net_diffdiag.py').read_bytes()).hexdigest()}
    summary['passed']=all(row['passed'] for row in checks.values()) and not summary['source_changed_during_run']
    (out/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8');print(json.dumps(summary,indent=2))
    return 0 if summary['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
