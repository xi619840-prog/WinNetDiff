"""Controlled local Windows review evidence; no repairs or desktop automation.

Optional cmarkgfm is a QA-only dependency, never an application dependency.
Local TCP listeners withhold TLS responses; they do not alter the network.
"""
from __future__ import annotations
import argparse
import dataclasses
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from html.parser import HTMLParser
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    source = hashlib.sha256((ROOT/'windows_net_diffdiag.py').read_bytes()).hexdigest()
    os.environ['WINNETDIFF_PSEUDONYM_KEY_FILE'] = str(out/'runtime'/'pseudonym.key')
    from winnetdiff.core import process, engine, privacy
    from winnetdiff.probes import transport
    from tests.unit.test_markdown_export import hostile_report
    from winnetdiff.reports.export import markdown_report
    import cmarkgfm
    from cmarkgfm.cmark import Options

    evidence = {'source_sha256': source, 'scope': 'Real loopback sockets, native read-only system tools, controlled GFM rendering and withdrawn Tk only. No network/security settings, clipboard, UAC or drivers changed.', 'checks': {}}
    commands = [['whoami', '/user'], ['route', 'print', '-4'], ['netsh', 'winhttp', 'show', 'proxy'],
                ['ping', '-n', '1', '127.0.0.1'], ['driverquery', '/fo', 'csv', '/nh'],
                ['tasklist', '/fo', 'csv', '/nh'], ['netstat', '-ano'], ['ipconfig', '/all']]
    tools = []
    for command in commands:
        result = process.run_command(command, timeout=30)
        tools.append({'tool': command[0], 'resolved': process.prepare_argv(command)[0],
                      'ok': result['ok'], 'returncode': result['returncode'], 'encoding': result['stdout_encoding']})
    ps = process.powershell("[pscustomobject]@{Text='服務_王濤';Bits=[IntPtr]::Size*8} | ConvertTo-Json -Compress")
    tools.append({'tool': 'powershell', 'resolved': process.resolve_system_tool('powershell'), 'ok': ps['ok'], 'unicode_roundtrip': '服務_王濤' in ps['stdout']})
    evidence['checks']['system_tools'] = {'python_bits': 8*__import__('struct').calcsize('P'), 'system_directory': process.system_directory(), 'results': tools, 'passed': all(t['ok'] for t in tools) and tools[-1]['unicode_roundtrip'], 'wow64_executed': False}

    # The parser observes actual cmark-gfm output, rather than approximating
    # Markdown with a regular expression. Evidence/commands remain code blocks.
    class Tags(HTMLParser):
        def __init__(self):
            super().__init__(); self.bad = []; self.tables = 0
        def handle_starttag(self, tag, attrs):
            if tag in ('a', 'script', 'img', 'iframe', 'b'):
                self.bad.append(tag)
            if tag == 'table': self.tables += 1
    rendered = []
    privacy.set_pseudonym_key(bytes(range(32)), 'validation')
    for language in ('en', 'zh-CN', 'zh-TW'):
        for full in (False, True):
            report = hostile_report(language)
            report.findings[0].title += ' https://evil.invalid/fix.exe www.evil.invalid user@evil.invalid <script>bad()</script>'
            markdown = markdown_report(report, full=full)
            html = cmarkgfm.github_flavored_markdown_to_html(markdown, options=Options.CMARK_OPT_UNSAFE)
            tags = Tags(); tags.feed(html)
            (out/f'gfm_{language}_{full}.md').write_text(markdown, encoding='utf-8')
            (out/f'gfm_{language}_{full}.html').write_text(html, encoding='utf-8')
            rendered.append({'language': language, 'full': full, 'forbidden_tags': tags.bad, 'tables': tags.tables})
    # GFM's tagfilter always filters script, even with unsafe HTML enabled.
    # Use an otherwise allowed raw tag to prove escaping is actually tested.
    control = Tags(); control.feed(cmarkgfm.github_flavored_markdown_to_html('<b>control</b>\n\nhttps://evil.invalid', options=Options.CMARK_OPT_UNSAFE))
    control_ok = 'b' in control.bad and 'a' in control.bad
    evidence['checks']['gfm'] = {'renderer': 'cmarkgfm', 'version': importlib.metadata.version('cmarkgfm'),
        'unsafe_html_enabled': True, 'unescaped_control_detected': control_ok, 'cases': rendered,
        'passed': control_ok and all(not r['forbidden_tags'] and r['tables']==1 for r in rendered)}
    privacy.set_pseudonym_key(None)

    stop = threading.Event(); sockets = []; accepted = []; held = []
    for family, address in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
        server = socket.socket(family, socket.SOCK_STREAM)
        if family == socket.AF_INET6: server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        server.bind((address, 0)); server.listen(16); server.settimeout(.1)
        sockets.append(server)
        def accept_loop(server=server):
            while not stop.is_set():
                try:
                    connection, _ = server.accept(); accepted.append(time.perf_counter()); held.append(connection)
                except socket.timeout: pass
                except OSError: break
        threading.Thread(target=accept_loop, daemon=True).start()
    ports = {server.family: server.getsockname()[1] for server in sockets}
    def native_probe(host, family, retries=2, cancel=None, retry_mode='same-ip'):
        address = ('127.0.0.1', ports[family]) if family == socket.AF_INET else ('::1', ports[family], 0, 0)
        info = (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', address)
        return transport.probe_endpoint(host, family, info, 0.0, connect_timeout=.4,
                                        tls_timeout=.6, http_timeout=.4, overall_timeout=2, cancel=cancel)
    hosts = ['first.example', 'second.example', 'third.example']
    try:
        started = time.perf_counter()
        sequential = [native_probe(host, family) for host in hosts for family in (socket.AF_INET, socket.AF_INET6)]
        sequential_seconds = time.perf_counter()-started
        started = time.perf_counter()
        with patch.object(engine, 'probe_host_family', native_probe):
            parallel = engine.run_probes(hosts, 1, threading.Event(), lambda _: None)
        parallel_seconds = time.perf_counter()-started
        cancel = threading.Event(); timer = threading.Timer(.15, cancel.set); timer.start()
        started = time.perf_counter()
        with patch.object(engine, 'probe_host_family', native_probe):
            cancelled = engine.run_probes(hosts, 1, cancel, lambda _: None)
        cancel_seconds = time.perf_counter()-started; timer.join()
        serial_stage = [p.stage for p in sequential]; parallel_stage = [p.stage for p in parallel]
        evidence['checks']['local_slow_tls'] = {'address_scope': 'Loopback only; no WAN throughput claim',
            'sequential_seconds': round(sequential_seconds,3), 'parallel_seconds': round(parallel_seconds,3),
            'cancel_seconds': round(cancel_seconds,3), 'sequential_stages': serial_stage,
            'parallel_stages': parallel_stage, 'cancel_stages': [p.stage for p in cancelled],
            'same_order': [(p.host,p.family) for p in sequential]==[(p.host,p.family) for p in parallel],
            'accepted_connections': len(accepted), 'passed': serial_stage==parallel_stage==['tls_timeout']*6 and all(p.stage=='cancelled' for p in cancelled) and cancel_seconds<2 and parallel_seconds<sequential_seconds}
        # Saturate the real resolver admission limit; actual localhost resolution
        # runs after release, without replacing socket.getaddrinfo.
        slots = transport._DNS_SLOTS
        for _ in range(transport.DNS_RESOLVER_SLOTS): slots.acquire()
        try:
            busy = transport.probe_host_family('localhost', socket.AF_INET, dns_timeout=.05)
        finally:
            for _ in range(transport.DNS_RESOLVER_SLOTS): slots.release()
        resolved, error, _ = transport.timeout_dns('localhost', socket.AF_INET, timeout=2)
        evidence['checks']['native_dns_slots'] = {'busy_stage': busy.stage, 'busy_error_type': busy.error_type,
            'busy_dns_ms': busy.dns_ms, 'resolved_after_release': len(resolved), 'error_after_release': error,
            'passed': busy.error_type=='DNSBusy' and busy.dns_ms is None and bool(resolved) and not error}
    finally:
        stop.set()
        for connection in held: connection.close()
        for server in sockets: server.close()

    # Each Tk window is created withdrawn. No desktop inspection/control.
    import tkinter as tk
    from tkinter import messagebox
    from winnetdiff.gui import app
    gui_rows = []
    for language in ('en', 'zh-CN', 'zh-TW'):
        times = []; result = {}; beat_id = [None]
        def harness(root):
            root.withdraw(); widgets=root.winnetdiff_widgets; state=root.winnetdiff_state
            def beat():
                times.append(time.perf_counter()); beat_id[0] = root.after(20, beat)
            beat(); widgets['run'].invoke(); deadline=time.monotonic()+100
            try:
                while state['busy'] and time.monotonic()<deadline:
                    root.update(); time.sleep(.005)
                report=state.get('report')
                result.update(language=language, finished=not state['busy'], layers=len(report.layers) if report else 0,
                    max_heartbeat_ms=round(max((b-a for a,b in zip(times,times[1:])),default=0)*1000,2),
                    errors={k:len(getattr(report,k).get('errors',[])) for k in ('proxy','route','security')} if report else {})
            finally:
                if beat_id[0]: root.after_cancel(beat_id[0])
                root.winnetdiff_close()
        with patch.object(app,'load_settings',return_value={}), patch.object(app,'save_settings'), patch.object(tk.Tk,'mainloop',harness), patch.object(messagebox,'showerror') as errors:
            app.gui(no_network=True,locale=language,fake_ip_audit=True)
        result['callback_errors']=errors.call_count
        result['passed']=result.get('finished') and result.get('layers')==5 and not errors.call_count and not any(result['errors'].values())
        gui_rows.append(result)
    evidence['checks']['withdrawn_native_gui'] = {'cases':gui_rows, 'passed':all(r['passed'] for r in gui_rows), 'visual_manual_check':False}
    evidence['source_changed_during_run'] = source != hashlib.sha256((ROOT/'windows_net_diffdiag.py').read_bytes()).hexdigest()
    evidence['passed'] = all(check['passed'] for check in evidence['checks'].values()) and not evidence['source_changed_during_run']
    (out/'summary.json').write_text(json.dumps(evidence,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps(evidence,ensure_ascii=False,indent=2))
    return 0 if evidence['passed'] else 1


if __name__=='__main__': raise SystemExit(main())
