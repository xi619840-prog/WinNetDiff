"""Actual Tk smoke harness, mocked by default; --live runs read-only collectors.

No repairs, UAC or file dialogs are invoked. Live output belongs outside Git.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import threading
import time
import traceback
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def synthetic_report(hosts, do_network=True, progress=lambda _: None, cancel=None,
                     retries=2, locale='en', profile=None, fake_ip_audit=False, retry_mode='same-ip', wfp_context=None):
    from winnetdiff.core.models import Finding, Probe, Report, VERSION
    progress('Synthetic read-only integration fixture')
    time.sleep(.25)
    probes = [Probe(hosts[0], 'IPv4', ip='203.0.113.7', stage='http_ok', dns_ms=1, tcp_ms=2,
                    tls_ms=3, http_ms=4, http_status=200)] if do_network else []
    report = Report(VERSION, '2026-10-24T00:00:00+00:00', 'Synthetic Windows fixture', False,
        list(hosts), {'errors': [], 'wininet': {'ProxyEnable': 0}}, {'errors': [], 'adapters': [],
        'bindings': [], 'routes': []}, probes, {'errors': [], 'evidence': []},
        [Finding('資訊', '綜合', '未發現明確異常', 'Synthetic fixture only', 'No confirmed configuration fault.')], [])
    report.locale = locale
    report.scan_options = {'hosts': list(hosts), 'do_network': do_network, 'retries': retries, 'profile': profile, 'retry_mode':retry_mode}
    report.layers = {key: {'status': '已稽核', 'confidence': '中', 'evidence': []}
                     for key in ['代理', '路由', 'IPv4/IPv6', 'TCP/TLS', '安全/驅動']}
    return report


def run(locale='en', live=False, no_network=False, timeout=150):
    import tkinter as tk
    from tkinter import messagebox
    import winnetdiff.gui.app as app
    observed = {'locale': locale, 'live_collectors': live, 'no_network': no_network,
                'started_at': dt.datetime.now().astimezone().isoformat(), 'heartbeat_ticks': 0,
                'max_heartbeat_gap_ms': 0, 'callback_errors': [], 'dialogs': [], 'rendered': False}
    observed['gui_source_sha256'] = hashlib.sha256(Path(app.__file__).read_bytes()).hexdigest()
    original_mainloop = tk.Tk.mainloop
    actual_scan = app.scan
    started = time.perf_counter()
    captured = {}

    def record_scan(*args, **kwargs):
        captured['worker_thread'] = threading.get_ident()
        report = (actual_scan if live else synthetic_report)(*args, **kwargs)
        captured['report'] = report
        return report

    def dialog(kind):
        def handle(*args, **kwargs):
            observed['dialogs'].append({'kind': kind, 'message': str(args)[:1000]})
            return False
        return handle

    def harness_loop(root, *args, **kwargs):
        root.withdraw()
        main_thread = threading.get_ident()
        previous = time.perf_counter()
        observed['main_thread'] = main_thread
        root.report_callback_exception = lambda typ, value, tb: observed['callback_errors'].append(''.join(traceback.format_exception(typ, value, tb)))
        def tick():
            nonlocal previous
            now = time.perf_counter()
            if root.winnetdiff_state['busy']:
                observed['heartbeat_ticks'] += 1
                observed['max_heartbeat_gap_ms'] = max(observed['max_heartbeat_gap_ms'], (now - previous) * 1000)
            previous = now
            widgets, state = root.winnetdiff_widgets, root.winnetdiff_state
            if state['report'] is not None and not state['busy']:
                observed['rendered'] = True
                observed['layer_count'] = len(widgets['layers'].get_children())
                observed['finding_count'] = len(widgets['findings'].get_children())
                observed['run_label'] = str(widgets['run'].cget('text'))
                observed['run_reenabled'] = str(widgets['run'].cget('state')) == 'normal'
                observed['cancel_disabled'] = str(widgets['cancel'].cget('state')) == 'disabled'
                observed['worker_is_background'] = captured.get('worker_thread') != main_thread
                observed['targets'] = widgets['hosts_var'].get()
                if locale == 'en':
                    summary = widgets['overview'].get('1.0', 'end')
                    observed['english_overview_cjk_lines'] = [line[:300] for line in summary.splitlines()
                        if any('\u4e00' <= char <= '\u9fff' for char in line)][:12]
                root.after(60, root.winnetdiff_close)
                return
            if now - started > timeout:
                observed['timed_out'] = True
                state['cancel'].set()
                root.winnetdiff_close()
                return
            root.after(30, tick)
        root.after(20, tick)
        root.after(50, lambda: root.winnetdiff_widgets['run'].invoke())
        return original_mainloop(root, *args, **kwargs)
    try:
        with patch.object(app, 'scan', record_scan), patch.object(app, 'load_settings', return_value={}), \
             patch.object(app, 'save_settings'), patch.object(tk.Tk, 'mainloop', harness_loop), \
             patch.object(messagebox, 'showerror', dialog('error')), \
             patch.object(messagebox, 'showinfo', dialog('info')), \
             patch.object(messagebox, 'askyesno', dialog('confirmation')):
            app.gui(locale=locale, no_network=no_network)
    except Exception:
        observed['harness_error'] = traceback.format_exc()
    if 'report' in captured:
        report = captured['report']
        observed['probe_results'] = [{'host': p.host, 'family': p.family, 'stage': p.stage,
            'attempt_count': len(p.attempts), 'tcp_ms': p.tcp_ms, 'tls_ms': p.tls_ms, 'http_ms': p.http_ms}
            for p in report.probes]
        observed['query_errors'] = {key: getattr(report, key).get('errors', []) for key in ['proxy', 'route', 'security']}
    observed['elapsed_seconds'] = round(time.perf_counter() - started, 3)
    observed['max_heartbeat_gap_ms'] = round(observed['max_heartbeat_gap_ms'], 2)
    observed['passed'] = bool(observed['rendered'] and observed.get('layer_count') == 5
        and observed.get('worker_is_background') and observed.get('run_reenabled')
        and observed['heartbeat_ticks'] >= 3 and not observed['dialogs']
        and not observed['callback_errors'] and 'harness_error' not in observed)
    observed['scope'] = 'Actual Tk event loop and worker wiring; live collectors only when live_collectors=true. No repairs or UAC.'
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lang', choices=['en', 'zh-CN', 'zh-TW'], default='en')
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--no-network', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    observed = run(args.lang, args.live, args.no_network)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(observed, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(observed, ensure_ascii=False, indent=2))
    return 0 if observed['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
