"""Tk interface. Workers never touch Tk; language and target profiles are independent."""
from __future__ import annotations

import ctypes
import contextvars
import gc
from dataclasses import replace
import json
import os
from pathlib import Path
import queue
import threading

from ..core.models import APP_NAME, VERSION
from ..core.config import (TARGET_PROFILES, default_profile, load_settings,
                           parse_hosts, resolve_targets, save_settings, default_output_dir)
from ..core.i18n import get_language, set_language, tr
from ..core.windows import is_admin
from ..core.engine import scan, layer_overview, with_proxy_path_evidence, with_wfp_context
from ..core.snapshots import create_snapshot, save_snapshot, load_snapshot, compare_snapshots
from ..analysis.verification import compare_verification
from ..collectors.security import export_wfp, summarize_wfp_xml
from ..repairs.manager import RepairManager, relaunch_as_admin
from ..core.atomic import atomic_write_text
from ..reports.share_card import compact_share_card
from ..probes.pmtu import pmtu_candidates, probe_pmtu, pmtu_summary
from ..reports.export import evidence_text, markdown_report, redact, redacted_data, repair_text

LANGUAGE_CHOICES = {'English': 'en', '简体中文': 'zh-CN', '繁體中文': 'zh-TW'}
PROFILE_LABELS = {'global': '全球網站', 'mainland': '中國大陸網站', 'traditional': '繁體中文地區網站'}


def diagnosis_outcome(report) -> str:
    """A completed measurement can fail; missing collection is incomplete evidence."""
    if report.cancelled:
        return 'cancelled'
    for data in (report.proxy, report.route, report.security):
        if data.get('errors') or any(value is False for value in data.get('completeness', {}).values()):
            return 'partial'
    if report.dns_audit.get('errors'):
        return 'partial'
    return 'completed'


def confirm_full_export(parent, locale=None, *, wfp=False):
    """Full output needs a fresh acknowledgement and a deliberate export action.

    No Return/Enter binding accepts this dialog, even on the enabled export
    button. Escape, Cancel and the window manager close action all deny it.
    Ordinary export buttons never open this dialog and always redact.
    """
    import tkinter as tk
    from tkinter import ttk
    L = lambda source: tr(source, locale=locale or get_language())
    window = tk.Toplevel(parent, name='full_export_confirmation')
    window.title(L('匯出完整本機資料'))
    window.transient(parent)
    window.resizable(True, True)
    body = ttk.Frame(window, padding=18)
    body.pack(fill='both', expand=True)
    ttk.Label(body, text=L('完整報告可能包含 IP、MAC、電腦名稱、安裝路徑、驅動資訊、網路設定及憑證。僅供本機保管，不會自動上傳。'),
              wraplength=540, justify='left').pack(fill='x', pady=(0, 12))
    if wfp:
        ttk.Label(body, text=L('WFP XML 是完整私密規則與路徑，唯讀匯出可能需要管理員權限。'),
                  wraplength=540, justify='left').pack(fill='x', pady=(0, 12))
    formats = {'WFP XML': 'wfp'} if wfp else {'JSON': 'json', 'Markdown': 'markdown', L('快照'): 'snapshot', L('修復與回復紀錄'): 'history'}
    format_var = tk.StringVar(window, value=next(iter(formats)))
    ttk.Label(body, text=L('檔案類型')).pack(anchor='w')
    format_box = ttk.Combobox(body, textvariable=format_var, values=list(formats), state='readonly', name='format')
    format_box.pack(fill='x', pady=(4, 12))
    acknowledged = tk.BooleanVar(window, value=False)
    buttons = ttk.Frame(body)
    result = None

    def cancel(event=None):
        window.destroy()
        return 'break'

    def accept():
        nonlocal result
        if acknowledged.get() and format_var.get() in formats:
            result = formats[format_var.get()]
            window.destroy()

    export = ttk.Button(buttons, text=L('匯出完整資料'), command=accept, state='disabled', name='export')
    acknowledge = ttk.Checkbutton(body, text=L('我了解這是完整私密資料，分享前必須另行審閱。'),
        variable=acknowledged, name='acknowledge',
        command=lambda: export.configure(state='normal' if acknowledged.get() else 'disabled'))
    acknowledge.pack(anchor='w', pady=(0, 14))
    buttons.pack(fill='x')
    cancel_button = ttk.Button(buttons, text=L('取消'), command=cancel, name='cancel')
    cancel_button.pack(side='right')
    export.pack(side='right', padx=10)
    window.protocol('WM_DELETE_WINDOW', cancel)
    # Widget bindings precede class bindings, including TButton key invocation.
    pending = [window]
    while pending:
        widget = pending.pop()
        pending.extend(widget.winfo_children())
        for key in ('<Return>', '<KP_Enter>', '<Escape>'):
            widget.bind(key, cancel)
    window.winnetdiff_full_export = {'acknowledgement': acknowledge, 'acknowledged': acknowledged,
        'format': format_box, 'format_var': format_var, 'export': export, 'cancel': cancel_button}
    try:
        window.wait_visibility()
        window.grab_set()
        cancel_button.focus_set()
        parent.wait_window(window)
    except tk.TclError:
        # A close/cancel event can arrive before mapping finishes.
        if window.winfo_exists():
            raise
    return result


def choose_profile_hosts(current: str, previous_auto: list[str], locale: str,
                         profile: str | None = None) -> tuple[str, list[str], bool]:
    """Resolve hosts for a deliberate profile choice, preserving custom input."""
    try:
        current_hosts = parse_hosts(current)
    except ValueError:
        current_hosts = None
    new = resolve_targets(locale, profile=profile)
    if current_hosts == previous_auto:
        return ','.join(new), new, True
    return current, new, False


def enable_high_dpi() -> None:
    if os.name != 'nt':
        return
    try:
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except (AttributeError, OSError):
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass


def gui(initial_hosts=None, no_network=False, locale='en', profile=None, retries=2, fake_ip_audit=None,
        retry_mode=None, initial_wfp_context=None) -> None:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk

    # Earlier destroyed windows can retain callback cycles. Reap those Tcl/Tk
    # objects on their owning GUI thread before a new worker can trigger GC.
    gc.collect()
    enable_high_dpi()
    set_language(locale)
    settings = load_settings()
    selected_profile = profile or settings.get('profile') or default_profile(locale)
    if selected_profile not in TARGET_PROFILES:
        selected_profile = default_profile(locale)
    auto_hosts = resolve_targets(locale, profile=selected_profile)
    supplied = initial_hosts
    if supplied is None:
        supplied = settings.get('hosts') or auto_hosts
    hosts = ','.join(supplied) if isinstance(supplied, (list, tuple)) else str(supplied)
    root = tk.Tk()
    root.title(f'{APP_NAME} {VERSION}')
    # Geometry uses physical pixels in a DPI-aware process; point-sized fonts
    # already scale. Scale the client area too, bounded by the current display.
    dpi_scale = max(1.0, min(3.0, root.winfo_fpixels('1i') / 96.0))
    available_width = max(640, root.winfo_screenwidth() - 80)
    available_height = max(480, root.winfo_screenheight() - 100)
    root.geometry(f'{min(round(1180*dpi_scale),available_width)}x{min(round(860*dpi_scale),available_height)}')
    root.minsize(min(round(900*dpi_scale), available_width), min(round(650*dpi_scale), available_height))
    style = ttk.Style(root)
    if 'vista' in style.theme_names():
        style.theme_use('vista')
    style.configure('Title.TLabel', font=('Segoe UI', 17, 'bold'))
    style.configure('Card.TLabel', font=('Segoe UI', 10))
    style.configure('Treeview', rowheight=max(26, round(26*dpi_scale)))
    localizable = []
    heading_sources = []
    tabs = []

    def L(source, **kwargs):
        return tr(source, locale=get_language(), **kwargs)

    def label(parent, source, **kwargs):
        widget = ttk.Label(parent, text=L(source), **kwargs)
        localizable.append((widget, source))
        return widget

    def button(parent, source, **kwargs):
        widget = ttk.Button(parent, text=L(source), **kwargs)
        localizable.append((widget, source))
        return widget

    main = ttk.Frame(root, padding=12, name='main')
    main.pack(fill='both', expand=True)
    ttk.Label(main, text='WinNetDiff', style='Title.TLabel').pack(anchor='w')
    label(main, '代理 → 路由與綁定 → IPv4/IPv6 → TCP/TLS/HTTP → 安全元件', foreground='#475569').pack(anchor='w', pady=(3, 5))
    language_bar = ttk.Frame(main, name='preferences')
    language_bar.pack(fill='x', pady=(2, 7))
    label(language_bar, '語言').pack(side='left')
    language_var = tk.StringVar(value=next((name for name, code in LANGUAGE_CHOICES.items() if code == locale), 'English'))
    language_box = ttk.Combobox(language_bar, values=list(LANGUAGE_CHOICES), textvariable=language_var,
                               state='readonly', width=14, name='language')
    language_box.pack(side='left', padx=(6, 16))
    label(language_bar, '測試設定').pack(side='left')
    profile_var = tk.StringVar()
    profile_box = ttk.Combobox(language_bar, textvariable=profile_var, state='readonly', width=29, name='profile')
    profile_box.pack(side='left', padx=(6, 16))
    expert_var = tk.BooleanVar(value=settings.get('mode') == 'expert')
    expert_button = ttk.Checkbutton(language_bar, text=L('專家模式'), variable=expert_var, name='expert')
    expert_button.pack(side='right')
    localizable.append((expert_button, '專家模式'))

    form = ttk.Frame(main, name='form')
    form.pack(fill='x')
    label(form, '測試網域').pack(side='left')
    hosts_var = tk.StringVar(value=hosts)
    hosts_entry = ttk.Entry(form, textvariable=hosts_var, width=48, name='hosts')
    hosts_entry.pack(side='left', fill='x', expand=True, padx=8)
    passive_var = tk.BooleanVar(value=no_network)
    passive_button = ttk.Checkbutton(form, text=L('僅本機稽核'), variable=passive_var, name='passive')
    passive_button.pack(side='left', padx=4)
    localizable.append((passive_button, '僅本機稽核'))
    run_button = button(form, '開始診斷', name='run')
    run_button.pack(side='left', padx=4)
    cancel_button = button(form, '取消', name='cancel', state='disabled')
    cancel_button.pack(side='left', padx=4)

    extension_bar = ttk.Frame(main, name='extensions')
    extension_bar.pack(fill='x', pady=(6, 0))
    fake_ip_var = tk.BooleanVar(value=settings.get('fake_ip_audit', True) if fake_ip_audit is None else fake_ip_audit)
    fake_ip_button = ttk.Checkbutton(extension_bar, text=L('Fake-IP / DNS audit'), variable=fake_ip_var, name='fake_ip')
    localizable.append((fake_ip_button, 'Fake-IP / DNS audit'))
    fake_ip_button.pack(side='left')
    share_button = button(extension_bar, 'Copy compact diagnostic card', name='share', state='disabled')
    share_button.pack(side='right', padx=4)
    pmtu_button = button(extension_bar, 'Run optional PMTU probe', name='pmtu', state='disabled')
    pmtu_button.pack(side='right', padx=4)
    path_bar = ttk.Frame(main, name='paths')
    path_bar.pack(fill='x', pady=(6, 0))
    retry_same_ip_var = tk.BooleanVar(value=(retry_mode or settings.get('retry_mode','same-ip')) == 'same-ip')
    retry_button = ttk.Checkbutton(path_bar, text=L('Retry the same IP'), variable=retry_same_ip_var, name='same_ip')
    retry_button.pack(side='left'); localizable.append((retry_button,'Retry the same IP'))
    proxy_paths_button = button(path_bar, 'Compare proxy paths', name='proxy_paths', state='disabled')
    proxy_paths_button.pack(side='right', padx=4)
    wfp_input_button = button(path_bar, 'Import WFP context', name='wfp_input', state='disabled')
    wfp_input_button.pack(side='right', padx=4)

    notebook = ttk.Notebook(main, name='tabs')
    notebook.pack(fill='both', expand=True, pady=10)
    frames = {}
    for key, source in [('overview', '健康概覽'), ('findings', '異常與修復'), ('snapshots', '快照比較'),
                        ('layers', '五層診斷'), ('evidence', '原始證據'), ('history', '修復與回復紀錄')]:
        frame = ttk.Frame(notebook, padding=8, name=key)
        frames[key] = frame
        notebook.add(frame, text=L(source))
        tabs.append((frame, source))

    def text_widget(parent, name, height=10):
        box = scrolledtext.ScrolledText(parent, name=name, height=height, wrap='word', padx=9, pady=9,
                                       font=('Segoe UI', 10), relief='flat')
        box.pack(fill='both', expand=True)
        box.insert('1.0', L('完成診斷後顯示結果。'))
        box.configure(state='disabled')
        return box

    def set_text(widget, text):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        text = str(text)
        widget.insert('1.0', text[:160000])
        if len(text) > 160000:
            widget.insert('end', '\n\n' + L('介面預覽已截斷；匯出報告保留全部證據。'))
        widget.configure(state='disabled')

    def tree_widget(parent, columns, headings, height, name='list', show='headings'):
        frame = ttk.Frame(parent)
        frame.pack(fill='x', pady=(0, 7))
        tree = ttk.Treeview(frame, columns=columns, show=show, height=height, name=name)
        vertical = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
        horizontal = ttk.Scrollbar(frame, orient='horizontal', command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        tree.grid(row=0, column=0, sticky='nsew')
        vertical.grid(row=0, column=1, sticky='ns')
        horizontal.grid(row=1, column=0, sticky='ew')
        frame.columnconfigure(0, weight=1)
        for key, source, width in headings:
            tree.heading(key, text=L(source))
            tree.column(key, width=width, minwidth=60, stretch=(key == columns[-1]))
            heading_sources.append((tree, key, source))
        return tree

    cards = ttk.Frame(frames['overview'])
    cards.pack(fill='x', pady=(0, 6))
    card_vars = {}
    for index, source in enumerate(['網路', 'IPv4', 'IPv6', 'TCP / TLS', '代理', '可疑元件']):
        box = ttk.LabelFrame(cards, text=L(source), padding=7)
        box.grid(row=0, column=index, sticky='nsew', padx=3)
        localizable.append((box, source))
        cards.columnconfigure(index, weight=1)
        value = tk.StringVar(value=L('尚未檢測'))
        ttk.Label(box, textvariable=value, style='Card.TLabel', wraplength=145).pack(anchor='w')
        card_vars[source] = value
    label(frames['overview'], '本機優先，無遙測。診斷結果是調查線索，不保證定位所有故障。',
          foreground='#475569').pack(anchor='w', pady=(4, 7))
    overview_text = text_widget(frames['overview'], 'summary')
    repair_bar = ttk.Frame(frames['findings'], name='actions')
    repair_bar.pack(fill='x', pady=(0, 7))
    proxy_button = button(repair_bar, '關閉失效手動代理', name='proxy', state='disabled')
    restore_button = button(repair_bar, '恢復代理備份', name='restore')
    rerun_button = button(repair_bar, '重新驗證', name='rerun')
    dns_button = button(repair_bar, 'DNS 快取處理說明', name='dns')
    guidance_button = button(repair_bar, '人工操作預覽', name='guidance', state='disabled')
    for widget in [proxy_button, restore_button, rerun_button, dns_button, guidance_button]:
        widget.pack(side='left', padx=(0, 6))
    finding_tree = tree_widget(frames['findings'], ('risk', 'layer', 'grade', 'title'),
        [('risk', '風險等級', 150), ('layer', '診斷層', 125), ('grade', '可信度', 100), ('title', '發現', 650)], 7)
    for tag, color in [('info', '#334155'), ('suspect', '#805800'), ('high', '#a14400'), ('confirmed', '#aa2020')]:
        finding_tree.tag_configure(tag, foreground=color)
    finding_detail = text_widget(frames['findings'], 'detail', 8)
    layer_tree = tree_widget(frames['layers'], ('name', 'state'),
        [('name', '診斷層', 280), ('state', '狀態', 550)], 5)
    layer_detail = text_widget(frames['layers'], 'detail')
    evidence_box = text_widget(frames['evidence'], 'json')
    history_box = text_widget(frames['history'], 'log')
    snapshot_bar = ttk.Frame(frames['snapshots'], name='actions')
    snapshot_bar.pack(fill='x', pady=(0, 7))
    snapshot_save = button(snapshot_bar, '儲存目前快照', name='save', state='disabled')
    snapshot_base = button(snapshot_bar, '開啟基準快照', name='baseline')
    snapshot_compare = button(snapshot_bar, '開啟比較快照', name='comparison')
    snapshot_current = button(snapshot_bar, '比較目前狀態', name='current', state='disabled')
    snapshot_export = button(snapshot_bar, '匯出差異', name='export', state='disabled')
    for widget in [snapshot_save, snapshot_base, snapshot_compare, snapshot_current, snapshot_export]:
        widget.pack(side='left', padx=(0, 6))
    snapshot_status = tk.StringVar(value=L('尚未載入基準快照。'))
    ttk.Label(frames['snapshots'], textvariable=snapshot_status, wraplength=1050).pack(anchor='w', pady=4)
    label(frames['snapshots'], '快照以去識別化方式儲存；比較使用相同版本與隱私模式。', foreground='#475569').pack(anchor='w', pady=(0, 6))
    snapshot_tree = tree_widget(frames['snapshots'], ('kind', 'category', 'item'),
        [('kind', '變化', 150), ('category', '類別', 220), ('item', '項目', 600)], 7)
    snapshot_detail = text_widget(frames['snapshots'], 'detail', 8)

    footer = ttk.Frame(main, name='footer')
    footer.pack(fill='x')
    privilege_bar = ttk.Frame(footer)
    privilege_bar.pack(fill='x', pady=(0, 4))
    export_bar = ttk.Frame(footer)
    export_bar.pack(fill='x')
    administrator = is_admin()
    label(privilege_bar, '目前權限：管理員' if administrator else '目前權限：一般使用者').pack(side='left', padx=(0, 10))
    elevate_button = button(privilege_bar, '申請管理員權限', name='elevate')
    elevate_button.pack(side='left')
    wfp_button = button(export_bar, '匯出 WFP', name='wfp')
    export_history = button(export_bar, '匯出紀錄', name='history')
    export_md = button(export_bar, '匯出 Markdown', name='markdown', state='disabled')
    export_json = button(export_bar, '匯出 JSON', name='json', state='disabled')
    for widget in [export_json, export_md, export_history, wfp_button]:
        widget.pack(side='right', padx=3)
    privacy_bar = ttk.Frame(footer, name='privacy')
    privacy_bar.pack(fill='x', pady=(5, 0))
    label(privacy_bar, '一般匯出與快照預設去識別化；完整資料需另外確認。').pack(side='left')
    full_export_button = button(privacy_bar, '完整資料…', name='full', state='disabled')
    full_export_button.pack(side='right')
    status_var = tk.StringVar(value=L('準備就緒。遠端探針直接連線；本機稽核可離線執行。'))
    ttk.Label(main, textvariable=status_var, wraplength=1120, name='status', foreground='#334155').pack(anchor='w', pady=(7, 0))
    progress = ttk.Progressbar(main, mode='indeterminate', name='progress')
    progress.pack(fill='x', pady=(6, 0))
    # Reserve fixed bottom controls before allocating the expandable notebook.
    # Hidden expert tabs can otherwise leave a large requested notebook height.
    progress.pack_configure(side='bottom', before=notebook)
    main.nametowidget('status').pack_configure(side='bottom', before=notebook, fill='x')
    footer.pack_configure(side='bottom', before=notebook)
    mailbox = queue.Queue()
    state = {'report': None, 'busy': False, 'kind': '', 'cancel': threading.Event(), 'findings': {}, 'wfp_context': initial_wfp_context,
             'layers': {}, 'baseline': None, 'comparison': None, 'diff': None, 'auto_hosts': auto_hosts,
             'profile': selected_profile, 'last_parameters': None, 'verification_only': False,
             'diagnosis_status': None, 'worker': None}
    output_dir = default_output_dir()
    manager = RepairManager(output_dir / 'repairs')
    controls = [run_button, hosts_entry, passive_button, language_box, profile_box, expert_button,
        proxy_button, restore_button, rerun_button, dns_button, guidance_button, elevate_button,
        export_json, export_md, export_history, wfp_button, snapshot_save, snapshot_base,
        snapshot_compare, snapshot_current, snapshot_export, fake_ip_button, share_button, pmtu_button,
        retry_button, proxy_paths_button, wfp_input_button, full_export_button]

    def profile_choices():
        return {L(PROFILE_LABELS.get(key, key)): key for key in TARGET_PROFILES}

    def persist():
        try:
            try:
                custom = parse_hosts(hosts_var.get())
            except ValueError:
                custom = None
            if custom == state['auto_hosts']:
                custom = None
            save_settings({'language': get_language(), 'profile': state['profile'],
                           'hosts': custom, 'mode': 'expert' if expert_var.get() else 'basic',
                           'retries': retries, 'no_network': bool(passive_var.get()), 'fake_ip_audit': bool(fake_ip_var.get()),
                           'retry_mode': 'same-ip' if retry_same_ip_var.get() else 'rotate'})
            return True
        except (OSError, ValueError) as exc:
            status_var.set(L('設定無法儲存，仍可繼續使用：{error}', error=redact(L(exc))))
            return False

    def refresh_mode():
        for key in ['layers', 'evidence', 'history']:
            if expert_var.get():
                notebook.add(frames[key], text=L(dict((str(f), source) for f, source in tabs)[str(frames[key])]))
            else:
                notebook.hide(frames[key])
        guidance_button.configure(state='normal' if expert_var.get() and state['report'] is not None and not state['busy'] else 'disabled')
        wfp_button.configure(state='normal' if expert_var.get() and not state['busy'] else 'disabled')

    def change_language(event=None):
        new_locale = LANGUAGE_CHOICES[language_var.get()]
        # The language selector only changes presentation. Hosts, selected
        # profile, retry count and scan provenance belong to the user's scan.
        set_language(new_locale)
        for widget, source in localizable:
            widget.configure(text=L(source))
        for tree, key, source in heading_sources:
            tree.heading(key, text=L(source))
        for frame, source in tabs:
            notebook.tab(frame, text=L(source))
        profile_box.configure(values=list(profile_choices()))
        profile_var.set(L(PROFILE_LABELS.get(state['profile'], state['profile'])))
        if state['report'] is not None:
            display_report(state['report'], outcome=state['diagnosis_status'])
        else:
            for value in card_vars.values():
                value.set(L('尚未檢測'))
            for widget in [overview_text, finding_detail, layer_detail, evidence_box, history_box, snapshot_detail]:
                set_text(widget, L('完成診斷後顯示結果。'))
        if state['diff'] is not None:
            display_diff(state['diff'])
        refresh_mode()
        persist()
        if state['report'] is not None or state['diagnosis_status'] == 'failed':
            display_diagnosis_status(state['report'], state['diagnosis_status'])
        else:
            status_var.set(L('設定已儲存。自訂網域不因切換語言而改寫。'))

    def change_profile(event=None):
        chosen = profile_choices().get(profile_var.get(), default_profile(get_language()))
        state['profile'] = chosen
        # A deliberate profile selection replaces hosts; a language switch does not overwrite custom hosts.
        state['auto_hosts'] = resolve_targets(get_language(), profile=chosen)
        hosts_var.set(','.join(state['auto_hosts']))
        persist()

    profile_box.configure(values=list(profile_choices()))
    profile_var.set(L(PROFILE_LABELS.get(selected_profile, selected_profile)))
    language_box.bind('<<ComboboxSelected>>', change_language)
    profile_box.bind('<<ComboboxSelected>>', change_profile)
    expert_button.configure(command=lambda: (refresh_mode(), persist()))

    def update_controls():
        for widget in controls:
            widget.configure(state='disabled' if state['busy'] else 'normal')
        cancel_button.configure(state='normal' if state['busy'] and (state['kind'] in ('scan', 'wfp', 'pmtu', 'proxy_paths', 'wfp_input') or state['verification_only']) else 'disabled')
        if not state['busy']:
            language_box.configure(state='readonly')
            profile_box.configure(state='readonly')
            if state['report'] is None:
                for widget in [proxy_button, guidance_button, export_json, export_md, snapshot_save, snapshot_current, share_button, pmtu_button, proxy_paths_button, wfp_input_button, full_export_button]:
                    widget.configure(state='disabled')
            elif not manager.preview_disable_proxy(state['report']).get('eligible'):
                proxy_button.configure(state='disabled')
            if not state['diff']:
                snapshot_export.configure(state='disabled')
            if state['report'] is not None and not pmtu_candidates(state['report'].probes):
                pmtu_button.configure(state='disabled')
            if administrator:
                elevate_button.configure(state='disabled')
            refresh_mode()

    def dispatch(kind, function):
        if state['busy']:
            return
        state.update(busy=True, kind=kind, cancel=threading.Event(), verification_only=False)
        update_controls()
        progress.start(15)
        def worker():
            try:
                mailbox.put((kind, function()))
            except Exception as exc:
                mailbox.put(('error', exc))
        # ContextVars do not automatically propagate to worker threads.
        context = contextvars.copy_context()
        state['worker'] = threading.Thread(target=lambda: context.run(worker), daemon=True, name='WinNetDiffWorker')
        state['worker'].start()

    def history_text():
        return json.dumps(redacted_data(manager.history()), ensure_ascii=False, indent=2, default=str)

    def scan_parameters():
        return {'hosts': parse_hosts(hosts_var.get()), 'do_network': not passive_var.get(),
                'retries': retries, 'locale': get_language(), 'profile': state['profile'], 'fake_ip_audit': bool(fake_ip_var.get()),
                'retry_mode': 'same-ip' if retry_same_ip_var.get() else 'rotate',
                **({'wfp_context': state['wfp_context']} if state['wfp_context'] is not None else {})}

    def run_scan(parameters):
        report = scan(**parameters, progress=lambda line: mailbox.put(('progress', line)), cancel=state['cancel'])
        # Cancellation may arrive after scan assembled its report but before
        # the bounded worker returns. Retain its partial evidence truthfully.
        if state['cancel'].is_set() and not report.cancelled:
            report = replace(report, cancelled=True)
            report.layers = layer_overview(report)
        report.repair_history = manager.history()
        return report

    def start_scan():
        if state['busy']:
            return
        try:
            parameters = scan_parameters()
        except ValueError as exc:
            messagebox.showerror(L('網域格式錯誤'), redact(L(exc)), parent=root)
            return
        state['last_parameters'] = parameters
        persist()
        status_var.set(L('正在診斷，可取消。未完成查詢會保留為未知。'))
        dispatch('scan', lambda: run_scan(parameters))
    run_button.configure(command=start_scan)
    rerun_button.configure(command=start_scan)

    def cancel_scan():
        if not state['busy']:
            return
        state['cancel'].set()
        cancel_button.configure(state='disabled')
        status_var.set(L('已要求取消，等待目前的有界查詢結束。'))
    cancel_button.configure(command=cancel_scan)

    def field(value, name, default=''):
        return value.get(name, default) if isinstance(value, dict) else getattr(value, name, default)

    def describe_finding(event=None):
        selected = finding_tree.selection()
        if not selected:
            return
        finding = state['findings'][selected[0]]
        lines = [L(field(finding, 'title')), '', L('可信度') + ': ' + L(field(finding, 'confidence')),
                 '', L('解釋'), L(field(finding, 'interpretation')), '', L('證據'),
                 redact(str(field(finding, 'evidence')))]
        if expert_var.get() and field(finding, 'commands', []):
            lines.extend(['', L('命令預覽，需人工確認'), *field(finding, 'commands', [])])
        if field(finding, 'rollback'):
            lines.extend(['', L('恢復與風險'), L(field(finding, 'rollback'))])
        set_text(finding_detail, '\n'.join(lines))
    finding_tree.bind('<<TreeviewSelect>>', describe_finding)

    def describe_layer(event=None):
        selected = layer_tree.selection()
        if selected:
            set_text(layer_detail, json.dumps(redacted_data(state['layers'][selected[0]]), ensure_ascii=False, indent=2, default=str))
    layer_tree.bind('<<TreeviewSelect>>', describe_layer)

    def display_diagnosis_status(report, outcome):
        if outcome == 'cancelled':
            status_var.set(L('診斷已取消，以下結果可能不完整。'))
        elif outcome == 'partial':
            status_var.set(L('診斷未完成，以下結果可能不完整。{probes} 個探針結果、{findings} 項發現。', probes=len(report.probes), findings=len(report.findings)))
        elif outcome == 'failed':
            status_var.set(L('診斷失敗，顯示上次保留的結果。' if report is not None else '診斷失敗，沒有本次完整結果。'))
        else:
            status_var.set(L('診斷完成，{probes} 個探針結果、{findings} 項發現。', probes=len(report.probes), findings=len(report.findings)))

    def display_report(report, *, outcome=None):
        state['report'] = report
        state['diagnosis_status'] = outcome or diagnosis_outcome(report)
        probes, findings = report.probes, report.findings
        stages = [p.stage for p in probes] + [a.get('stage') for p in probes for a in p.attempts]
        card_vars['網路'].set(L('部分目標可用' if 'http_ok' in stages else '請檢視證據' if probes else '未測試外網'))
        for family in ['IPv4', 'IPv6']:
            outcomes = [p.stage for p in probes if p.family == family]
            card_vars[family].set(L('HTTP 可達' if 'http_ok' in outcomes else '請檢視分層結果' if outcomes else '未測試'))
        card_vars['TCP / TLS'].set(L('TCP 通／TLS 逾時' if 'tls_timeout' in stages else 'TLS 憑證異常' if 'tls_cert_error' in stages else '已有測量' if probes else '未測試'))
        important = [f for f in findings if str(f.severity) not in ('資訊', '信息', 'Information', 'info')]
        proxy_issues = [f for f in important if str(f.layer) in ('代理', 'Proxy', 'proxy')]
        suspicious = [f for f in important if str(f.layer) in ('安全/驅動', '安全/驱动', 'Security/drivers', 'security')]
        card_vars['代理'].set(L('需檢視' if proxy_issues else '未發現明確異常'))
        card_vars['可疑元件'].set(L('{count} 項發現', count=len(suspicious)))
        lines = [L('最可能需要調查的項目'), '']
        scenarios = sorted(getattr(report, 'scenarios', []), key=lambda s: (
            0 if s.get('priority') == 'high' else 1, {'E3': 0, 'E2': 1, 'E1': 2}.get(s.get('grade'), 3)))
        if scenarios:
            for scenario in scenarios[:2]:
                lines.extend([L(scenario.get('title', scenario.get('code', ''))),
                              str(scenario.get('grade', 'E1')) + ': ' + L(scenario.get('grade_definition', '')),
                              L(scenario.get('reasoning', ''))])
                evidence = scenario.get('evidence')
                if isinstance(evidence, dict) and 'attempts' in evidence:
                    evidence = evidence['attempts']
                rows = evidence if isinstance(evidence, list) else [evidence]
                brief = []
                for row in rows[:2]:
                    if isinstance(row, dict):
                        brief.append({key: row[key] for key in ['host', 'family', 'stage', 'tcp_ms', 'tls_ms',
                            'http_ms', 'Name', 'InterfaceAlias', 'ComponentID', 'Status'] if key in row})
                if any(brief):
                    lines.extend([L('證據'), json.dumps(redacted_data(brief), ensure_ascii=False, indent=2)])
                alternatives = scenario.get('alternatives', [])[:2]
                if alternatives:
                    lines.extend([L('其他可能原因'), *[L(v) for v in alternatives]])
                checks = scenario.get('verification', [])[:2]
                if checks:
                    lines.extend([L('下一步'), *[L(v) for v in checks]])
                lines.append('')
        else:
            for finding in (important or findings)[:3]:
                lines.extend([L(finding.title), L(finding.interpretation), ''])
        if not important:
            lines.append(L('目前沒有足夠證據確認故障。請查看未完成查詢，必要時更換目標重試。'))
        lines.extend(['', L('下一步'), L('先核對證據與其他可能原因；只對符合條件的低風險操作進行確認。')])
        if report.verification:
            verification_status = report.verification.get('status')
            key = {'improved': '已驗證改善', 'regressed': '結果退步', 'incomparable': '無法比較'}.get(verification_status, '未驗證有效')
            lines.extend(['', L('修復前 → 修復後'), L(key),
                          json.dumps(redacted_data(report.verification), ensure_ascii=False, indent=2, default=str)])
        if state['diagnosis_status'] in ('cancelled', 'partial'):
            lines[:0] = [L('診斷已取消，以下結果可能不完整。' if state['diagnosis_status'] == 'cancelled' else '診斷未完成，以下結果可能不完整。'), '']
        elif state['diagnosis_status'] == 'failed':
            lines[:0] = [L('診斷失敗，顯示上次保留的結果。'), '']
        set_text(overview_text, '\n'.join(lines))
        set_text(evidence_box, evidence_text(replace(report, locale=get_language())))
        set_text(history_box, json.dumps(redacted_data(report.repair_history), ensure_ascii=False, indent=2, default=str))
        finding_tree.delete(*finding_tree.get_children())
        state['findings'].clear()
        for index, finding in enumerate(findings):
            severity = str(finding.severity)
            tag = ('confirmed' if '確認' in severity or '确认' in severity or 'Confirmed' in severity else
                   'high' if '高' in severity or 'High' in severity else
                   'info' if severity in ('資訊', '信息', 'Information', 'info') else 'suspect')
            identifier = str(index)
            state['findings'][identifier] = finding
            finding_tree.insert('', 'end', iid=identifier, values=(L(severity), L(finding.layer),
                L(finding.confidence), L(finding.title)), tags=(tag,))
        if findings:
            finding_tree.selection_set('0')
            describe_finding()
        layer_tree.delete(*layer_tree.get_children())
        state['layers'].clear()
        for index, (name, layer) in enumerate(report.layers.items()):
            identifier = str(index)
            state['layers'][identifier] = layer
            layer_tree.insert('', 'end', iid=identifier, values=(L(str(name)), L(str(layer.get('status', '')))))
        if state['layers']:
            layer_tree.selection_set('0')
            describe_layer()
        display_diagnosis_status(report, state['diagnosis_status'])
        update_controls()

    def request_proxy():
        if state['report'] is not None:
            dispatch('proxy_preview', lambda: manager.preview_disable_proxy(state['report']))
    proxy_button.configure(command=request_proxy)
    def request_restore():
        if state['last_parameters'] is None:
            try:
                state['last_parameters'] = scan_parameters()
            except ValueError as exc:
                messagebox.showerror(L('網域格式錯誤'), redact(L(exc)), parent=root)
                return
        dispatch('restore_preview', manager.last_backup)
    restore_button.configure(command=request_restore)

    def repair_and_verify(function):
        # All Tk values were captured on the main thread before dispatch.
        parameters = dict(state['last_parameters'])
        before = state['report'] or run_scan(parameters)
        result = function()
        if result.get('ok') and result.get('changed'):
            mailbox.put(('repair_verification', None))
            mailbox.put(('progress', L('正在以原有目標與參數驗證修復效果。')))
            after = run_scan(parameters)
            after.verification = compare_verification(before, after)
            after.repair_history = manager.history()
            return result, after
        before.repair_history = manager.history()
        before.verification = {'status': 'not_verified', 'reason': 'No confirmed configuration change; network effectiveness was not inferred.'}
        return result, before

    def request_dns():
        messagebox.showinfo(L('DNS 快取處理說明'), L('DNS 快取是暫態資料，無法忠實還原，因此不提供自動清除按鈕。\n\n若專家確認有需要，可在終端執行 ipconfig /flushdns，保存退出碼，然後重新診斷。'), parent=root)
    dns_button.configure(command=request_dns)

    def request_guidance():
        if state['report'] is None:
            return
        if messagebox.askyesno(L('人工操作預覽'), L('單項綁定變更可能立即斷線。先核對元件歸屬、保存原始狀態並準備恢復命令。\n\n繼續檢視人工命令？'), parent=root):
            window = tk.Toplevel(root)
            window.title(L('人工操作預覽'))
            window.geometry('900x620')
            text = text_widget(window, 'preview')
            set_text(text, repair_text(replace(state['report'], locale=get_language())))
    guidance_button.configure(command=request_guidance)

    def request_elevation():
        if messagebox.askyesno(L('重新啟動並申請權限'), L('Windows UAC 將要求確認。取消會保留目前視窗；同意後開啟新視窗。請先匯出需要的結果。\n\n是否繼續？'), parent=root):
            try:
                parameters = scan_parameters()
            except ValueError as exc:
                messagebox.showerror(L('網域格式錯誤'), redact(L(exc)), parent=root)
                return
            persist()
            argv = ['--lang', parameters['locale'], '--profile', parameters['profile'],
                    '--hosts', ','.join(parameters['hosts']), '--retries', str(parameters['retries']),
                    '--output-dir', str(output_dir)]
            argv.append('--fake-ip-audit' if parameters['fake_ip_audit'] else '--no-fake-ip-audit')
            argv += ['--retry-mode', parameters['retry_mode']]
            if not parameters['do_network']:
                argv.append('--no-network')
            hwnd = root.winfo_id()
            dispatch('elevation', lambda: relaunch_as_admin(argv=argv, hwnd=hwnd))
    elevate_button.configure(command=request_elevation)

    def show_share_card():
        if state['report'] is None:
            return
        card = compact_share_card(state['report'], get_language())
        window = tk.Toplevel(root)
        window.title(L('Diagnostic card preview'))
        window.geometry('820x520')
        ttk.Label(window, text=L('Review this minimized text before copying. Third-party raw errors, names and addresses are excluded; anonymity is not guaranteed.'), wraplength=780).pack(fill='x', padx=12, pady=8)
        preview = text_widget(window, 'card')
        set_text(preview, card)
        ttk.Label(window, text=L('Characters: {count}/500', count=len(card))).pack(anchor='w', padx=12)
        def copy_preview():
            root.clipboard_clear()
            root.clipboard_append(card)
            status_var.set(L('Diagnostic card copied. Nothing was uploaded.'))
        copy_button = ttk.Button(window, text=L('Copy this preview'), command=copy_preview)
        copy_button.pack(pady=10)
        root.winnetdiff_share_preview = {'window': window, 'text': preview, 'copy': copy_button, 'card': card}
    share_button.configure(command=show_share_card)

    def request_pmtu():
        report = state['report']
        if report is None:
            return
        addresses = pmtu_candidates(report.probes)
        if not addresses:
            messagebox.showinfo(L('PMTU auxiliary evidence'), L('No eligible repeated same-IP IPv4 TLS timeout. Run a network scan first; Fake-IP targets are skipped.'), parent=root)
            return
        if not messagebox.askyesno(L('PMTU consent'), L('This sends a bounded set of IPv4 DF ICMP packets to the same measured IP. ICMP filtering can make the result inconclusive. No MTU or network setting will be changed. Continue?') + '\n\n' + ', '.join(addresses), parent=root):
            return
        def measure():
            outcomes = []
            for address in addresses:
                if state['cancel'].is_set():
                    break
                outcomes.append(probe_pmtu(address, confirmed=True, cancel=state['cancel']))
            return replace(report, pmtu=list(report.pmtu) + outcomes)
        dispatch('pmtu', measure)
    pmtu_button.configure(command=request_pmtu)

    def request_proxy_paths():
        report = state['report']
        if report is None: return
        if passive_var.get() or not report.scan_options.get('do_network'):
            messagebox.showinfo(L('Proxy path comparison'), L('Run an online scan before comparing proxy paths.'), parent=root)
            return
        eligible = [row for row in report.proxy_paths.get('paths',[]) if row.get('eligible')]
        if not eligible:
            messagebox.showinfo(L('Proxy path comparison'), L('No eligible static HTTP proxy. Review PAC, bypass, authentication and unsupported paths in the report.'), parent=root)
            return
        endpoints = '\n'.join(str(row.get('source')) + ' ' + str(row.get('host')) + ':' + str(row.get('port')) for row in eligible[:2])
        if not messagebox.askyesno(L('Proxy path comparison'), L('Send credential-free CONNECT, verified TLS and HEAD through up to two listed proxies to the first test domain? No settings will change. PAC and automatic authentication are not used.') + '\n\n' + report.hosts[0] + '\n' + endpoints, parent=root):
            return
        dispatch('proxy_paths', lambda: with_proxy_path_evidence(report, confirmed=True, cancel=state['cancel']))
    proxy_paths_button.configure(command=request_proxy_paths)

    def request_wfp_input():
        if state['report'] is None: return
        path = filedialog.askopenfilename(parent=root, filetypes=[('WFP XML','*.xml')])
        if not path: return
        report = state['report']
        def load():
            context = summarize_wfp_xml(path, state['cancel'])
            if context.get('cancelled'): raise RuntimeError('WFP context import cancelled')
            return context, with_wfp_context(report, context)
        dispatch('wfp_input', load)
    wfp_input_button.configure(command=request_wfp_input)

    def save_path(filename, extension='.json'):
        try:
            directory = output_dir if output_dir.is_dir() else None
            if directory is None:
                status_var.set(L('輸出資料夾不存在或無法使用，請選擇已存在的儲存資料夾。'))
                home = Path.home()
                chosen = filedialog.askdirectory(parent=root, title=L('請選擇已存在的儲存資料夾'),
                    initialdir=str(home) if home.is_dir() else '', mustexist=True)
                if not chosen:
                    status_var.set(L('已取消儲存，未寫入檔案。'))
                    return None
                directory = Path(chosen)
            if not directory.is_dir():
                raise FileNotFoundError(L('儲存資料夾不存在。'))
            path = filedialog.asksaveasfilename(parent=root, title=L('保存本機檔案'), initialdir=str(directory.resolve()),
            initialfile=filename, defaultextension=extension, filetypes=[(extension.upper().lstrip('.'), '*' + extension)])
            if not path:
                status_var.set(L('已取消儲存，未寫入檔案。'))
                return None
            if not Path(path).parent.is_dir():
                raise FileNotFoundError(L('儲存資料夾不存在。'))
            return path
        except OSError as exc:
            detail = redact(L(exc))
            status_var.set(L('儲存失敗，未確認寫入完成：{error}', error=detail))
            messagebox.showerror(L('儲存失敗'), detail, parent=root)
            return None

    def confirm_overwrite(path):
        if not Path(path).exists():
            return False
        if messagebox.askyesno(L('確認覆蓋檔案'), L('檔案已存在：{path}\n\n是否覆蓋？', path=path), parent=root, default=messagebox.NO):
            return True
        status_var.set(L('已取消儲存，未寫入檔案。'))
        return None

    def export_report(kind, *, full=False):
        if state['busy']:
            return
        if kind != 'history' and state['report'] is None:
            return
        path = save_path('winnetdiff_' + kind + ('.md' if kind == 'markdown' else '.json'), '.md' if kind == 'markdown' else '.json')
        if not path:
            return
        overwrite = confirm_overwrite(path)
        if overwrite is None:
            return
        report = replace(state['report'], locale=get_language()) if state['report'] is not None else None
        def write():
            if kind == 'history':
                data = manager.history()
                text = json.dumps(data if full else redacted_data(data), ensure_ascii=False, indent=2, default=str)
            elif kind == 'markdown':
                text = markdown_report(report, full=full)
            else:
                text = evidence_text(report, full=full)
            if not Path(path).parent.is_dir():
                raise FileNotFoundError(L('儲存資料夾不存在。'))
            atomic_write_text(path, text, overwrite=overwrite)
            return path
        dispatch('export', write)
    export_json.configure(command=lambda: export_report('json'))
    export_md.configure(command=lambda: export_report('markdown'))
    export_history.configure(command=lambda: export_report('history'))

    def request_full_export():
        if state['busy'] or state['report'] is None:
            return
        kind = confirm_full_export(root, get_language())
        if kind == 'snapshot':
            request_snapshot_save(full=True)
        elif kind in ('json', 'markdown', 'history'):
            export_report(kind, full=True)
        else:
            status_var.set(L('已取消完整資料匯出，未寫入檔案。'))
    full_export_button.configure(command=request_full_export)

    def request_wfp():
        if state['busy']:
            return
        if confirm_full_export(root, get_language(), wfp=True) != 'wfp':
            status_var.set(L('已取消完整資料匯出，未寫入檔案。'))
            return
        path = save_path('wfp_state.xml', '.xml')
        if path:
            overwrite = confirm_overwrite(path)
            if overwrite is None:
                return
            status_var.set(L('正在背景匯出並串流處理 WFP。'))
            dispatch('wfp', lambda: export_wfp(Path(path), cancel=state['cancel'], overwrite=overwrite))
    wfp_button.configure(command=request_wfp)

    def request_snapshot_save(*, full=False):
        if state['busy'] or state['report'] is None:
            return
        path = save_path('winnetdiff_snapshot.json')
        if path:
            overwrite = confirm_overwrite(path)
            if overwrite is None:
                return
            report = replace(state['report'], locale=get_language())
            def write():
                if not Path(path).parent.is_dir():
                    raise FileNotFoundError(L('儲存資料夾不存在。'))
                save_snapshot(Path(path), report, label='GUI snapshot', full=full, overwrite=overwrite)
                return path
            dispatch('export', write)
    snapshot_save.configure(command=request_snapshot_save)

    def open_snapshot(is_baseline):
        path = filedialog.askopenfilename(parent=root, title=L('開啟基準快照' if is_baseline else '開啟比較快照'),
                    initialdir=str(output_dir), filetypes=[('JSON', '*.json')])
        if path:
            def load():
                snapshot = load_snapshot(Path(path))
                return is_baseline, snapshot, path
            dispatch('snapshot_load', load)
    snapshot_base.configure(command=lambda: open_snapshot(True))
    snapshot_compare.configure(command=lambda: open_snapshot(False))

    def compare_current():
        if state['baseline'] is None:
            messagebox.showinfo(L('快照'), L('請先載入基準快照。'), parent=root)
            return
        if state['report'] is None:
            messagebox.showinfo(L('快照'), L('請先完成一輪診斷。'), parent=root)
            return
        # Match the baseline privacy mode in memory; difference exports remain redacted.
        full = state['baseline'].get('privacy') == 'full'
        dispatch('snapshot_diff', lambda: compare_snapshots(state['baseline'], create_snapshot(state['report'], full=full)))
    snapshot_current.configure(command=compare_current)

    def export_diff():
        if state['diff'] is None:
            return
        path = save_path('winnetdiff_difference.json')
        if path:
            overwrite = confirm_overwrite(path)
            if overwrite is None:
                return
            def write():
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                atomic_write_text(path, json.dumps(redacted_data(state['diff']), ensure_ascii=False, indent=2), overwrite=overwrite)
                return path
            dispatch('export', write)
    snapshot_export.configure(command=export_diff)

    def display_diff(difference):
        state['diff'] = difference
        changes = difference.get('changes', [])
        snapshot_tree.delete(*snapshot_tree.get_children())
        for index, change in enumerate(changes):
            kind = {'added': '新增', 'removed': '刪除', 'enabled': '啟用', 'disabled': '停用', 'changed': '設定變化'}.get(change.get('kind'), change.get('kind', ''))
            snapshot_tree.insert('', 'end', iid=str(index), values=(L(kind), change.get('category', ''), change.get('id', '')))
        snapshot_status.set(L('快照差異：{count} 項', count=len(changes)))
        set_text(snapshot_detail, json.dumps(redacted_data(difference), ensure_ascii=False, indent=2, default=str))
        notebook.select(frames['snapshots'])
    def describe_change(event=None):
        selected = snapshot_tree.selection()
        if selected and state['diff']:
            change = state['diff'].get('changes', [])[int(selected[0])]
            set_text(snapshot_detail, json.dumps(redacted_data(change), ensure_ascii=False, indent=2, default=str))
    snapshot_tree.bind('<<TreeviewSelect>>', describe_change)

    def finish():
        state.update(busy=False, kind='', verification_only=False)
        progress.stop()
        update_controls()

    def drain():
        try:
            for _ in range(40):
                kind, payload = mailbox.get_nowait()
                if kind == 'progress':
                    status_var.set(L(payload))
                    continue
                if kind == 'repair_verification':
                    state['verification_only'] = True
                    update_controls()
                    continue
                # Do not enable a second operation while the previous worker
                # is still returning, even if its terminal item was queued.
                if state['worker'] is not None and state['worker'].is_alive():
                    mailbox.put((kind, payload))
                    break
                operation = state['kind']
                finish()
                if kind == 'scan':
                    display_report(payload)
                elif kind == 'error':
                    detail = redact(type(payload).__name__ + ': ' + L(payload))
                    if operation == 'scan':
                        state['diagnosis_status'] = 'failed'
                        if state['report'] is not None:
                            display_report(state['report'], outcome='failed')
                        status_var.set(L('診斷失敗，保留上次結果。{error}' if state['report'] is not None else '診斷失敗，沒有本次完整結果。{error}', error=detail))
                    elif operation == 'export':
                        status_var.set(L('儲存失敗，未確認寫入完成：{error}', error=detail))
                    else:
                        status_var.set(L('操作未完成，保留既有結果。{error}', error=detail))
                    messagebox.showerror(L('操作未完成'), detail, parent=root)
                elif kind == 'proxy_preview':
                    if not payload.get('eligible'):
                        messagebox.showinfo(L('目前不符合代理修復條件'), L(str(payload.get('reason', L('未確認失效的手動代理。')))), parent=root)
                    else:
                        preview = json.dumps(redacted_data(payload), ensure_ascii=False, indent=2, default=str)
                        if messagebox.askyesno(L('代理修復預覽'), preview + '\n\n' + L('將先備份原始值、修改並驗證設定，再以相同目標與參數自動重測。\n\n是否執行？'), parent=root):
                            before = state['report']
                            dispatch('repair', lambda: repair_and_verify(lambda: manager.disable_proxy(before, confirmed=True)))
                elif kind == 'restore_preview':
                    if payload is None:
                        messagebox.showinfo(L('尚無備份'), L('沒有本工具建立的可恢復代理備份。'), parent=root)
                    elif messagebox.askyesno(L('恢復代理設定'), L('備份檔案：{path}\n\n將核對目前設定，拒絕覆蓋其他程式的新設定。恢復可能再次啟用失效代理。\n\n是否繼續？', path=str(payload)), parent=root):
                        backup = payload
                        dispatch('repair', lambda: repair_and_verify(lambda: manager.restore_proxy(backup, confirmed=True)))
                elif kind == 'repair':
                    result, report = payload
                    display_report(report)
                    notebook.select(frames['overview'])
                    messagebox.showinfo(L('操作結果'), L('設定變更結果與網路改善分開判讀；詳見前後驗證。') + '\n\n' + json.dumps(redacted_data(result), ensure_ascii=False, indent=2)[:7000], parent=root)
                elif kind == 'export':
                    status_var.set(L('已保存本機檔案：{path}', path=str(payload)))
                elif kind == 'snapshot_load':
                    baseline, snapshot, path = payload
                    state['baseline' if baseline else 'comparison'] = snapshot
                    snapshot_status.set(L('快照已載入：{label}', label=str(snapshot.get('label') or Path(path).name)))
                    if state['baseline'] is not None and state['comparison'] is not None:
                        dispatch('snapshot_diff', lambda: compare_snapshots(state['baseline'], state['comparison']))
                elif kind == 'snapshot_diff':
                    display_diff(payload)
                elif kind == 'proxy_paths':
                    display_report(payload)
                    notebook.select(frames['evidence'])
                elif kind == 'wfp_input':
                    context, report = payload
                    state['wfp_context'] = context
                    display_report(report)
                    notebook.select(frames['evidence'])
                elif kind == 'pmtu':
                    display_report(payload)
                    set_text(evidence_box, json.dumps(redacted_data(payload.pmtu), ensure_ascii=False, indent=2))
                    if expert_var.get():
                        notebook.select(frames['evidence'])
                    else:
                        messagebox.showinfo(L('PMTU auxiliary evidence'), '\n\n'.join(pmtu_summary(item, get_language()) for item in payload.pmtu)[-7000:], parent=root)
                    status_var.set(L('PMTU probe finished; review the evidence and limitations.'))
                elif kind == 'wfp':
                    set_text(evidence_box, json.dumps(redacted_data(payload), ensure_ascii=False, indent=2, default=str))
                    notebook.select(frames['evidence'])
                    status_var.set(L('WFP 匯出已返回；請核對成功狀態及權限錯誤。'))
                elif kind == 'elevation':
                    if payload.get('ok'):
                        messagebox.showinfo(L('已要求啟動'), L('管理員啟動要求已提交；確認新視窗後再關閉此視窗。'), parent=root)
                    elif payload.get('cancelled'):
                        status_var.set(L('已取消 UAC，保留目前結果。'))
                    else:
                        messagebox.showerror(L('管理員啟動未完成'), redact(L(payload.get('error', payload))), parent=root)
                update_controls()
        except queue.Empty:
            pass
        if root.winfo_exists():
            state['drain_id'] = root.after(100, drain)

    def close():
        if state['busy'] and state['kind'] == 'repair' and not state['verification_only']:
            messagebox.showinfo(L('操作進行中'), L('請等候修復、驗證與記錄完成後再關閉。'), parent=root)
            return
        state['cancel'].set()
        persist()
        if state.get('drain_id'):
            root.after_cancel(state['drain_id'])
        # Drain pending geometry/theme work before destroying a reusable Tk interpreter.
        root.update_idletasks()
        root.destroy()
    root.protocol('WM_DELETE_WINDOW', close)
    # Stable hook objects support actual Tk integration tests without desktop automation.
    root.winnetdiff_state = state
    root.winnetdiff_close = close
    root.winnetdiff_widgets = {'run': run_button, 'cancel': cancel_button, 'language': language_box,
        'profile': profile_box, 'hosts': hosts_entry, 'expert': expert_button, 'notebook': notebook,
        'layers': layer_tree, 'findings': finding_tree, 'snapshot_changes': snapshot_tree,
        'overview': overview_text, 'status_var': status_var, 'proxy': proxy_button, 'restore': restore_button,
        'snapshot_save': snapshot_save, 'snapshot_base': snapshot_base, 'snapshot_current': snapshot_current,
        'change_language': change_language, 'change_profile': change_profile, 'language_var': language_var,
        'profile_var': profile_var, 'expert_var': expert_var, 'hosts_var': hosts_var,
        'passive_var': passive_var, 'export_report': export_report, 'request_wfp': request_wfp,
        'request_snapshot_save': request_snapshot_save, 'request_elevation': request_elevation,
        'request_guidance': request_guidance, 'display_report': display_report, 'drain': drain,
        'share': share_button, 'show_share_card': show_share_card, 'pmtu': pmtu_button, 'request_pmtu': request_pmtu, 'fake_ip_var': fake_ip_var,
        'retry_same_ip_var': retry_same_ip_var, 'proxy_paths': proxy_paths_button, 'request_proxy_paths': request_proxy_paths,
        'wfp_input': wfp_input_button, 'request_wfp_input': request_wfp_input}
    root.winnetdiff_widgets.update(full_export=full_export_button, request_full_export=request_full_export,
        export_json=export_json, export_md=export_md, export_history=export_history, save_path=save_path,
        start_scan=start_scan, cancel_scan=cancel_scan)
    update_controls()
    state['drain_id'] = root.after(100, drain)
    root.mainloop()
