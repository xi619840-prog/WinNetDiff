import ast
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

from winnetdiff.core.config import resolve_targets
from winnetdiff.core.i18n import get_language, tr
from winnetdiff.gui import app
from winnetdiff.gui.catalog import TRANSLATIONS


class GuiPreferenceTests(unittest.TestCase):
    def test_deliberate_profile_selection_can_resolve_new_defaults(self):
        old = resolve_targets('en')
        text, new, changed = app.choose_profile_hosts(','.join(old), old, 'zh-CN')
        self.assertTrue(changed)
        self.assertEqual(text.split(','), resolve_targets('zh-CN'))
        self.assertEqual(new, resolve_targets('zh-CN'))

    def test_custom_targets_survive_language_switch(self):
        old = resolve_targets('en')
        for custom in ['private.example.com', 'not a valid domain list!']:
            text, new, changed = app.choose_profile_hosts(custom, old, 'zh-TW')
            self.assertEqual(text, custom)
            self.assertFalse(changed)

    def test_explicit_profile_is_independent_of_language(self):
        old = resolve_targets('zh-CN')
        text, new, changed = app.choose_profile_hosts(','.join(old), old, 'en', 'mainland')
        self.assertEqual(new, resolve_targets('zh-CN'))
        self.assertEqual(text.split(','), new)

    def test_all_static_gui_chinese_strings_have_explicit_translation(self):
        source = ast.parse(Path(app.__file__).read_text(encoding='utf-8'))
        strings = {n.args[0].value for n in ast.walk(source) if isinstance(n, ast.Call)
                   and isinstance(n.func, ast.Name) and n.func.id in ('L', 'label', 'button')
                   and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)}
        # Labels/buttons receive parent first, so inspect their second argument too.
        strings |= {n.args[1].value for n in ast.walk(source) if isinstance(n, ast.Call)
                   and isinstance(n.func, ast.Name) and n.func.id in ('label', 'button')
                   and len(n.args) > 1 and isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str)}
        for text in strings:
            if any('\u4e00' <= c <= '\u9fff' for c in text):
                with self.subTest(text=text):
                    self.assertIn(text, TRANSLATIONS)
                    self.assertTrue(TRANSLATIONS[text].get('en'))
                    self.assertTrue(TRANSLATIONS[text].get('zh-CN'))

    @unittest.skipUnless(sys.platform == 'win32', 'Actual Tk Windows integration')
    def test_actual_tk_switch_language_profiles_modes_and_preserve_custom_hosts(self):
        import tkinter as tk
        from tkinter import messagebox
        observed = []
        def harness(root, *args, **kwargs):
            root.withdraw()
            widgets = root.winnetdiff_widgets
            try:
                self.assertEqual(widgets['run'].cget('text'), 'Start diagnosis')
                pending = [root]
                while pending:
                    widget = pending.pop()
                    pending.extend(widget.winfo_children())
                    try:
                        text = str(widget.cget('text'))
                    except tk.TclError:
                        continue
                    self.assertFalse(any('\u4e00' <= c <= '\u9fff' for c in text), text)
                for tab in widgets['notebook'].tabs():
                    self.assertFalse(any('\u4e00' <= c <= '\u9fff' for c in widgets['notebook'].tab(tab, 'text')))
                self.assertEqual(widgets['hosts_var'].get().split(','), resolve_targets('en'))
                widgets['language_var'].set('简体中文')
                widgets['change_language']()
                self.assertEqual(widgets['run'].cget('text'), '开始诊断')
                self.assertEqual(widgets['hosts_var'].get().split(','), resolve_targets('en'))
                self.assertEqual(root.winnetdiff_state['profile'], 'global')
                widgets['hosts_var'].set('custom.example.com')
                widgets['language_var'].set('繁體中文')
                widgets['change_language']()
                self.assertEqual(widgets['run'].cget('text'), '開始診斷')
                self.assertEqual(widgets['hosts_var'].get(), 'custom.example.com')
                widgets['profile_var'].set(tr('全球網站', locale='zh-TW'))
                widgets['change_profile']()
                self.assertEqual(widgets['hosts_var'].get().split(','), resolve_targets('en'))
                widgets['expert_var'].set(True)
                widgets['expert'].invoke()  # Checkbutton toggles; invoke twice to end enabled.
                widgets['expert'].invoke()
                self.assertTrue(widgets['expert_var'].get())
                observed.append(True)
            finally:
                root.winnetdiff_close()
        with patch.object(app, 'load_settings', return_value={}), patch.object(app, 'save_settings') as save, \
             patch.object(tk.Tk, 'mainloop', harness), patch.object(messagebox, 'showerror'):
            app.gui(locale='en')
        self.assertTrue(observed)
        self.assertEqual(save.call_args.args[0]['language'], 'zh-TW')
        self.assertEqual(save.call_args.args[0]['profile'], 'global')

    @unittest.skipUnless(sys.platform == 'win32', 'Actual Tk worker and verification integration')
    def test_proxy_repair_retests_identical_parameters_and_preserves_worker_locale(self):
        import tkinter as tk
        from tkinter import messagebox
        from tests.integration.gui_smoke import synthetic_report
        calls, mutations, observed, callback_errors = [], [], [], []
        class FakeManager:
            def __init__(self, directory):
                pass
            def history(self):
                return []
            def preview_disable_proxy(self, report):
                return {'eligible': True, 'reason': 'Synthetic test only', 'objects': []}
            def disable_proxy(self, report, confirmed=False):
                mutations.append(confirmed)
                return {'ok': True, 'changed': True, 'operation': 'disable_proxy'}
        def fake_scan(**kwargs):
            calls.append(({k: v for k, v in kwargs.items() if k not in ('progress', 'cancel')}, get_language(), threading.get_ident()))
            report = synthetic_report(**kwargs)
            if len(calls) == 1:
                report.probes[0].stage = 'tls_timeout'
                report.probes[0].http_status = None
                report.probes[0].http_ms = None
            return report
        original_loop = tk.Tk.mainloop
        def harness(root, *args, **kwargs):
            root.withdraw()
            phase, ticks = [0], [0]
            root.report_callback_exception = lambda *error: callback_errors.append(str(error))
            def step():
                ticks[0] += 1
                widgets, state = root.winnetdiff_widgets, root.winnetdiff_state
                if phase[0] == 0:
                    phase[0] = 1
                    widgets['run'].invoke()
                elif phase[0] == 1 and state['report'] is not None and not state['busy']:
                    phase[0] = 2
                    widgets['proxy'].invoke()
                elif phase[0] == 2 and state['report'] is not None and state['report'].verification and not state['busy']:
                    observed.append(state['report'].verification)
                    root.winnetdiff_close()
                    return
                if ticks[0] > 200:
                    root.winnetdiff_close()
                    return
                root.after(25, step)
            root.after(20, step)
            return original_loop(root, *args, **kwargs)
        with patch.object(app, 'RepairManager', FakeManager), patch.object(app, 'scan', fake_scan), \
             patch.object(app, 'load_settings', return_value={}), patch.object(app, 'save_settings'), \
             patch.object(tk.Tk, 'mainloop', harness), patch.object(messagebox, 'askyesno', return_value=True), \
             patch.object(messagebox, 'showinfo'), patch.object(messagebox, 'showerror') as errors:
            app.gui(initial_hosts='example.com', locale='zh-CN', retries=3)
        self.assertEqual(mutations, [True])
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], calls[1][0])
        self.assertEqual(calls[0][0]['retries'], 3)
        self.assertTrue(all(row[1] == 'zh-CN' for row in calls))
        self.assertTrue(all(row[2] != threading.get_ident() for row in calls))
        self.assertFalse(callback_errors)
        errors.assert_not_called()
        self.assertTrue(observed)
        self.assertEqual(observed[0]['status'], 'improved')

    @unittest.skipUnless(sys.platform == 'win32', 'Actual mapped Tk layout and DPI regression')
    def test_mapped_initial_and_minimum_windows_keep_bottom_controls_visible(self):
        """Geometry must reserve the footer before an expanding notebook at high DPI."""
        import tkinter as tk
        from tkinter import messagebox
        import traceback
        original_loop = tk.Tk.mainloop
        observed, failures = [], []

        def harness(root, *args, **kwargs):
            widgets = root.winnetdiff_widgets
            root.deiconify()
            initial_size = None
            cases = [(language, size) for language in ['English', '简体中文', '繁體中文']
                     for size in ['initial', 'minimum']]

            def validate_case(index):
                nonlocal initial_size
                try:
                    root.update_idletasks()
                    if initial_size is None:
                        initial_size = (root.winfo_width(), root.winfo_height())
                    if index == len(cases):
                        root.winnetdiff_close()
                        return
                    language, size = cases[index]
                    widgets['language_var'].set(language)
                    widgets['change_language']()
                    width, height = root.minsize() if size == 'minimum' else initial_size
                    root.geometry(f'{width}x{height}')
                    root.after(70, lambda: check_bounds(index, language, size))
                except Exception:
                    failures.append(traceback.format_exc())
                    root.winnetdiff_close()

            def check_bounds(index, language, size):
                try:
                    root.update_idletasks()
                    client_width, client_height = root.winfo_width(), root.winfo_height()
                    footer = root.nametowidget('.main.footer')
                    required = [footer, root.nametowidget('.main.status'), root.nametowidget('.main.progress')]
                    pending = list(footer.winfo_children())
                    while pending:
                        widget = pending.pop()
                        pending.extend(widget.winfo_children())
                        if widget.winfo_class() in ('TButton', 'TLabel'):
                            required.append(widget)
                    rects = []
                    for widget in required:
                        name = str(widget)
                        self.assertTrue(widget.winfo_ismapped(), (language, size, name, 'not mapped'))
                        self.assertGreater(widget.winfo_width(), 1, (language, size, name, 'no width'))
                        self.assertGreater(widget.winfo_height(), 1, (language, size, name, 'no height'))
                        left = widget.winfo_rootx() - root.winfo_rootx()
                        top = widget.winfo_rooty() - root.winfo_rooty()
                        right, bottom = left + widget.winfo_width(), top + widget.winfo_height()
                        self.assertGreaterEqual(left, 0, (language, size, name, left))
                        self.assertGreaterEqual(top, 0, (language, size, name, top))
                        self.assertLessEqual(right, client_width, (language, size, name, right, client_width))
                        self.assertLessEqual(bottom, client_height, (language, size, name, bottom, client_height))
                        rects.append((name, left, top, right, bottom))
                    self.assertTrue(widgets['notebook'].winfo_ismapped(), (language, size, 'notebook'))
                    self.assertGreater(widgets['notebook'].winfo_height(), 60, (language, size, 'notebook lost usable height'))
                    observed.append({'language': language, 'size': size,
                                     'client': (client_width, client_height), 'rects': rects,
                                     'dpi': root.winfo_fpixels('1i')})
                    root.after(20, lambda: validate_case(index + 1))
                except Exception:
                    failures.append(traceback.format_exc())
                    root.winnetdiff_close()

            root.after(100, lambda: validate_case(0))
            return original_loop(root, *args, **kwargs)

        with patch.object(app, 'load_settings', return_value={}), patch.object(app, 'save_settings'), \
             patch.object(tk.Tk, 'mainloop', harness), patch.object(messagebox, 'showerror'):
            app.gui(locale='en', no_network=True)
        self.assertFalse(failures, '\n'.join(failures))
        self.assertEqual(len(observed), 6)


if __name__ == '__main__':
    unittest.main()
