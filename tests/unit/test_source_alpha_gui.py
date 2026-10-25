"""GUI-01/02/03: real Tk callbacks/keys, synthetic reports and private temp files.

No real collectors, repairs, UAC, network settings or security components run.
"""
import copy
import gc
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from winnetdiff.core.engine import layer_overview
from winnetdiff.core.i18n import set_language, tr
from winnetdiff.gui import app
from tests.unit import test_i18n_safety_gui as gui_helpers
from tests.unit.test_language_cli import empty_report


class DiagnosisOutcomeTests(unittest.TestCase):
    def test_cancelled_wins_over_missing_collection_and_offline_layers(self):
        report=empty_report('en');report.cancelled=True;report.probes=[]
        report.proxy['errors']=['cancelled']
        self.assertEqual(app.diagnosis_outcome(report),'cancelled')
        self.assertTrue(all(row['status']=='已取消，證據不完整' for row in layer_overview(report).values()))

    def test_partial_collection_is_distinct_from_a_measured_network_failure(self):
        report=empty_report('en')
        self.assertEqual(app.diagnosis_outcome(report),'completed')
        report.proxy['errors']=['synthetic access denied']
        self.assertEqual(app.diagnosis_outcome(report),'partial')
        report.proxy['errors']=[];report.security['completeness']={'service_registry':False}
        self.assertEqual(app.diagnosis_outcome(report),'partial')
        report.security['completeness']={};report.dns_audit={'errors':['synthetic incomplete query']}
        self.assertEqual(app.diagnosis_outcome(report),'partial')


@unittest.skipUnless(sys.platform=='win32','Actual Windows Tk bindings')
class FullExportDialogTests(unittest.TestCase):
    def exercise(self, action, acknowledged=False, language='en', kind='json'):
        import tkinter as tk
        root=tk.Tk();root.geometry('240x100+40+40');root.update()
        errors=[];observed=[]
        def drive():
            window=root.nametowidget('.full_export_confirmation')
            if not window.winfo_viewable():
                root.after(10,drive)
                return
            try:
                w=window.winnetdiff_full_export
                self.assertFalse(w['acknowledged'].get())
                self.assertEqual(str(w['export'].cget('state')),'disabled')
                w['format'].current(0 if kind=='wfp' else ('json','markdown','snapshot','history').index(kind))
                if acknowledged:
                    w['acknowledgement'].invoke()
                    self.assertTrue(w['acknowledged'].get())
                    self.assertEqual(str(w['export'].cget('state')),'normal')
                if action in ('Return','KP_Enter','Escape'):
                    w['export'].focus_force()
                    root.update()
                    self.assertIs(root.focus_get(),w['export'])
                    w['export'].event_generate('<KeyPress-'+action+'>')
                    if window.winfo_exists():w['export'].event_generate('<KeyRelease-'+action+'>')
                    # Some Windows Tk builds do not synthesize KP_Enter.
                    # It may be ignored, but it must never accept full output.
                    if window.winfo_exists():w['cancel'].invoke()
                elif action=='close':
                    window.tk.call(window.protocol('WM_DELETE_WINDOW'))
                elif action=='disabled':
                    w['export'].invoke()
                    self.assertTrue(window.winfo_exists())
                    w['cancel'].invoke()
                else:
                    w['export' if action=='accept' else 'cancel'].invoke()
                observed.append(True)
            except Exception as exc:
                errors.append(exc)
                if window.winfo_exists():window.destroy()
        root.after(80,drive)
        root.after(3000,lambda: (errors.append(AssertionError('Dialog did not close')),root.destroy()))
        try:
            result=app.confirm_full_export(root,language,wfp=kind=='wfp')
            self.assertEqual(errors,[])
            self.assertTrue(observed)
            return result
        finally:
            try:root.destroy()
            except tk.TclError:pass
            gc.collect()

    def test_enter_never_confirms_even_after_acknowledging_and_focusing_export(self):
        for key in ('Return','KP_Enter'):
            for acknowledged in (False,True):
                with self.subTest(key=key,acknowledged=acknowledged):
                    self.assertIsNone(self.exercise(key,acknowledged))

    def test_escape_cancel_and_window_close_never_select_full_data(self):
        for action in ('Escape','cancel','close'):
            for acknowledged in (False,True):
                with self.subTest(action=action,acknowledged=acknowledged):
                    self.assertIsNone(self.exercise(action,acknowledged))

    def test_disabled_export_cannot_accept_without_acknowledgement(self):
        self.assertIsNone(self.exercise('disabled'))

    def test_explicit_acknowledgement_and_export_work_in_three_languages(self):
        for language in ('en','zh-CN','zh-TW'):
            for kind in ('json','markdown','snapshot','history'):
                with self.subTest(language=language,kind=kind):
                    self.assertEqual(self.exercise('accept',True,language,kind),kind)

    def test_raw_wfp_uses_the_same_acknowledgement_and_enter_denial(self):
        self.assertIsNone(self.exercise('disabled',kind='wfp'))
        self.assertIsNone(self.exercise('Return',True,kind='wfp'))
        self.assertEqual(self.exercise('accept',True,kind='wfp'),'wfp')


@unittest.skipUnless(sys.platform=='win32','Isolated Windows Tk export/worker contracts')
class SourceAlphaGuiTests(unittest.TestCase):
    run_gui=gui_helpers.GuiAuditSafetyTests.run_gui
    wait_worker=gui_helpers.GuiAuditSafetyTests.wait_worker

    def tearDown(self):
        set_language('en')
        gc.collect()

    def test_ordinary_json_markdown_history_and_snapshot_always_redact(self):
        from tkinter import filedialog, messagebox
        with tempfile.TemporaryDirectory() as folder:
            paths=[Path(folder)/name for name in ('out.json','out.md','history.json','snapshot.json')]
            report=empty_report('en');report.proxy['SSID']='synthetic-private-wifi'
            report.findings[0].evidence=json.dumps(report.proxy)
            def exercise(root,w,state):
                w['display_report'](report)
                for kind in ('json','markdown','history'):
                    w['export_report'](kind);self.wait_worker(root,state)
                w['request_snapshot_save']();self.wait_worker(root,state)
                for path in paths:
                    self.assertTrue(path.is_file())
                    self.assertNotIn('synthetic-private-wifi',path.read_text(encoding='utf-8'))
                self.assertEqual(json.loads(paths[-1].read_text())['privacy'],'redacted')
            with patch.object(filedialog,'asksaveasfilename',side_effect=list(map(str,paths))), \
                 patch.object(app.RepairManager,'history',return_value=[{'SSID':'synthetic-private-wifi'}]), \
                 patch.object(app,'confirm_full_export') as full, \
                 patch.object(messagebox,'askyesno',return_value=True) as yes:
                self.run_gui(exercise)
            full.assert_not_called();yes.assert_not_called()

    def test_full_data_uses_separate_action_and_preserves_full_formats(self):
        from tkinter import filedialog
        for kind in ('json','markdown','snapshot','history'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                path=Path(folder)/('full.md' if kind=='markdown' else 'full.json')
                report=empty_report('en');report.proxy['SSID']='synthetic-full-wifi'
                report.findings[0].evidence=json.dumps(report.proxy)
                def exercise(root,w,state):
                    w['display_report'](report)
                    w['full_export'].invoke();self.wait_worker(root,state)
                    if kind=='snapshot':self.assertEqual(json.loads(path.read_text())['privacy'],'full')
                    else:self.assertIn('synthetic-full-wifi',path.read_text())
                with patch.object(app,'confirm_full_export',return_value=kind) as consent, \
                     patch.object(app.RepairManager,'history',return_value=[{'SSID':'synthetic-full-wifi'}]), \
                     patch.object(filedialog,'asksaveasfilename',return_value=str(path)):
                    self.run_gui(exercise)
                consent.assert_called_once()

    def test_cancelled_full_consent_does_not_open_file_dialog_or_write(self):
        from tkinter import filedialog
        def exercise(root,w,state):
            w['display_report'](empty_report('en'));w['full_export'].invoke()
            self.assertFalse(state['busy'])
            self.assertIn('cancelled',w['status_var'].get())
        with patch.object(app,'confirm_full_export',return_value=None), \
             patch.object(filedialog,'asksaveasfilename') as save:
            self.run_gui(exercise)
        save.assert_not_called()

    def test_existing_output_directory_is_passed_to_native_dialog(self):
        from tkinter import filedialog
        with tempfile.TemporaryDirectory() as folder:
            def exercise(root,w,state):
                self.assertIsNone(w['save_path']('a.json'))
                self.assertIn('cancelled',w['status_var'].get())
            with patch.object(filedialog,'asksaveasfilename',return_value='') as save, \
                 patch.object(filedialog,'askdirectory') as directory:
                self.run_gui(exercise,_output_dir=folder)
            directory.assert_not_called()
            self.assertEqual(Path(save.call_args.kwargs['initialdir']),Path(folder).resolve())

    def test_missing_output_directory_requires_a_deliberate_existing_folder(self):
        from tkinter import filedialog
        with tempfile.TemporaryDirectory() as folder:
            missing=Path(folder)/'not-created';chosen=Path(folder)/'chosen';chosen.mkdir()
            def exercise(root,w,state):
                self.assertEqual(w['save_path']('a.json'),str(chosen/'a.json'))
                self.assertFalse(missing.exists())
            with patch.object(filedialog,'askdirectory',return_value=str(chosen)) as directory, \
                 patch.object(filedialog,'asksaveasfilename',return_value=str(chosen/'a.json')) as save:
                self.run_gui(exercise,_output_dir=missing)
            self.assertIs(directory.call_args.kwargs['mustexist'],True)
            self.assertEqual(Path(save.call_args.kwargs['initialdir']),chosen.resolve())

    def test_missing_folder_selection_cancel_never_falls_back_to_cwd(self):
        from tkinter import filedialog
        with tempfile.TemporaryDirectory() as folder:
            def exercise(root,w,state):
                w['display_report'](empty_report('en'));w['export_report']('json')
                self.assertFalse(state['busy'])
                self.assertIn('No file was written',w['status_var'].get())
            with patch.object(filedialog,'askdirectory',return_value=''), \
                 patch.object(filedialog,'asksaveasfilename') as save,patch.object(app,'atomic_write_text') as write:
                self.run_gui(exercise,_output_dir=Path(folder)/'missing')
            save.assert_not_called();write.assert_not_called()

    def test_selected_missing_parent_is_rejected_without_writing(self):
        from tkinter import filedialog
        with tempfile.TemporaryDirectory() as folder:
            def exercise(root,w,state):
                w['display_report'](empty_report('en'));w['export_report']('json')
                self.assertFalse(state['busy']);self.assertIn('Save failed',w['status_var'].get())
            with patch.object(filedialog,'asksaveasfilename',return_value=str(Path(folder)/'absent'/'a.json')), \
                 patch.object(app,'atomic_write_text') as write:
                self.run_gui(exercise,expected_error=True)
            write.assert_not_called()

    def test_overwrite_needs_explicit_yes_and_defaults_no(self):
        from tkinter import filedialog,messagebox
        for answer in (False,True):
            with self.subTest(answer=answer),tempfile.TemporaryDirectory() as folder:
                path=Path(folder)/'old.json';path.write_text('original')
                def exercise(root,w,state):
                    w['display_report'](empty_report('en'));w['export_report']('json')
                    self.wait_worker(root,state)
                    if answer:self.assertEqual(json.loads(path.read_text())['locale'],'en')
                    else:self.assertEqual(path.read_text(),'original')
                with patch.object(filedialog,'asksaveasfilename',return_value=str(path)), \
                     patch.object(messagebox,'askyesno',return_value=answer) as yes:
                    self.run_gui(exercise)
                yes.assert_called_once();self.assertEqual(yes.call_args.kwargs['default'],messagebox.NO)

    def test_permission_failure_preserves_old_file_and_reports_save_failed(self):
        from tkinter import filedialog,messagebox
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'old.json';path.write_text('original')
            def exercise(root,w,state):
                w['display_report'](empty_report('en'));w['export_report']('json');self.wait_worker(root,state)
                self.assertIn('Save failed',w['status_var'].get())
                self.assertEqual(path.read_text(),'original')
                self.assertEqual(list(Path(folder).iterdir()),[path])
            with patch.object(filedialog,'asksaveasfilename',return_value=str(path)), \
                 patch.object(messagebox,'askyesno',return_value=True), \
                 patch('winnetdiff.core.atomic.os.replace',side_effect=PermissionError('synthetic access denied')):
                self.run_gui(exercise,expected_error=True)

    def test_cancel_worker_keeps_partial_evidence_and_allows_fresh_restart(self):
        calls=[];started=threading.Event()
        def scan(**kwargs):
            calls.append(kwargs);started.set()
            if len(calls)==1:
                self.assertTrue(kwargs['cancel'].wait(2))
                time.sleep(.05)
            return empty_report(kwargs['locale'])  # Deliberately races with late cancellation.
        def exercise(root,w,state):
            w['start_scan']();first=state['worker']
            self.assertTrue(started.wait(1));w['start_scan']()
            self.assertEqual(len(calls),1)
            self.assertEqual(str(w['run'].cget('state')),'disabled')
            w['cancel'].invoke();self.wait_worker(root,state)
            self.assertFalse(first.is_alive())
            self.assertTrue(state['report'].cancelled)
            self.assertEqual(state['diagnosis_status'],'cancelled')
            self.assertTrue(state['report'].findings)
            for language,label in [('en','English'),('zh-CN','简体中文'),('zh-TW','繁體中文')]:
                w['language_var'].set(label);w['change_language']()
                message=tr('診斷已取消，以下結果可能不完整。',language)
                self.assertEqual(w['status_var'].get(),message)
                self.assertTrue(w['overview'].get('1.0','end').startswith(message))
            self.assertEqual(str(w['cancel'].cget('state')),'disabled')
            w['start_scan']();self.wait_worker(root,state)
            self.assertIsNot(state['worker'],first)
            self.assertFalse(state['worker'].is_alive())
            self.assertFalse(state['report'].cancelled)
            self.assertEqual(state['diagnosis_status'],'completed')
            self.assertEqual(len(calls),2)
        with patch.object(app,'scan',scan):self.run_gui(exercise)

    def test_partial_and_failed_are_distinct_and_failed_retains_previous_evidence(self):
        report=empty_report('en');report.proxy['errors']=['synthetic query unavailable']
        def exercise(root,w,state):
            w['display_report'](report)
            self.assertEqual(state['diagnosis_status'],'partial')
            self.assertIn('Partial / Incomplete',w['status_var'].get())
            w['start_scan']();self.wait_worker(root,state)
            self.assertEqual(state['diagnosis_status'],'failed')
            self.assertIs(state['report'],report)
            self.assertIn('failed',w['status_var'].get())
            w['language_var'].set('繁體中文');w['change_language']()
            self.assertIn('診斷失敗',w['status_var'].get())
        with patch.object(app,'scan',side_effect=RuntimeError('synthetic collection failed')):
            self.run_gui(exercise,expected_error=True)
