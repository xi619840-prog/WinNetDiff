"""External programs must never be located through a Windows search path.

CreateProcess searches the launching executable's directory and the current
directory before System32 for a bare program name. These tests pin the
allowlist, the refusal paths and every call site in the application source.
"""
import ast
import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import windows_net_diffdiag as app
from winnetdiff.core import process

ROOT = Path(__file__).resolve().parents[2]
FAKE_SYSTEM = 'C:\\Windows\\System32'
MODULES = (('standalone', app), ('modular', process))


class SystemToolResolutionTests(unittest.TestCase):
    def test_allowlisted_tools_resolve_under_system_directory(self):
        expected = {
            'powershell.exe': FAKE_SYSTEM + '\\WindowsPowerShell\\v1.0\\powershell.exe',
            'POWERSHELL': FAKE_SYSTEM + '\\WindowsPowerShell\\v1.0\\powershell.exe',
            'netsh': FAKE_SYSTEM + '\\netsh.exe', 'netsh.exe': FAKE_SYSTEM + '\\netsh.exe',
            'route': FAKE_SYSTEM + '\\route.exe', 'tasklist': FAKE_SYSTEM + '\\tasklist.exe',
            'netstat': FAKE_SYSTEM + '\\netstat.exe', 'whoami': FAKE_SYSTEM + '\\whoami.exe',
            'ipconfig': FAKE_SYSTEM + '\\ipconfig.exe', 'ping.exe': FAKE_SYSTEM + '\\ping.exe',
            'driverquery.exe': FAKE_SYSTEM + '\\driverquery.exe',
        }
        for label, module in MODULES:
            for name, path in expected.items():
                with self.subTest(module=label, name=name):
                    self.assertEqual(path, module.resolve_system_tool(name, FAKE_SYSTEM))

    def test_unknown_relative_and_lookalike_programs_are_refused(self):
        for label, module in MODULES:
            for name in ('evil', 'evil.exe', 'netsh.com', 'netsh.bat', '.\\netsh.exe', '..\\netsh.exe',
                         'tools\\netsh.exe', 'tools/netsh.exe', 'C:netsh.exe', '', '.', '..'):
                with self.subTest(module=label, name=name), self.assertRaises(ValueError):
                    module.resolve_system_tool(name, FAKE_SYSTEM)

    def test_untrusted_system_directory_shapes_are_refused(self):
        for label, module in MODULES:
            for base in ('Windows\\System32', 'C:Windows\\System32', '\\Windows\\System32', ''):
                with self.subTest(module=label, base=base), self.assertRaises(OSError):
                    module.resolve_system_tool('netsh', base)

    def test_prepare_argv_on_windows_rewrites_only_bare_names(self):
        for label, module in MODULES:
            with self.subTest(module=label), patch.object(module, '_windows_host', return_value=True):
                self.assertEqual([FAKE_SYSTEM + '\\route.exe', 'print', '-4'],
                                 module.prepare_argv(['route', 'print', '-4'], FAKE_SYSTEM))
                absolute = ['D:\\Python\\python.exe', '-m', 'winnetdiff']
                self.assertEqual(absolute, module.prepare_argv(absolute, FAKE_SYSTEM))
                unc = ['\\\\server\\share\\tool.exe']
                self.assertEqual(unc, module.prepare_argv(unc, FAKE_SYSTEM))
                with self.assertRaises(ValueError):
                    module.prepare_argv([], FAKE_SYSTEM)

    def test_prepare_argv_off_windows_is_unchanged(self):
        for label, module in MODULES:
            with self.subTest(module=label), patch.object(module, '_windows_host', return_value=False):
                self.assertEqual(['route', 'print'], module.prepare_argv(['route', 'print']))


class RunCommandIntegrationTests(unittest.TestCase):
    def test_subprocess_receives_absolute_program_on_windows(self):
        completed = subprocess.CompletedProcess([], 0, b'ok', b'')
        for label, module in MODULES:
            with self.subTest(module=label), patch.object(module, '_windows_host', return_value=True), \
                    patch.object(module, 'system_directory', return_value=FAKE_SYSTEM), \
                    patch.object(module.subprocess, 'run', return_value=completed) as run:
                result = module.run_command(['netsh', 'winhttp', 'show', 'proxy'])
            self.assertTrue(result['ok'])
            self.assertEqual([FAKE_SYSTEM + '\\netsh.exe', 'winhttp', 'show', 'proxy'], run.call_args.args[0])

    def test_powershell_wrapper_uses_absolute_windows_powershell(self):
        completed = subprocess.CompletedProcess([], 0, b'[]', b'')
        with patch.object(app, '_windows_host', return_value=True), \
                patch.object(app, 'system_directory', return_value=FAKE_SYSTEM), \
                patch.object(app.subprocess, 'run', return_value=completed) as run:
            app.powershell('1')
        self.assertEqual(FAKE_SYSTEM + '\\WindowsPowerShell\\v1.0\\powershell.exe', run.call_args.args[0][0])

    def test_refused_program_is_an_incomplete_query_not_a_crash(self):
        for label, module in MODULES:
            with self.subTest(module=label), patch.object(module, '_windows_host', return_value=True), \
                    patch.object(module, 'system_directory', return_value=FAKE_SYSTEM), \
                    patch.object(module.subprocess, 'run') as run:
                result = module.run_command(['planted-tool', '/all'])
            run.assert_not_called()
            self.assertFalse(result['ok'])
            self.assertIsNone(result['returncode'])
            self.assertIn('RefusedExecutable', result['stderr'])

    def test_system_directory_failure_is_an_incomplete_query(self):
        with patch.object(app, '_windows_host', return_value=True), \
                patch.object(app, 'system_directory', side_effect=OSError(5, 'denied')), \
                patch.object(app.subprocess, 'run') as run:
            result = app.run_command(['route', 'print'])
        run.assert_not_called()
        self.assertFalse(result['ok'])
        self.assertIn('RefusedExecutable', result['stderr'])

    @unittest.skipUnless(os.name == 'nt', 'Native GetSystemDirectoryW')
    def test_native_system_directory_is_fully_qualified_system32(self):
        directory = process.system_directory()
        self.assertTrue(process._fully_qualified(directory))
        self.assertEqual('system32', directory.rstrip('\\').rsplit('\\', 1)[-1].lower())


class CallSiteContractTests(unittest.TestCase):
    """Static contract over the modular source, so new call sites cannot regress."""

    def _calls(self):
        for path in sorted((ROOT / 'winnetdiff').rglob('*.py')):
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            # Simple `command = [...]` bindings, so a literal argv built one line
            # earlier is still checked rather than exempted.
            lists = {}
            for node in ast.walk(tree):
                if (isinstance(node, ast.Assign) and len(node.targets) == 1 and
                        isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.List)):
                    lists.setdefault(node.targets[0].id, []).append(node.value)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    yield path.relative_to(ROOT).as_posix(), node, lists

    def test_every_literal_run_command_program_is_allowlisted(self):
        seen = set()
        for where, node, lists in self._calls():
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, 'attr', '')
            if name != 'run_command' or not node.args:
                continue
            argv = node.args[0]
            if isinstance(argv, ast.Name):
                bound = lists.get(argv.id, [])
                self.assertEqual(1, len(bound), f'{where}:{node.lineno}: argv variable must have one literal list binding')
                argv = bound[0]
            self.assertIsInstance(argv, ast.List, where + ': run_command argv must be a literal list')
            program = argv.elts[0]
            self.assertIsInstance(program, ast.Constant, where + ': program must be a literal name')
            seen.add(program.value)
            process.resolve_system_tool(program.value, FAKE_SYSTEM)
        # Guard against the scan silently matching nothing.
        self.assertTrue({'powershell.exe', 'netsh', 'driverquery.exe', 'ping.exe'} <= seen, seen)

    def test_no_other_process_launch_primitives_in_application_code(self):
        forbidden = {('subprocess', 'run'), ('subprocess', 'Popen'), ('subprocess', 'call'),
                     ('subprocess', 'check_call'), ('subprocess', 'check_output'),
                     ('os', 'system'), ('os', 'popen'), ('os', 'startfile'), ('os', 'execv'), ('os', 'spawnv')}
        for where, node, _ in self._calls():
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                pair = (func.value.id, func.attr)
                if pair in forbidden:
                    self.assertEqual('winnetdiff/core/process.py', where,
                                     f'{where}:{node.lineno} launches a process outside run_command')


if __name__ == '__main__':
    unittest.main()
