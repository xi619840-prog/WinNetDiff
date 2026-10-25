"""Release evidence cannot be reused across a changed revision."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def script(name):
    with patch.object(sys, 'path', [str(ROOT/'scripts'), *sys.path]):
        spec = importlib.util.spec_from_file_location('tested_' + name, ROOT/'scripts'/(name+'.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


class ReleaseIntegrityTests(unittest.TestCase):
    def test_gate_requires_version_digest_generated_source_and_real_validation(self):
        gate = script('check_release_gate')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'winnetdiff/core').mkdir(parents=True)
            (root/'winnetdiff/core/models.py').write_text("VERSION='2.1.0b2'", encoding='utf-8')
            (root/'pyproject.toml').write_text('version = "2.1.0b2"', encoding='utf-8')
            source = 'synthetic_source = True\n'
            (root/'windows_net_diffdiag.py').write_text(source, encoding='utf-8')
            accepted = dict(version='2.1.0b2', formal_release_ready=True,
                            reviewed_standalone_sha256=hashlib.sha256(source.encode()).hexdigest(),
                            windows_controlled_proxy_write_restore='verified', clean_windows11_vm_exe_smoke='verified')
            with patch.object(gate, '__file__', str(root/'scripts/check_release_gate.py')), patch.object(
                    gate, 'build_source', return_value=source) as builder, contextlib.redirect_stdout(io.StringIO()):
                for change, expected in [({}, 0), ({'version': '2.1.0b1'}, 1), ({'reviewed_standalone_sha256': '0'*64}, 1),
                                         ({'formal_release_ready': False}, 1),
                                         ({'windows_controlled_proxy_write_restore': 'not_executed'}, 1),
                                         ({'clean_windows11_vm_exe_smoke': 'not_executed'}, 1)]:
                    (root/'release-gate.json').write_text(json.dumps({**accepted, **change}), encoding='utf-8')
                    self.assertEqual(gate.main(), expected, change)
                (root/'release-gate.json').write_text(json.dumps(accepted), encoding='utf-8')
                builder.return_value = source + '# changed module'
                self.assertEqual(gate.main(), 1)

    def test_archive_preflights_checksum_and_is_deterministic(self):
        module = script('build_source_zip')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'windows_net_diffdiag.py'; source.write_text('VALUE=1\n', encoding='utf-8')
            output = root/'first.zip'; checksum = root/'first.sha256'
            checksum.write_text('old-checksum', encoding='utf-8')
            with patch.object(module, 'ROOT', root), patch.object(module, 'build_source', return_value='VALUE=1\n'), patch.object(module, 'audit', return_value=(1, [])), patch.object(
                    module, 'proposed_files', return_value=[source]), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with patch.object(sys, 'argv', ['builder', '--output', str(output)]), self.assertRaises(SystemExit):
                    module.main()
                self.assertFalse(output.exists())
                self.assertEqual(checksum.read_text(), 'old-checksum')
                for name in ('second', 'third'):
                    with patch.object(sys, 'argv', ['builder', '--output', str(root/(name+'.zip'))]):
                        self.assertEqual(module.main(), 0)
                self.assertEqual((root/'second.zip').read_bytes(), (root/'third.zip').read_bytes())
