import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('publication_audit', ROOT / 'scripts' / 'publication_audit.py')
audit_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit_module)


class PublicationAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.environment = patch.dict(os.environ, {'USERNAME': 'RunnerAdmin', 'USER': 'runner'})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def write(self, name, text='safe'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def test_safe_source_and_synthetic_fixture_allowed(self):
        self.write('winnetdiff/repairs/manager.py', 'VALUE = 1\n')
        self.write('tests/fixtures/profile.json', '{"path":"C:\\\\Users\\\\SyntheticOwner\\\\app.exe"}')
        count, errors = audit_module.audit(self.root)
        self.assertEqual(count, 2)
        self.assertEqual(errors, [])

    def test_ordinary_source_cannot_contain_private_profile_path(self):
        self.write('app.py', 'value = r"C:\\Users\\SyntheticOwner\\private.txt"')
        self.assertTrue(any('profile path' in error for error in audit_module.audit(self.root)[1]))

    def test_opaque_credential_and_identifier_patterns_rejected(self):
        token = 'ghp_' + 'x' * 30
        self.write('config.txt', token)
        self.assertTrue(any('potential secret' in error for error in audit_module.audit(self.root)[1]))
        self.write('config.txt', '-'.join(['S', '1', '5', '21', '11111', '22222', '33333', '1001']))
        self.assertTrue(any('potential secret' in error for error in audit_module.audit(self.root)[1]))

    def test_local_output_is_not_proposed_by_filesystem_fallback(self):
        self.write('README.md')
        self.write('.local_validation/report.json', 'private output')
        self.assertEqual(audit_module.audit(self.root), (1, []))

    def test_tracked_ignored_output_is_rejected(self):
        self.write('.gitignore', 'dist/\n.local_validation/\n')
        self.write('dist/app.exe', 'binary fixture')
        self.write('.local_validation/report.json', 'private fixture')
        try:
            subprocess.run(['git', 'init', '-q'], cwd=self.root, check=True, capture_output=True)
        except FileNotFoundError:
            self.skipTest('Git unavailable')
        subprocess.run(['git', 'add', '-f', 'dist/app.exe', '.local_validation/report.json'], cwd=self.root, check=True, capture_output=True)
        errors = audit_module.audit(self.root)[1]
        self.assertTrue(any('dist/app.exe' in error for error in errors))
        self.assertTrue(any('local_validation/report.json' in error for error in errors))

    def test_configurable_personal_marker_never_echoes_matched_value(self):
        marker = 'SyntheticOwner123'
        self.write('README.md', marker)
        errors = audit_module.audit(self.root, [marker])[1]
        self.assertTrue(errors)
        self.assertTrue(all(marker not in error for error in errors))

    def test_runtime_module_omitted_from_public_tree_is_rejected(self):
        self.write('scripts/build_standalone.py', "MODULES = ['core/models', 'repairs/manager']\n")
        self.write('winnetdiff/core/models.py', 'VERSION = "test"\n')
        errors = audit_module.audit(self.root)[1]
        self.assertTrue(any('winnetdiff/repairs/manager.py' in error and 'required runtime module' in error for error in errors))


if __name__ == '__main__':
    unittest.main()
