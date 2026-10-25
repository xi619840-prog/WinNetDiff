import copy
import contextlib
import io
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from tests.unit.test_extensions import dns_routes,dns_probe,runtime,private_card_report
from winnetdiff.collectors.dns_audit import audit_dns_state
from winnetdiff.probes.pmtu import parse_ping_result
from winnetdiff.reports.share_card import compact_share_card

ROOT=Path(__file__).resolve().parents[2]


def load_script(name):
    spec=importlib.util.spec_from_file_location('extension_'+name,ROOT/'scripts'/(name+'.py'))
    module=importlib.util.module_from_spec(spec)
    with patch.object(sys,'path',[str(ROOT/'scripts'),*sys.path]):
        spec.loader.exec_module(module)
    return module


class ExtensionBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder=load_script('build_standalone')
        source=cls.builder.build_source()
        cls.bundle=types.ModuleType('extension_bundle');cls.bundle.__file__=str(ROOT/'windows_net_diffdiag.py')
        sys.modules[cls.bundle.__name__]=cls.bundle
        exec(compile(source,cls.bundle.__file__,'exec'),cls.bundle.__dict__)
    @classmethod
    def tearDownClass(cls):sys.modules.pop(cls.bundle.__name__,None)

    def test_BUILD_01_deterministic_source_hash_and_current_artifact(self):
        first=self.builder.build_source().encode();second=self.builder.build_source().encode()
        self.assertEqual(hashlib.sha256(first).digest(),hashlib.sha256(second).digest())
        self.assertEqual(first,(ROOT/'windows_net_diffdiag.py').read_bytes())

    def test_BUILD_02_module_and_bundle_extensions_and_card_identical(self):
        expected=audit_dns_state(dns_routes(),[dns_probe()],runtime(),network_tested=True)
        self.assertEqual(expected,self.bundle.audit_dns_state(dns_routes(),[dns_probe()],runtime(),network_tested=True))
        raw={'stdout':'需要拆分数据包，但是设置 DF。','returncode':1}
        self.assertEqual(parse_ping_result(raw),self.bundle.parse_ping_result(raw))
        report,_=private_card_report()
        for locale in ('en','zh-CN','zh-TW'):
            self.assertEqual(compact_share_card(report,locale),self.bundle.compact_share_card(report,locale))

    def test_help_entrypoints_match_exactly_for_all_languages(self):
        for locale in ('en','zh-CN','zh-TW'):
            results=[subprocess.run([sys.executable,*entry,'--lang',locale,'--help'],cwd=ROOT,capture_output=True,timeout=15)
                     for entry in (['-m','winnetdiff'],['windows_net_diffdiag.py'])]
            self.assertTrue(all(r.returncode==0 for r in results))
            self.assertEqual(results[0].stdout,results[1].stdout)

    def test_builder_rejects_scoped_alias_wildcard_and_unlisted_imports(self):
        cases=['def run():\n    from .a import VALUE\n', 'from .a import VALUE as renamed\n',
               'from .a import *\n','from .missing import VALUE\n','from .a import MISSING\n']
        for source in cases:
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);(root/'winnetdiff').mkdir()
                (root/'winnetdiff/a.py').write_text('VALUE=1\n',encoding='utf-8')
                (root/'winnetdiff/b.py').write_text(source,encoding='utf-8')
                with patch.object(self.builder,'ROOT',root),patch.object(self.builder,'MODULES',['a','b']):
                    with self.assertRaises(ValueError):self.builder.build_source()

    def test_builder_keeps_stdlib_import_execution_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'winnetdiff').mkdir()
            (root/'winnetdiff/a.py').write_text('import math\nmath = 123\n',encoding='utf-8')
            (root/'winnetdiff/b.py').write_text('import math\nRESULT = math.sqrt(9)\n',encoding='utf-8')
            with patch.object(self.builder,'ROOT',root),patch.object(self.builder,'MODULES',['a','b']):
                source=self.builder.build_source()
            namespace={'__name__':'synthetic'};exec(source,namespace)
            self.assertEqual(namespace['RESULT'],3)

    def test_source_archive_refuses_stale_generated_source(self):
        module=load_script('build_source_zip')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'windows_net_diffdiag.py').write_text('old',encoding='utf-8')
            output=root/'candidate.zip'
            with patch.object(module,'ROOT',root),patch.object(module,'build_source',return_value='new'),patch.object(sys,'argv',['builder','--output',str(output)]),contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):module.main()
            self.assertFalse(output.exists())


class ChecksumTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.checksums=load_script('checksums')
    def test_manifest_matches_every_filename_including_spaces_and_unicode(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ('WinNetDiff.exe','README 中文.md','nested/LICENSE'):
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'synthetic candidate')
            self.assertEqual(self.checksums.write_checksums(root),3)
            self.assertEqual(self.checksums.verify_checksums(root),3)
            self.assertNotIn('(_.Name)',(root/'SHA256SUMS.txt').read_text(encoding='utf-8'))
            (root/'WinNetDiff.exe').write_bytes(b'changed')
            with self.assertRaises(ValueError):self.checksums.verify_checksums(root)

    def test_manifest_rejects_wrong_filename_unsafe_duplicate_and_omitted_files(self):
        for line in [('0'*64)+'  (_.Name)\n',('0'*64)+'  ../private\n',('0'*64)+'  a\n'+('0'*64)+'  a\n','']:
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);(root/'a').write_bytes(b'synthetic')
                (root/'SHA256SUMS.txt').write_text(line,encoding='utf-8')
                with self.assertRaises(ValueError):self.checksums.verify_checksums(root)

    def test_CI_02_readonly_pr_and_separate_privileged_jobs(self):
        ci=(ROOT/'.github/workflows/ci.yml').read_text(encoding='utf-8')
        release=(ROOT/'.github/workflows/release.yml').read_text(encoding='utf-8')
        self.assertNotIn('contents: write',ci);self.assertNotIn('id-token: write',ci);self.assertNotIn('attestations: write',ci)
        self.assertIn('actions/attest@1e69f48',release);self.assertNotIn('attest-build-provenance@',release)
        self.assertIn("inputs.create_draft == true",release)
        self.assertLess(release.index('scripts/check_release_gate.py'),release.index('scripts/build_exe.ps1'))
        build=release.split('  validate-build:',1)[1].split('  attest:',1)[0]
        self.assertNotIn('id-token: write',build);self.assertNotIn('contents: write',build)

    def test_release_staging_is_ignored_but_force_tracked_artifacts_are_rejected(self):
        self.assertIn('/release/',(ROOT/'.gitignore').read_text(encoding='utf-8'))
        audit=load_script('publication_audit')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'release').mkdir();artifact=root/'release/WinNetDiff.exe';artifact.write_bytes(b'synthetic')
            with patch.object(audit,'proposed_files',return_value=[artifact]):
                self.assertTrue(audit.audit(root)[1])

    @unittest.skipUnless(sys.platform=='win32','Native PowerShell build failure boundary')
    def test_CI_03_test_failure_stops_before_any_executable_or_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);stub=root/'synthetic_python.cmd';output=root/'candidate'
            # Standalone check succeeds; unittest command fails. No actual
            # Python installation, compiler or system mutation is invoked.
            stub.write_bytes(b'@echo off\r\nif "%~1"=="-m" exit /b 7\r\nexit /b 0\r\n')
            run=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(ROOT/'scripts/build_exe.ps1'),
                                '-Python',str(stub),'-NoInstall','-OutputDirectory',str(output)],cwd=ROOT,capture_output=True,timeout=20)
            self.assertNotEqual(run.returncode,0)
            self.assertFalse(output.exists())
