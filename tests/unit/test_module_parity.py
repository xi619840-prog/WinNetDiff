"""Package/standalone parity and a fully mocked modular engine integration.

The generated source is loaded without starting the GUI or issuing OS commands.
This catches flattening/global-name mistakes while remaining CI/offline safe.
"""
import copy
import dataclasses
import importlib.util
import json
from pathlib import Path
import socket
import sys
import types
import unittest
from unittest.mock import patch

from winnetdiff.core import engine, models, i18n
from winnetdiff.core.snapshots import create_snapshot, compare_snapshots
from winnetdiff.analysis.scenarios import evaluate_scenarios
from winnetdiff.analysis.verification import compare_verification
from winnetdiff.reports import export

ROOT = Path(__file__).resolve().parents[2]


def fixture():
    return json.loads((ROOT / "tests" / "fixtures" / "orphaned_endpoint_security_filter.json").read_text(encoding="utf-8"))


def make_report(namespace, locale="en"):
    value = fixture()
    allowed = {f.name for f in dataclasses.fields(namespace.Report)}
    probe_keys = {f.name for f in dataclasses.fields(namespace.Probe)}
    value.update(device="Synthetic Windows 11", administrator=False, locale=locale)
    value["probes"] = [namespace.Probe(**{k: v for k, v in p.items() if k in probe_keys}) for p in value["probes"]]
    return namespace.Report(**{k: v for k, v in value.items() if k in allowed})


def normalized_snapshot(value):
    value = copy.deepcopy(value)
    value.pop("created_at", None)
    return value


class ModuleParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        name = "winnetdiff_parity_build_script"
        spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / "build_standalone.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        cls.generated_source = builder.build_source()
        cls.bundle_name = "winnetdiff_synthetic_standalone_parity"
        cls.bundle = types.ModuleType(cls.bundle_name)
        cls.bundle.__file__ = str(ROOT / "windows_net_diffdiag.py")
        sys.modules[cls.bundle_name] = cls.bundle
        exec(compile(cls.generated_source, cls.bundle.__file__, "exec"), cls.bundle.__dict__)

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop(cls.bundle_name, None)

    def tearDown(self):
        i18n.set_language("en")

    def test_snapshot_categories_and_structural_diff_match(self):
        source = fixture()
        package_snapshot = create_snapshot(source)
        standalone_snapshot = self.bundle.create_snapshot(source)
        self.assertEqual(normalized_snapshot(package_snapshot), normalized_snapshot(standalone_snapshot))
        changed = copy.deepcopy(source)
        changed["route"]["bindings"][0]["Enabled"] = False
        self.assertEqual(compare_snapshots(package_snapshot, create_snapshot(changed)),
                         self.bundle.compare_snapshots(standalone_snapshot, self.bundle.create_snapshot(changed)))

    def test_scenario_and_verification_semantics_match(self):
        source = fixture()
        self.assertEqual(evaluate_scenarios(source), self.bundle.evaluate_scenarios(source))
        after = copy.deepcopy(source)
        for p in after["probes"]:
            p["stage"], p["tls_ms"], p["http_ms"] = "http_ok", 70, 20
            for a in p["attempts"]:
                a["stage"], a["tls_ms"], a["http_ms"] = "http_ok", 70, 20
        package = compare_verification(source, after)
        standalone = self.bundle.compare_verification(source, after)
        # Snapshot creation timestamps can straddle a second; diff observations do not.
        self.assertEqual(package, standalone)

    def test_reports_match_for_three_locales_and_both_privacy_modes(self):
        for locale in ("en", "zh-CN", "zh-TW"):
            for full in (False, True):
                with self.subTest(locale=locale, full=full):
                    package = make_report(models, locale)
                    standalone = make_report(self.bundle, locale)
                    package.scenarios = evaluate_scenarios(package)
                    standalone.scenarios = self.bundle.evaluate_scenarios(standalone)
                    self.assertEqual(export.evidence_text(package, full), self.bundle.evidence_text(standalone, full))
                    self.assertEqual(export.markdown_report(package, full), self.bundle.markdown_report(standalone, full))
                    self.assertEqual(export.summarize(package, full), self.bundle.summarize(standalone, full))

    def test_language_context_and_profile_config_remain_independent(self):
        i18n.set_language("zh-CN")
        self.bundle.set_language("en")
        self.assertEqual(i18n.tr("開始診斷"), "开始诊断")
        self.assertEqual(self.bundle.tr("開始診斷"), "Start diagnosis")
        self.assertNotEqual(self.bundle.resolve_targets("en"), self.bundle.resolve_targets("zh-CN"))
        self.assertEqual(self.bundle.resolve_targets("zh-TW", custom_hosts="example.com"), ["example.com"])

    def test_embedded_selftest_is_usable_without_package_imports(self):
        self.assertIn("_STANDALONE_BUILD = True", self.generated_source)
        # Application imports would violate ordinary-user single-file operation.
        import ast
        tree = ast.parse(self.generated_source)
        self.assertFalse(any(isinstance(n, ast.ImportFrom) and (n.level or str(n.module).startswith("winnetdiff")) for n in ast.walk(tree)))


class ModularEngineMockTests(unittest.TestCase):
    def tearDown(self):
        i18n.set_language("en")

    def test_offline_query_failures_stay_unknown_and_parameters_are_preserved(self):
        progress = []
        with patch("subprocess.run", side_effect=AssertionError("No OS commands in mock integration")), \
             patch("socket.socket", side_effect=AssertionError("No network in mock integration")), \
             patch.object(engine.platform, "platform", return_value="Synthetic Windows"), \
             patch.object(engine, "os", types.SimpleNamespace(name="nt")), \
             patch.object(engine, "collect_proxy", side_effect=PermissionError("synthetic access denied")) as proxy, \
             patch.object(engine, "collect_routes", side_effect=RuntimeError("synthetic query failed")) as routes, \
             patch.object(engine, "collect_security", return_value={"errors": ["synthetic access denied"], "completeness": {}}), \
             patch.object(engine, "probe_host_family") as network, patch.object(engine, "is_admin", return_value=False):
            report = engine.scan(["example.com"], do_network=False, progress=progress.append,
                                 retries=3, locale="zh-TW", profile="traditional")
        network.assert_not_called()
        self.assertEqual(report.locale, "zh-TW")
        self.assertEqual(report.scan_options, {"hosts": ["example.com"], "do_network": False, "retries": 3, "profile": "traditional", "fake_ip_audit": False, "retry_mode": "same-ip"})
        self.assertTrue(any("未知" in f.title for f in report.findings))
        self.assertFalse(any("未找到 IPv4" in f.title for f in report.findings))
        self.assertTrue(report.proxy["errors"])
        self.assertTrue(report.route["errors"])
        self.assertEqual(report.layers["TCP/TLS"]["status"], "未執行主動探針")
        self.assertTrue(all("cancel" in call.kwargs for call in proxy.call_args_list + routes.call_args_list))
        self.assertGreaterEqual(len(progress), 5)

    def test_active_mock_probes_receive_identical_retry_and_cancel_options(self):
        source = fixture()
        observations = []
        def fake_probe(host, family, retries, cancel, retry_mode):
            observations.append((host, family, retries, cancel, retry_mode))
            return models.Probe(host, "IPv4" if family == socket.AF_INET else "IPv6", stage="http_ok", http_status=200)
        with patch("subprocess.run", side_effect=AssertionError("No OS commands in mock integration")), \
             patch("socket.socket", side_effect=AssertionError("No network in mock integration")), \
             patch.object(engine.platform, "platform", return_value="Synthetic Windows"), \
             patch.object(engine, "os", types.SimpleNamespace(name="nt")), \
             patch.object(engine, "collect_proxy", return_value=source["proxy"]), \
             patch.object(engine, "collect_routes", return_value=source["route"]), \
             patch.object(engine, "collect_security", return_value=source["security"]), \
             patch.object(engine, "probe_host_family", side_effect=fake_probe), patch.object(engine, "is_admin", return_value=False):
            report = engine.scan(["example.com"], retries=4, locale="en", profile="global")
        self.assertEqual(len(observations), 2)
        self.assertTrue(all(row[2] == 4 for row in observations))
        self.assertIs(observations[0][3], observations[1][3])
        self.assertTrue(all(row[4] == 'same-ip' for row in observations))
        self.assertEqual(report.scan_options["retries"], 4)

    def test_unavailable_ipv6_does_not_hide_repeated_ipv4_filter_evidence(self):
        source = fixture()
        source["probes"].extend({"host": host, "family": "IPv6", "stage": "dns_error", "attempts": []}
                                for host in source["hosts"])
        candidate = next(s for s in evaluate_scenarios(source) if s["code"] == "tcp_ok_tls_failure")
        self.assertEqual(candidate["grade"], "E3")

    def test_one_failure_per_family_does_not_become_persistent(self):
        source = fixture()
        for p in source["probes"]:
            p["attempts"] = p["attempts"][:1]
        source["probes"].extend(dict(copy.deepcopy(p), family="IPv6", attempts=[dict(p["attempts"][0], family="IPv6")])
                                for p in list(source["probes"]))
        candidate = next(s for s in evaluate_scenarios(source) if s["code"] == "tcp_ok_tls_failure")
        self.assertEqual(candidate["grade"], "E2")


if __name__ == "__main__":
    unittest.main()
