"""Synthetic regression evidence only; no Windows API or network mutations."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from winnetdiff.core.snapshots import (
    SnapshotError, create_snapshot, save_snapshot, load_snapshot, compare_snapshots,
)
from winnetdiff.analysis.scenarios import evaluate_scenarios
from winnetdiff.analysis.verification import compare_verification
from winnetdiff.core.scenario_catalog import SCENARIO_TRANSLATIONS


def sample_report():
    return {
        "version": "2.1.0a1", "locale": "en", "generated_at": "2026-01-01T00:00:00+00:00",
        "hosts": ["example.com", "example.org"], "cancelled": False,
        "scan_options": {"do_network": True, "retries": 2, "profile": "global"},
        "proxy": {"wininet": {"ProxyEnable": 0, "ProxyServer": ""}, "errors": [],
                  "environ_user": {}, "environ_machine": {}, "environ_process": {}, "local_listeners": []},
        "route": {
            "adapters": [{"Name": "WLAN", "ifIndex": 3, "InterfaceGuid": "synthetic-guid", "Status": "Up", "Classification": "physical"}],
            "routes": [{"InterfaceIndex": 3, "AddressFamily": 2, "DestinationPrefix": "0.0.0.0/0", "NextHop": "192.0.2.1", "RouteMetric": 10, "InterfaceMetric": 25, "EffectiveMetric": 35}],
            "defaults_ipv4": [{"InterfaceIndex": 3, "AddressFamily": 2, "DestinationPrefix": "0.0.0.0/0", "NextHop": "192.0.2.1", "InterfaceAlias": "WLAN", "EffectiveMetric": 35}],
            "defaults_ipv6": [], "ipv6_bindings": [{"Name": "WLAN", "ComponentID": "ms_tcpip6", "Enabled": False}],
            "dns_servers": [{"InterfaceIndex": 3, "InterfaceAlias": "WLAN", "AddressFamily": 2, "ServerAddresses": ["192.0.2.53"]}],
            "bindings": [{"Name": "WLAN", "ComponentID": "synthetic_filter", "Enabled": True, "Classification": "unknown-third-party"}],
            "query_status": {key: "ok" for key in ("adapters", "interfaces", "routes", "bindings", "dns_servers")}, "errors": []},
        "security": {"service_registry": [], "services_wmi": [], "drivers_wmi": [], "driverquery": [],
            "installed_apps": [], "antivirus_products": [], "evidence": [], "errors": [],
            "completeness": {key: True for key in ("service_registry", "services_wmi", "drivers_wmi", "driverquery", "installed_apps", "antivirus_products")}},
        "probes": [], "findings": [], "limitations": [],
    }


def probe(host="example.com", stage="tls_timeout", family="IPv4", attempts=2):
    row = {"host": host, "family": family, "ip": "203.0.113.10", "stage": stage,
           "context": {"port": 443, "sni": host, "method": "HEAD", "path": "/",
                       "connect_timeout": 5, "tls_timeout": 6, "http_timeout": 5},
           "dns_ms": 2, "tcp_ms": 10 if stage not in ("dns_error", "tcp_timeout") else None,
           "tls_ms": 50 if stage in ("http_ok", "http_timeout") else 6000,
           "http_ms": 20 if stage == "http_ok" else None, "intermittent": False}
    row["attempts"] = [dict(row, attempt=index + 1) for index in range(attempts)]
    return row


class SnapshotTests(unittest.TestCase):
    def test_roundtrip_schema_and_locale(self):
        report = sample_report()
        report["locale"] = "zh-CN"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "snapshot.json"
            original = save_snapshot(path, report, label="Synthetic known-good")
            loaded = load_snapshot(path)
        self.assertEqual(original, loaded)
        self.assertEqual(loaded["schema_version"], 1)
        self.assertEqual(loaded["locale"], "zh-CN")

    def test_snapshot_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "snapshot.json"
            save_snapshot(path, sample_report())
            with self.assertRaises(FileExistsError):
                save_snapshot(path, sample_report())

    def test_default_snapshot_redacts_secret_paths_and_identifiers(self):
        report = sample_report()
        report["proxy"]["environ_process"] = {"HTTP_PROXY": "http://person:private-password@127.0.0.1:7890", "API_KEY": "synthetic-secret"}
        report["security"]["installed_apps"] = [{"DisplayName": "Synthetic app", "InstallLocation": r"C:\Users\Private Person\Work\Software", "Scope": "user"}]
        text = json.dumps(create_snapshot(report), ensure_ascii=False)
        for secret in ("private-password", "synthetic-secret", "Private Person", "synthetic-guid"):
            self.assertNotIn(secret, text)
        self.assertIn("private-password", json.dumps(create_snapshot(report, full=True)))

    def test_identity_stable_and_redacted(self):
        report = sample_report()
        a, b = create_snapshot(report), create_snapshot(report)
        self.assertEqual(a["categories"], b["categories"])
        self.assertEqual(compare_snapshots(a, b)["changes"], [])
        self.assertNotIn("synthetic-guid", a["categories"]["adapters"][0]["id"])

    def test_added_removed_enabled_disabled_changed(self):
        before = sample_report()
        after = copy.deepcopy(before)
        after["route"]["bindings"][0]["Enabled"] = False
        after["route"]["routes"][0]["RouteMetric"] = 2
        after["route"]["adapters"] = [{"Name": "Ethernet", "ifIndex": 4, "InterfaceGuid": "new-synthetic-guid"}]
        after["proxy"]["wininet"]["ProxyEnable"] = 1
        result = compare_snapshots(create_snapshot(before), create_snapshot(after))
        self.assertEqual(set(c["kind"] for c in result["changes"]), {"added", "removed", "enabled", "disabled", "changed"})
        changed = next(c for c in result["changes"] if c["category"] == "routes")
        self.assertIn("RouteMetric", changed["changed_fields"])

    def test_incomplete_inventory_never_implies_removal(self):
        before = sample_report()
        before["security"]["drivers_wmi"] = [{"Name": "SyntheticDriver", "State": "Running"}]
        after = sample_report()
        after["security"]["completeness"]["drivers_wmi"] = False
        after["security"]["errors"] = ["Access denied"]
        result = compare_snapshots(create_snapshot(before), create_snapshot(after))
        self.assertIn("drivers", result["unavailable_categories"])
        self.assertFalse(any(c["category"] == "drivers" for c in result["changes"]))

    def test_cancelled_snapshot_never_supports_removals(self):
        before = sample_report()
        after = sample_report()
        after["cancelled"] = True
        self.assertFalse(compare_snapshots(create_snapshot(before), create_snapshot(after))["changes"])

    def test_privacy_modes_cannot_be_mixed(self):
        report = sample_report()
        with self.assertRaises(SnapshotError):
            compare_snapshots(create_snapshot(report), create_snapshot(report, full=True))

    def test_duplicate_identity_refused(self):
        report = sample_report()
        report["route"]["bindings"].append(dict(report["route"]["bindings"][0], Enabled=False))
        with self.assertRaisesRegex(SnapshotError, "duplicate"):
            create_snapshot(report)

    def test_runtime_and_registry_service_sources_are_merged(self):
        report = sample_report()
        report["security"]["service_registry"] = [{"Name": "SyntheticSvc", "RegistryStart": 2}]
        report["security"]["services_wmi"] = [{"Name": "syntheticsvc", "State": "Running"}]
        snapshot = create_snapshot(report)
        self.assertEqual(len(snapshot["categories"]["services"]), 1)
        self.assertEqual(set(snapshot["categories"]["services"][0]["value"]["sources"]), {"registry", "wmi"})

    def test_untrusted_schema_duplicate_keys_and_nesting_rejected(self):
        for mutate in (lambda s: s.update(schema_version=2), lambda s: s.update(schema_version=True),
                       lambda s: s["categories"]["bindings"].append(s["categories"]["bindings"][0])):
            snapshot = create_snapshot(sample_report())
            mutate(snapshot)
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "invalid.json"
                path.write_text(json.dumps(snapshot), encoding="utf-8")
                with self.assertRaises(SnapshotError):
                    load_snapshot(path)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "duplicate.json"
            path.write_text('{"format":"winnetdiff.snapshot","format":"other"}', encoding="utf-8")
            with self.assertRaisesRegex(SnapshotError, "Duplicate"):
                load_snapshot(path)


class ScenarioTests(unittest.TestCase):
    def test_orphaned_endpoint_security_filter_regression_case(self):
        path = Path(__file__).parents[1] / "fixtures" / "orphaned_endpoint_security_filter.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        scenarios = evaluate_scenarios(report)
        tls = next(s for s in scenarios if s["code"] == "tcp_ok_tls_failure")
        self.assertEqual(tls["grade"], "E3")
        self.assertEqual(tls["priority"], "high")
        self.assertIn("MTU", " ".join(tls["alternatives"]))
        self.assertIn("does not", " ".join(tls["conditions"]))
        self.assertTrue(any(s["code"] == "orphaned_service_or_driver" for s in scenarios))
        self.assertNotIn("sc delete", json.dumps(scenarios).lower())

    def test_legitimate_third_party_filter_does_not_prove_fault(self):
        report = sample_report()
        report["security"]["evidence"] = [{"Name": "VirtualBox", "Status": "owner_installed"}]
        report["route"]["bindings"][0].update(Classification="known-third-party", OwnerEvidence={"SecurityCorrelation": report["security"]["evidence"]})
        report["probes"] = [probe(stage="http_ok"), probe(host="example.org", stage="http_ok")]
        self.assertEqual(evaluate_scenarios(report), [])

    def test_environment_proxy_alone_not_stale_proxy_scenario(self):
        report = sample_report()
        report["proxy"]["local_listeners"] = [{"confirmed_dead": True, "accepts_tcp": False, "references": [{"active": "application-dependent"}]}]
        self.assertFalse(any(s["code"] == "stale_local_proxy" for s in evaluate_scenarios(report)))

    def test_single_tls_failure_is_observation_not_corroborated_cause(self):
        report = sample_report()
        report["probes"] = [probe(attempts=1)]
        scenario = next(s for s in evaluate_scenarios(report) if s["code"] == "tcp_ok_tls_failure")
        self.assertEqual(scenario["grade"], "E1")

    def test_later_success_prevents_persistent_corroborated_grade(self):
        report = sample_report()
        a = probe()
        a["attempts"][1]["stage"] = "http_ok"
        report["probes"] = [a, probe(host="example.org")]
        report["security"]["evidence"] = [{"Name": "Synthetic", "Status": "orphan_candidate"}]
        scenario = next(s for s in evaluate_scenarios(report) if s["code"] == "tcp_ok_tls_failure")
        self.assertEqual(scenario["grade"], "E2")

    def test_ipv6_unavailable_does_not_create_mismatch_fault(self):
        report = sample_report()
        report["probes"] = [probe(stage="http_ok"), probe(stage="dns_error", family="IPv6")]
        self.assertFalse(any(s["code"] == "ipv6_reachability_mismatch" for s in evaluate_scenarios(report)))

    def test_baseline_change_never_claims_windows_update_causation(self):
        report = sample_report()
        scenario = evaluate_scenarios(report, {"changes": [{"kind": "added", "category": "drivers"}]})[-1]
        self.assertEqual(scenario["code"], "configuration_changed_since_baseline")
        self.assertIn("never inferred", " ".join(scenario["conditions"]))

    def test_each_scenario_has_falsifiable_evidence_contract(self):
        report = sample_report()
        report["probes"] = [probe(stage="http_timeout")]
        report["security"]["evidence"] = [{"Name": "Synthetic", "Status": "orphan_candidate"}]
        for scenario in evaluate_scenarios(report):
            for key in ("code", "evidence", "layer", "reasoning", "alternatives", "verification", "conditions", "risk", "grade"):
                self.assertTrue(scenario[key])
            self.assertNotRegex(json.dumps(scenario), r"\b9[0-9]%")


class VerificationTests(unittest.TestCase):
    def test_protocol_progress_is_observed_improvement(self):
        before, after = sample_report(), sample_report()
        before["probes"], after["probes"] = [probe()], [probe(stage="http_ok")]
        result = compare_verification(before, after)
        self.assertEqual(result["status"], "improved")
        self.assertTrue(result["effective"])
        self.assertIn("does not prove causation", " ".join(result["reasons"]))

    def test_unchanged_failure_or_faster_latency_not_verified(self):
        before = sample_report()
        before["probes"] = [probe()]
        after = copy.deepcopy(before)
        after["probes"][0]["tcp_ms"] = 1
        result = compare_verification(before, after)
        self.assertEqual(result["status"], "not_verified")
        self.assertFalse(result["effective"])

    def test_any_regression_prevents_success_claim(self):
        before, after = sample_report(), sample_report()
        before["probes"] = [probe(), probe(host="example.org", stage="http_ok")]
        after["probes"] = [probe(stage="http_ok"), probe(host="example.org")]
        result = compare_verification(before, after)
        self.assertEqual(result["status"], "regressed")
        self.assertFalse(result["effective"])

    def test_different_targets_or_options_incomparable(self):
        before = sample_report()
        before["probes"] = [probe()]
        for change in ("hosts", "scan_options", "cancelled"):
            after = copy.deepcopy(before)
            after[change] = ["different.example"] if change == "hosts" else {"retries": 1} if change == "scan_options" else True
            self.assertEqual(compare_verification(before, after)["status"], "incomparable")

    def test_missing_or_duplicate_probes_not_success(self):
        before, after = sample_report(), sample_report()
        self.assertEqual(compare_verification(before, after)["status"], "incomparable")
        before["probes"] = [probe(), probe()]
        after["probes"] = [probe(stage="http_ok")]
        self.assertEqual(compare_verification(before, after)["status"], "incomparable")

    def test_resolved_ip_variation_is_reported_alternative(self):
        before, after = sample_report(), sample_report()
        before["probes"], after["probes"] = [probe()], [probe(stage="http_ok")]
        for row in after["probes"][0]["attempts"]:
            row["ip"] = "203.0.113.20"
        result = compare_verification(before, after)
        self.assertIn("IP sets changed", " ".join(result["reasons"]))

    def test_missing_options_cannot_assume_same_defaults(self):
        before, after = sample_report(), sample_report()
        before["scan_options"], after["scan_options"] = {}, {}
        before["probes"], after["probes"] = [probe()], [probe(stage="http_ok")]
        self.assertEqual(compare_verification(before, after)["status"], "incomparable")


class ScenarioCatalogTests(unittest.TestCase):
    def test_every_scenario_explanation_has_three_locales(self):
        fixture = json.loads((Path(__file__).parents[1] / "fixtures" / "orphaned_endpoint_security_filter.json").read_text(encoding="utf-8"))
        for scenario in evaluate_scenarios(fixture):
            texts = [scenario[key] for key in ("title", "reasoning", "repair", "grade_definition")]
            texts += scenario["alternatives"] + scenario["verification"] + scenario["conditions"]
            for text in texts:
                self.assertIn(text, SCENARIO_TRANSLATIONS)
                self.assertEqual(set(SCENARIO_TRANSLATIONS[text]), {"en", "zh-CN", "zh-TW"})

    def test_simplified_and_traditional_preserve_meaningful_script_difference(self):
        item = SCENARIO_TRANSLATIONS["Network configuration differs from the selected baseline"]
        self.assertIn("网络配置", item["zh-CN"])
        self.assertIn("網路設定", item["zh-TW"])


if __name__ == "__main__":
    unittest.main()
