from dataclasses import asdict
import json
import socket
import unittest
from unittest.mock import patch

import windows_net_diffdiag as app


def routes(**kwargs):
    data = {"defaults_ipv4": [{"InterfaceAlias": "WLAN", "InterfaceIndex": 3,
        "Gateway": "192.168.1.1", "EffectiveMetric": 35, "ConnectionState": "Connected"}],
        "defaults_ipv6": [], "adapters": [{"Name": "WLAN", "Status": "Up", "ifIndex": 3,
        "Classification": "physical"}], "bindings": [], "ipv6_bindings": [],
        "ipv6_addresses": [], "query_status": {"routes": "ok", "bindings": "ok"}, "errors": []}
    data.update(kwargs)
    return data


def security():
    return {"errors": [], "evidence": [], "installed_apps": [], "service_registry": [],
            "drivers_wmi": [], "driverquery": [], "antivirus_products": []}


def proxy(port_live=False, enabled=True, active=True, confirmed=True):
    return {"wininet": {"ProxyEnable": int(enabled), "ProxyServer": "127.0.0.1:7890"},
        "wininet_api": {"flags": 3 if enabled else 1, "ProxyServer": "127.0.0.1:7890",
                         "ProxyOverride": "", "AutoConfigURL": ""}, "applicable_policy": {},
        "effective_scope": "HKCU", "errors": [], "policy": {"values": {}, "error": ""},
        "policy_user": {"values": {}, "error": ""}, "local_listeners": [
        {"host": "127.0.0.1", "port": 7890, "accepts_tcp": port_live, "confirmed_dead": confirmed,
         "pid": 15 if port_live else None, "program": "代理程序.exe" if port_live else None,
         "error": "" if port_live else "connection refused", "references": [
          {"source": "WinINET" if active is True or active is False else "env:process:HTTP_PROXY", "active": active}]}]}


def analyze(p=None, r=None, probes=None, sec=None):
    return app.analyze(p or {"wininet": {}, "local_listeners": [], "errors": []},
                       r or routes(), probes or [], sec or security())


class AnalysisRoutesTests(unittest.TestCase):
    def test_dead_enabled_manual_proxy_is_confirmed(self):
        findings = analyze(p=proxy())
        result = next(f for f in findings if f.layer == "代理")
        self.assertEqual(result.severity, "已確認設定異常")
        self.assertEqual(result.action, "disable_proxy")

    def test_live_manual_proxy_is_information(self):
        findings = analyze(p=proxy(port_live=True, confirmed=False))
        self.assertTrue(all(f.severity == "資訊" for f in findings if f.layer == "代理"))
        self.assertFalse(app.proxy_repair_eligibility(proxy(port_live=True, confirmed=False))["eligible"])

    def test_disabled_manual_proxy_is_not_fault(self):
        findings = analyze(p=proxy(enabled=False, active=False))
        self.assertFalse(any(f.severity == "已確認設定異常" for f in findings))
        self.assertFalse(any(f.action == "disable_proxy" for f in findings))

    def test_environment_proxy_consumption_is_unknown(self):
        data = proxy(enabled=False, active="application-dependent")
        findings = analyze(p=data)
        self.assertTrue(all(f.severity == "資訊" for f in findings if f.layer == "代理"))
        self.assertFalse(any(f.action == "disable_proxy" for f in findings))

    def test_connection_timeout_is_suspicion_not_confirmed_dead_proxy(self):
        findings = analyze(p=proxy(confirmed=False))
        self.assertTrue(any(f.layer == "代理" and f.severity == "可疑" for f in findings))
        self.assertFalse(any(f.severity == "已確認設定異常" for f in findings))

    def test_virtual_lower_metric_is_only_suspicion(self):
        data = routes(defaults_ipv4=[
            {"InterfaceAlias": "WLAN", "InterfaceIndex": 3, "EffectiveMetric": 35, "ConnectionState": "Connected"},
            {"InterfaceAlias": "WireGuard Tunnel", "InterfaceIndex": 40, "EffectiveMetric": 5, "ConnectionState": "Connected"}])
        findings = analyze(r=data)
        result = next(f for f in findings if "多條" in f.title)
        self.assertEqual(result.severity, "可疑")
        self.assertIn("符合預期", result.interpretation)
        self.assertEqual(result.commands, [])

    def test_disconnected_virtual_lower_metric_does_not_win(self):
        data = routes(defaults_ipv4=[
            {"InterfaceAlias": "WLAN", "InterfaceIndex": 3, "EffectiveMetric": 35, "ConnectionState": "Connected"},
            {"InterfaceAlias": "WireGuard Tunnel", "InterfaceIndex": 40, "EffectiveMetric": 5, "ConnectionState": "Disconnected"}])
        self.assertFalse(any("多條" in f.title for f in analyze(r=data)))

    def test_ipv6_without_default_route_is_information_when_ipv4_works(self):
        probes = [app.Probe("example.com", "IPv4", stage="http_ok"),
                  app.Probe("example.com", "IPv6", stage="tcp_error", error="no route")]
        findings = analyze(probes=probes)
        item = next(f for f in findings if f.layer == "IPv4/IPv6")
        self.assertEqual(item.severity, "資訊")
        self.assertIn("無預設路由", item.title)

    def test_disabled_ipv6_is_not_fault(self):
        probes = [app.Probe("example.com", "IPv4", stage="http_ok"), app.Probe("example.com", "IPv6", stage="tcp_error")]
        findings = analyze(r=routes(ipv6_bindings=[{"Name": "WLAN", "Enabled": False}]), probes=probes)
        item = next(f for f in findings if f.layer == "IPv4/IPv6")
        self.assertEqual(item.severity, "資訊")
        self.assertIn("未啟用", item.title)

    def test_dual_stack_tcp_and_tls_timeout_remain_distinct(self):
        for stage in ("tcp_timeout", "tls_timeout"):
            with self.subTest(stage=stage):
                probes = [app.Probe("example.com", "IPv4", stage="http_ok"),
                    app.Probe("example.com", "IPv6", stage=stage, tcp_ms=10 if stage == "tls_timeout" else None)]
                findings = analyze(r=routes(defaults_ipv6=[{"DestinationPrefix": "::/0"}]), probes=probes)
                self.assertTrue(any(f.layer == "IPv4/IPv6" and stage in f.title for f in findings))
                self.assertEqual(any("TCP 成功" in f.title for f in findings), stage == "tls_timeout")

    def test_one_successful_ipv6_host_does_not_hide_other_host_difference(self):
        probes = [app.Probe("first.example.com", "IPv4", stage="http_ok"),
            app.Probe("first.example.com", "IPv6", stage="tls_timeout", tcp_ms=10),
            app.Probe("second.example.com", "IPv4", stage="http_ok"),
            app.Probe("second.example.com", "IPv6", stage="http_ok")]
        findings = analyze(r=routes(defaults_ipv6=[{"DestinationPrefix": "::/0"}]), probes=probes)
        self.assertTrue(any(f.layer == "IPv4/IPv6" and "first.example.com" in f.evidence for f in findings))

    def test_ipv6_query_failure_does_not_imply_absent_route(self):
        data = routes(query_status={"routes": "error", "bindings": "ok"}, errors=["Get-NetRoute: Access denied"])
        probes = [app.Probe("example.com", "IPv4", stage="http_ok"), app.Probe("example.com", "IPv6", stage="tcp_error")]
        findings = analyze(r=data, probes=probes)
        self.assertTrue(any(f.layer == "IPv4/IPv6" and "不完整" in f.title for f in findings))
        self.assertFalse(any("無預設路由" in f.title for f in findings))

    def test_route_query_failure_not_configuration_absent(self):
        findings = analyze(r=routes(defaults_ipv4=[], errors=["Access denied"], query_status={"routes": "error"}))
        result = next(f for f in findings if f.layer == "路由")
        self.assertEqual(result.severity, "資訊")
        self.assertIn("未知", result.title)

    def test_docker_virtualbox_binding_information_and_no_bulk_cleanup(self):
        for component in ("VBoxNetLwf", "docker_filter", "npcap"):
            findings = analyze(r=routes(bindings=[{"Name": "WLAN", "ComponentID": component, "Enabled": True}]))
            result = next(f for f in findings if "綁定" in f.title)
            self.assertEqual(result.severity, "資訊")
            self.assertEqual(result.action, "manual_binding_review")
            self.assertFalse(any("sc delete" in command.lower() for command in result.commands))
            self.assertIn(component, result.commands[0])
            self.assertIn("Enable-NetAdapterBinding", result.rollback)

    def test_binding_name_with_wildcards_uses_exact_input_object(self):
        preview = app.binding_preview({"Name": "WLAN [主卡]*", "ComponentID": "VBoxNetLwf", "Enabled": True})
        self.assertIn("-ceq 'WLAN [主卡]*'", preview["disable"])
        self.assertIn("-Confirm", preview["disable"])
        self.assertNotIn("Disable-NetAdapterBinding -Name", preview["disable"])

    def test_collect_routes_sums_route_and_interface_metrics(self):
        fixtures = [
            [{"Name": "WLAN", "Status": "Up", "HardwareInterface": True, "ifIndex": 3}],
            [{"InterfaceIndex": 3, "AddressFamily": 2, "InterfaceMetric": 25, "ConnectionState": 1}],
            [{"InterfaceIndex": 3, "AddressFamily": 2, "DestinationPrefix": "0.0.0.0/0", "RouteMetric": 10, "NextHop": "192.168.1.1"}],
            [{"Name": "WLAN", "ComponentID": "ms_tcpip6", "Enabled": True}], [], []]
        with patch.object(app, "ps_json", side_effect=[(x, "") for x in fixtures + [[]]]), \
             patch.object(app, "run_command", return_value={"ok": True, "stdout": "", "stderr": ""}):
            result = app.collect_routes()
        self.assertEqual(result["defaults_ipv4"][0]["EffectiveMetric"], 35)
        self.assertEqual(result["adapters"][0]["Classification"], "physical")

    def test_json_report_redacts_raw_bytes_credentials_and_user_path(self):
        evidence = json.dumps({"path": r"C:\Users\Alice\Private\secret.txt", "proxy": "http://alice:password@127.0.0.1:7890"})
        report = app.Report("2.0", "2026-10-24", "Windows 11", False, ["example.com"],
            {"raw_stdout_base64": "U0VDUkVU", "url": "http://alice:password@127.0.0.1:7890"},
            routes(), [], security(), [app.Finding("資訊", "安全/驅動", "sample", evidence, "explanation")], [])
        exported = app.evidence_text(report)
        parsed = json.loads(exported)
        self.assertNotIn("password", exported)
        self.assertNotIn("U0VDUkVU", exported)
        self.assertNotIn("Alice", exported)
        self.assertEqual(parsed["version"], "2.0")
        self.assertIn("Alice", app.evidence_text(report, full=True))

    def test_security_warning_appears_in_fifth_layer(self):
        data = security()
        data["evidence"] = [{"Name": "BdNet", "Status": "registration_missing", "Severity": "高優先級",
                             "Confidence": "高", "Reasons": ["driver present without service"]}]
        findings = analyze(sec=data)
        report = app.Report("2.0", "today", "Windows", False, [], {}, routes(), [], data, findings, [])
        overview = app.layer_overview(report)
        self.assertTrue(overview["安全/驅動"]["evidence"])
        self.assertEqual(overview["安全/驅動"]["status"], "待核對")


if __name__ == "__main__":
    unittest.main()
