"""Offline deadline-origin and shared evidence-contract regressions.

All clocks, sockets and collectors are mocks; no Windows settings are changed.
"""
import copy
import json
from pathlib import Path
import socket
import types
import unittest
from unittest.mock import MagicMock, patch

from winnetdiff.probes import transport
from winnetdiff.analysis.evidence import assess_phase_evidence, corroborating_orphans
from winnetdiff.analysis.rules import analyze
from winnetdiff.analysis.scenarios import evaluate_scenarios
from winnetdiff.analysis.verification import compare_verification
from winnetdiff.core import engine
from winnetdiff.core.models import Finding, Probe

INFO = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.10", 443))
ROOT = Path(__file__).resolve().parents[2]


def audit_fixture():
    return json.loads((ROOT / "tests/fixtures/orphaned_endpoint_security_filter.json").read_text(encoding="utf-8"))


def row(stage="tls_timeout", attempt=1, ip="203.0.113.10", host="example.com", family="IPv4", **extra):
    context = extra.pop("context", {"port": 443, "sni": host, "method": "HEAD", "path": "/",
                                    "connect_timeout": 5, "tls_timeout": 6, "http_timeout": 5})
    return dict(host=host, family=family, ip=ip, stage=stage, tcp_ms=10,
                tls_ms=100, attempt=attempt, context=context, **extra)


class DeadlineOriginTests(unittest.TestCase):
    def endpoint(self, *, tcp_duration=0, tls_duration=0, http_duration=0,
                 tls_error=None, overall=20, tls_timeout=6):
        clock = [0.0]
        raw, secure, context = MagicMock(), MagicMock(), MagicMock()
        def connect(_):
            clock[0] += tcp_duration
        def handshake():
            clock[0] += tls_duration
            if tls_error:
                raise tls_error
        def recv(_):
            clock[0] += http_duration
            return b"HTTP/1.1 200 OK\r\n"
        raw.connect.side_effect = connect
        secure.do_handshake.side_effect = handshake
        secure.recv.side_effect = recv
        secure.version.return_value = "TLSv1.3"
        context.wrap_socket.return_value = secure
        with patch.object(transport.time, "perf_counter", side_effect=lambda: clock[0]), \
             patch.object(transport.socket, "socket", return_value=raw), \
             patch.object(transport.ssl, "create_default_context", return_value=context):
            result = transport.probe_endpoint("example.com", socket.AF_INET, INFO, 2,
                                              overall_timeout=overall, tls_timeout=tls_timeout)
        return result, raw, secure, context

    def test_tcp_consumes_overall_budget_preserves_tcp_time_and_never_starts_tls(self):
        result, raw, secure, context = self.endpoint(tcp_duration=5, overall=4.5)
        self.assertEqual((result.stage, result.timeout_stage), ("overall_timeout", "overall"))
        self.assertEqual(result.tcp_ms, 5000)
        self.assertIsNone(result.tls_ms)
        context.wrap_socket.assert_not_called()
        raw.close.assert_called_once()

    def test_tls_socket_timeout_with_overall_first_is_overall(self):
        result, _, _, _ = self.endpoint(tcp_duration=1, tls_duration=4, overall=4,
                                        tls_timeout=6, tls_error=TimeoutError("socket deadline"))
        self.assertEqual((result.stage, result.timeout_stage), ("overall_timeout", "overall"))
        self.assertEqual(result.tcp_ms, 1000)
        self.assertEqual(result.tls_ms, 4000)

    def test_equal_tls_and_overall_deadline_gives_overall_precedence(self):
        result, _, _, _ = self.endpoint(tcp_duration=1, tls_duration=3, overall=4,
                                        tls_timeout=3, tls_error=TimeoutError("socket deadline"))
        self.assertEqual((result.stage, result.timeout_stage), ("overall_timeout", "overall"))

    def test_tls_phase_deadline_first_remains_tls_even_if_exception_handled_later(self):
        result, _, _, _ = self.endpoint(tcp_duration=1, tls_duration=8, overall=8,
                                        tls_timeout=2, tls_error=TimeoutError("phase deadline"))
        self.assertEqual((result.stage, result.timeout_stage), ("tls_timeout", "tls"))

    def test_immediate_real_tls_timeout_is_still_tls_timeout(self):
        result, _, _, _ = self.endpoint(tls_error=TimeoutError("handshake timeout"))
        self.assertEqual((result.stage, result.timeout_stage), ("tls_timeout", "tls"))

    def test_normal_tls_http_uses_one_socket_and_retains_context(self):
        result, raw, secure, context = self.endpoint(tcp_duration=.1, tls_duration=.2, http_duration=.3)
        self.assertEqual(result.stage, "http_ok")
        self.assertEqual(result.http_status, 200)
        self.assertEqual((result.tcp_ms, result.tls_ms, result.http_ms), (100, 200, 300))
        context.wrap_socket.assert_called_once_with(raw, server_hostname="example.com", do_handshake_on_connect=False)
        secure.sendall.assert_called_once()
        self.assertEqual(result.context["method"], "HEAD")
        self.assertEqual(result.context["port"], 443)

    def test_http_overall_expiration_is_not_http_phase_timeout(self):
        result, _, _, _ = self.endpoint(tcp_duration=1, tls_duration=1, http_duration=4, overall=5)
        self.assertEqual((result.stage, result.timeout_stage), ("overall_timeout", "overall"))
        self.assertEqual(result.tls_ms, 1000)

    def test_configured_dns_budget_is_passed_without_fixed_six_second_cap(self):
        with patch.object(transport, "timeout_dns", return_value=([], "DNSTimeout: test", 12000)) as dns:
            result = transport.probe_host_family("example.com", socket.AF_INET, overall_timeout=30, dns_timeout=12)
        self.assertEqual(dns.call_args.args[2], 12)
        self.assertEqual(result.stage, "dns_timeout")

    def test_retry_admission_uses_configured_connect_plus_tls_budgets(self):
        for connect_timeout, tls_timeout, expected in ((1, 1, 2), (3, 4, 1)):
            clock = [0.0]
            def endpoint(host, family, address, dns_ms, **options):
                clock[0] += 1
                return Probe(host, "IPv4", ip=address[4][0], stage="tls_timeout", tcp_ms=1)
            with self.subTest(connect_timeout=connect_timeout, tls_timeout=tls_timeout), \
                 patch.object(transport.time, "perf_counter", side_effect=lambda: clock[0]), \
                 patch.object(transport, "timeout_dns", return_value=([INFO], "", 0)), \
                 patch.object(transport, "probe_endpoint", side_effect=endpoint) as probe:
                result = transport.probe_host_family("example.com", socket.AF_INET, retries=2,
                    overall_timeout=5, connect_timeout=connect_timeout, tls_timeout=tls_timeout, http_timeout=2)
            self.assertEqual(probe.call_count, expected)
            self.assertEqual(probe.call_args.kwargs["connect_timeout"], connect_timeout)
            self.assertEqual(probe.call_args.kwargs["tls_timeout"], tls_timeout)
            self.assertEqual(len(result.attempts), expected)

    def test_dns_overall_deadline_has_independent_timeout_origin(self):
        clock = [0.0]
        def dns(*_args):
            clock[0] = 2
            return [], "DNSTimeout: limited resolver wait", 2000
        with patch.object(transport.time, "perf_counter", side_effect=lambda: clock[0]), \
             patch.object(transport, "timeout_dns", side_effect=dns):
            result = transport.probe_host_family("example.com", socket.AF_INET, overall_timeout=1, dns_timeout=6)
        self.assertEqual((result.stage, result.timeout_stage), ("overall_timeout", "overall"))

    def test_dns_phase_deadline_first_remains_dns_if_result_handled_late(self):
        clock = [0.0]
        def dns(*_args):
            clock[0] = 3
            return [], "DNSTimeout: resolver wait", 3000
        with patch.object(transport.time, "perf_counter", side_effect=lambda: clock[0]), \
             patch.object(transport, "timeout_dns", side_effect=dns):
            result = transport.probe_host_family("example.com", socket.AF_INET, overall_timeout=2, dns_timeout=1)
        self.assertEqual((result.stage, result.timeout_stage), ("dns_timeout", "dns"))

    def test_overall_timeout_never_outranks_a_genuine_prior_protocol_observation(self):
        tcp = Probe("example.com", "IPv4", ip=INFO[4][0], stage="tcp_error", error="refused")
        overall = Probe("example.com", "IPv4", ip=INFO[4][0], stage="overall_timeout", timeout_stage="overall", tcp_ms=1)
        with patch.object(transport, "timeout_dns", return_value=([INFO], "", 1)), \
             patch.object(transport, "probe_endpoint", side_effect=[tcp, overall]):
            result = transport.probe_host_family("example.com", socket.AF_INET)
        self.assertEqual(result.stage, "tcp_error")
        self.assertEqual([r["stage"] for r in result.attempts], ["tcp_error", "overall_timeout"])


class SharedEvidenceTests(unittest.TestCase):
    def assessment(self, rows, **kwargs):
        return assess_phase_evidence([dict(host="example.com", family="IPv4", attempts=rows)], {"tls_timeout"}, **kwargs)

    def test_one_concrete_observation_is_e1(self):
        self.assertEqual(self.assessment([row()])["grade"], "E1")

    def test_same_destination_and_context_repeats_are_e2(self):
        self.assertEqual(self.assessment([row(), row(attempt=2)])["grade"], "E2")

    def test_different_dns_answers_do_not_make_same_path_repeat(self):
        assessment = self.assessment([row(), row(attempt=2, ip="203.0.113.20")])
        self.assertEqual(assessment["grade"], "E1")
        self.assertFalse(assessment["persistent_paths"])

    def test_missing_attempt_ips_are_not_filled_from_best_ip(self):
        data = {"host": "example.com", "family": "IPv4", "ip": "203.0.113.10",
                "attempts": [row(ip=""), row(ip="", attempt=2)]}
        self.assertEqual(assess_phase_evidence([data], {"tls_timeout"})["grade"], "E1")

    def test_different_measurement_contexts_do_not_count_as_repeat(self):
        first, second = row(), row(attempt=2)
        first["context"]["tls_timeout"], second["context"]["tls_timeout"] = 1, 10
        rows = [first, second]
        self.assertEqual(self.assessment(rows)["grade"], "E1")

    def test_absent_context_cannot_be_assumed_equal_defaults(self):
        rows = [row(context={}), row(attempt=2, context={})]
        self.assertEqual(self.assessment(rows)["grade"], "E1")

    def test_missing_timeout_context_cannot_be_assumed_equal_defaults(self):
        rows = [row(), row(attempt=2)]
        for attempt in rows:
            attempt["context"].pop("tls_timeout")
        self.assertEqual(self.assessment(rows)["grade"], "E1")

    def test_independent_targets_with_different_budgets_are_not_repeat_evidence(self):
        first, second = row(), row(host="example.org")
        second["context"]["tls_timeout"] = 1
        self.assertEqual(self.assessment([first, second])["grade"], "E1")

    def test_multi_target_persistence_with_different_budgets_is_not_e3(self):
        report = audit_fixture()
        report["probes"][1]["context"]["tls_timeout"] = 1
        scenario = next(s for s in evaluate_scenarios(report) if s["code"] == "tcp_ok_tls_failure")
        self.assertEqual(scenario["grade"], "E2")

    def test_duplicate_serialization_is_not_a_second_measurement(self):
        self.assertEqual(self.assessment([row(), row()])["grade"], "E1")

    def test_complete_relevant_inventory_and_multi_target_repetition_are_e3(self):
        report = audit_fixture()
        corroboration = corroborating_orphans(report["security"], report["route"])
        self.assertTrue(corroboration)
        self.assertEqual(assess_phase_evidence(report["probes"], {"tls_timeout"}, corroboration=corroboration)["grade"], "E3")

    def test_unrelated_ipv6_intermittency_cannot_erase_persistent_ipv4(self):
        report = audit_fixture()
        report["probes"].append(dict(host="example.com", family="IPv6", intermittent=True,
            attempts=[row(ip="2001:db8::10", family="IPv6"), row(stage="http_ok", attempt=2, ip="2001:db8::10", family="IPv6")]))
        findings = analyze(report["proxy"], report["route"], [Probe(**p) for p in report["probes"]], report["security"])
        finding = next(f for f in findings if "TCP 成功" in f.title)
        scenario = next(s for s in evaluate_scenarios(report) if s["code"] == "tcp_ok_tls_failure")
        self.assertEqual((finding.evidence_grade, scenario["grade"]), ("E3", "E3"))
        self.assertEqual(finding.priority, 0)

    def test_same_path_later_success_prevents_e3_but_preserves_e2(self):
        report = audit_fixture()
        report["probes"][0]["attempts"][1]["stage"] = "http_ok"
        scenario = next(s for s in evaluate_scenarios(report) if s["code"] == "tcp_ok_tls_failure")
        self.assertEqual(scenario["grade"], "E2")

    def test_running_orphan_corroborates_without_ndis_binding(self):
        report = audit_fixture()
        report["route"]["bindings"][0].pop("OwnerEvidence")
        names = {row['Name'] for row in corroborating_orphans(report["security"], report["route"])}
        self.assertIn('BdNet', names)
        self.assertIn('EndpointProtectionService', names)
        scenario = next(s for s in evaluate_scenarios(report) if s["code"] == "tcp_ok_tls_failure")
        self.assertEqual(scenario["grade"], "E3")

    def test_unverified_label_cannot_replace_runtime_evidence(self):
        report = audit_fixture()
        report['route']['bindings'] = []
        report['security']['drivers_wmi'] = []
        report['security']['services_wmi'] = []
        self.assertFalse(corroborating_orphans(report['security'], report['route']))

    def test_incomplete_inventory_never_supports_absence(self):
        report = audit_fixture()
        report["security"]["completeness"]["service_registry"] = False
        self.assertFalse(corroborating_orphans(report["security"], report["route"]))

    def test_missing_runtime_source_prevents_label_only_corroboration(self):
        report = audit_fixture()
        report["security"]["drivers_wmi"] = []
        report["security"]["services_wmi"] = []
        self.assertFalse(corroborating_orphans(report["security"], report["route"]))

    def test_mixed_tls_failure_types_do_not_create_repeated_differential(self):
        report = audit_fixture()
        for probe in report["probes"]:
            probe["attempts"][1]["stage"] = "tls_cert_error"
        scenario = next(s for s in evaluate_scenarios(report) if s["code"] == "tcp_ok_tls_failure")
        self.assertEqual(scenario["grade"], "E2")

    def test_only_overall_timeouts_never_create_tls_filter_hypothesis(self):
        report = audit_fixture()
        for probe in report["probes"]:
            probe["stage"] = "overall_timeout"
            for attempt in probe["attempts"]:
                attempt.update(stage="overall_timeout", timeout_stage="overall")
        self.assertFalse(any(s["code"] == "tcp_ok_tls_failure" for s in evaluate_scenarios(report)))
        findings = analyze(report["proxy"], report["route"], [Probe(**p) for p in report["probes"]], report["security"])
        self.assertFalse(any("TCP 成功" in f.title for f in findings))
        overall = next(f for f in findings if "整體時間" in f.title)
        self.assertEqual((overall.severity, overall.evidence_grade), ("資訊", "E1"))

    def test_shared_grader_cannot_promote_budget_expiration(self):
        rows = [row(stage="overall_timeout"), row(stage="overall_timeout", attempt=2)]
        self.assertEqual(assess_phase_evidence([{"attempts": rows}], {"overall_timeout"},
                         corroboration=[{"synthetic": True}])["grade"], "E1")

    def test_engine_keeps_e2_and_never_infers_e3_from_priority_zero(self):
        for grade in ("E1", "E2"):
            finding = Finding("高優先級", "TCP/TLS", "Synthetic finding", "synthetic", "reason", priority=0, evidence_grade=grade)
            with self.subTest(grade=grade), patch.object(engine, "os", types.SimpleNamespace(name="nt")), \
                 patch.object(engine, "collect_proxy", return_value={}), patch.object(engine, "collect_routes", return_value={}), \
                 patch.object(engine, "collect_security", return_value={}), patch.object(engine, "analyze", return_value=[finding]), \
                 patch.object(engine, "is_admin", return_value=False):
                report = engine.scan(["example.com"], do_network=False)
            self.assertEqual(report.findings[0].evidence_grade, grade)

    def test_overall_deadline_cannot_be_ranked_as_verification_improvement(self):
        before = audit_fixture()
        after = copy.deepcopy(before)
        for probe in before["probes"]:
            for attempt in probe["attempts"]:
                attempt["stage"] = "overall_timeout"
        result = compare_verification(before, after)
        self.assertEqual(result["status"], "incomparable")
        self.assertFalse(result["effective"])


if __name__ == "__main__":
    unittest.main()
