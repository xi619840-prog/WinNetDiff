"""Explainable scenario hypotheses built from observed evidence, not vendor names.

Evidence grades describe support, not calibrated probabilities. No rule proves a
kernel deadlock or authorizes a system mutation.
"""
from __future__ import annotations

import dataclasses
import re
from typing import Any
from winnetdiff.analysis.evidence import EVIDENCE_GRADES, assess_phase_evidence, corroborating_orphans, probe_attempts


def _scenario_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if dataclasses.is_dataclass(value):
        return dataclasses.asdict(value)
    return vars(value) if hasattr(value, "__dict__") else {}


def _scenario_row(code, title, layer, evidence, reasoning, alternatives, verification,
                  conditions, risk="read_only", grade="E1", priority="review"):
    return {"code": code, "title": title, "layer": layer, "evidence": evidence,
            "reasoning": reasoning, "alternatives": alternatives, "verification": verification,
            "conditions": conditions, "risk": risk, "grade": grade,
            "grade_definition": EVIDENCE_GRADES[grade], "priority": priority,
            "repair": "No automatic system change is authorized by this hypothesis."}


def evaluate_scenarios(report: Any, baseline_diff: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    data = _scenario_mapping(report)
    route, proxy, security = data.get("route", {}), data.get("proxy", {}), data.get("security", {})
    probes = [_scenario_mapping(p) for p in data.get("probes", [])]
    attempts = probe_attempts(probes)
    results = []
    for listener in proxy.get("local_listeners", []):
        active = [r for r in listener.get("references", []) if r.get("active") is True]
        if active and listener.get("confirmed_dead") and not listener.get("accepts_tcp"):
            results.append(_scenario_row("stale_local_proxy", "Enabled proxy points to a refused local port", "proxy", [listener],
                "A configured, active proxy endpoint repeatedly refused TCP connections. Applications using that proxy cannot reach it.",
                ["The proxy is temporarily restarting.", "A local firewall may reject the connection."],
                ["Start the expected proxy client and retry the same endpoint.", "If the client is no longer used, preview the scoped user-proxy repair and verify the same targets afterward."],
                ["The proxy source is actually enabled, not merely an unused environment variable.", "No listener ownership evidence contradicts the refusal."],
                risk="low_with_confirmation", priority="high"))
    connected = [r for r in route.get("defaults_ipv4", []) if str(r.get("ConnectionState", "Connected")) in ("Connected", "1") and r.get("EffectiveMetric") is not None]
    if len(connected) > 1:
        ranked = sorted(connected, key=lambda r: r["EffectiveMetric"])
        first = ranked[0]
        adapter = next((a for a in route.get("adapters", []) if a.get("ifIndex") == first.get("InterfaceIndex")), {})
        if adapter.get("Classification") == "virtual" or re.search(r"vpn|wintun|wireguard|vethernet|virtualbox|docker", str(first.get("InterfaceAlias", "")), re.I):
            results.append(_scenario_row("virtual_default_route", "A virtual interface has the lowest default-route metric", "route", ranked,
                "For equal destination-prefix lengths, route and interface metrics prefer this virtual interface.",
                ["An active VPN intentionally owns the default route.", "More specific split-tunnel routes may take precedence."],
                ["Compare with a known-good snapshot and the intended VPN state.", "Inspect the route for the affected target IP before changing any interface."],
                ["Multiple connected default routes were successfully enumerated.", "Metrics refer to the same address family and prefix length."], risk="manual_network_change"))
    v4good = {p.get("host") for p in probes if p.get("family") == "IPv4" and p.get("stage") == "http_ok"}
    v6bad = [p for p in probes if p.get("family") == "IPv6" and p.get("host") in v4good and p.get("stage") != "http_ok"]
    bindings = route.get("ipv6_bindings", [])
    v6_enabled = any(b.get("Enabled") is True for b in bindings)
    query_ok = route.get("query_status", {}).get("routes") == "ok" and route.get("query_status", {}).get("bindings") == "ok"
    if v6bad and query_ok and v6_enabled and route.get("defaults_ipv6"):
        results.append(_scenario_row("ipv6_reachability_mismatch", "IPv6 is configured but differs from the same-host IPv4 result", "ipv4_ipv6", v6bad,
            "The same host works over IPv4 while an enabled, routed IPv6 path fails at the recorded phase.",
            ["The host has no usable AAAA record.", "An upstream IPv6 route, MTU, server or intermediate device differs."],
            ["Repeat the same domain over both families and inspect the exact IPv6 target route.", "Compare router advertisements and known-good local IPv6 configuration."],
            ["IPv4 succeeded for the same host.", "IPv6 binding and routing queries completed; lack of IPv6 service alone is not a system fault."], risk="read_only"))
    orphan_corroboration = corroborating_orphans(security, route)
    tls_assessment = assess_phase_evidence(probes, {"tls_timeout", "tls_error", "tls_cert_error"}, corroboration=orphan_corroboration)
    tls_failures = tls_assessment["attempts"]
    orphan = [e for e in security.get("evidence", []) if e.get("Status") in ("orphan_candidate", "registration_missing", "orphan_security_provider")]
    if tls_failures:
        grade = tls_assessment["grade"]
        results.append(_scenario_row("tcp_ok_tls_failure", "TCP established but TLS did not complete normally", "tcp_tls",
            tls_assessment,
            "Each recorded attempt completed TCP on the same socket before its TLS-stage failure. Relevant orphan evidence increases investigation priority when the differential repeats.",
            ["Path MTU or packet loss.", "Server-side policy or failure.", "TLS inspection or other intermediate equipment.", "Certificate/time/trust-store failure when certificate validation is the measured error."],
            ["Repeat identical targets and parameters; preserve all IPs and attempt outcomes.", "Inspect read-only WFP/NDIS ownership evidence and compare before/after snapshots.", "Use a trusted vendor removal procedure only after verifying product identity and suitability."],
            ["tcp_ms is present for each TLS-stage failure.", "E3 requires repeated multi-target failures and independently enumerated relevant orphan candidates.", "Correlation does not establish a kernel deadlock or identify a culpable driver."],
            risk="manual_security_component_review", grade=grade, priority="high" if grade == "E3" else "review"))
    http_timeouts = [p for p in attempts if p.get("stage") == "http_timeout" and p.get("tls_ms") is not None]
    if http_timeouts:
        results.append(_scenario_row("tls_ok_http_timeout", "TLS completed but HTTP response did not arrive in time", "http", http_timeouts,
            "The failure is after verified TLS completion, so it is distinct from a TLS handshake failure.",
            ["Server-side application delay.", "Application/content filtering.", "HTTP request policy or connection loss."],
            ["Repeat the same host, method and timeout; compare an independent target.", "Inspect the HTTP-stage error and latency distribution."],
            ["A TLS duration is recorded before HTTP timeout."], grade=assess_phase_evidence(probes, {"http_timeout"})["grade"]))
    unreachable = [p for p in attempts if p.get("stage") in ("tcp_timeout", "tcp_error") and p.get("ip") and p.get("dns_ms") is not None]
    if unreachable:
        results.append(_scenario_row("dns_ok_connect_unreachable", "DNS returned an address but TCP was unreachable", "dns_tcp", unreachable,
            "DNS resolution and TCP reachability are independent stages; the measured destination was known before connect failed.",
            ["Incorrect or stale DNS response.", "Route, firewall, destination policy or ordinary packet loss.", "No usable route for the selected address family."],
            ["Inspect the exact target-IP route and compare another address returned for the same host.", "Repeat across targets and separate IPv4 from IPv6."],
            ["The attempt records an IP and a completed DNS measurement."], grade=assess_phase_evidence(probes, {"tcp_timeout", "tcp_error"})["grade"]))
    if orphan:
        results.append(_scenario_row("orphaned_service_or_driver", "Security or VPN component ownership needs review", "security_driver", orphan,
            "Independent inventory records show an ownership/registration inconsistency. Missing uninstall registration alone is not proof that the main program was removed.",
            ["Portable or enterprise-deployed software.", "A shared SDK owned by a different installed product.", "A component pending reboot or a stale security-center registration."],
            ["Verify publisher signature, product metadata, service path and the current antivirus provider.", "Compare the component with the installed-app list and a known-good snapshot."],
            ["The inventory completeness attached to the evidence supports the stated absence.", "Names alone do not establish product ownership, malware or fault."], risk="manual_security_component_review"))
    products = security.get("antivirus_products", [])
    if len(products) >= 2 and security.get("completeness", {}).get("antivirus_products") is True:
        results.append(_scenario_row("multiple_security_providers", "Multiple antivirus products are registered", "security_driver", products,
            "Security Center contains more than one provider record. Registration does not establish that each product actively filters traffic.",
            ["A stale provider record.", "Expected coexistence with passive or managed products."],
            ["Check the active protection status in the supported Windows/vendor interface.", "Verify signatures and ownership before changing any product."],
            ["The Security Center inventory completed successfully."], risk="manual_security_component_review"))
    suspicious_bindings = [b for b in route.get("bindings", []) if b.get("Enabled") is True
                           and b.get("Classification") not in ("windows", "known-third-party")
                           and any(e.get("Status") in ("orphan_candidate", "registration_missing")
                                   for e in b.get("OwnerEvidence", {}).get("SecurityCorrelation", []))]
    if suspicious_bindings:
        results.append(_scenario_row("ndis_binding_corroborated", "An enabled binding has relevant ownership concerns", "ndis", suspicious_bindings,
            "The enabled binding is correlated with independent service/driver ownership evidence, rather than being flagged solely because its ID is non-Microsoft.",
            ["A legitimate shared filter remains needed by active software.", "The filter is present but unrelated to the current failure."],
            ["Record one exact adapter/component state and prepare its inverse operation.", "Review vendor ownership; only then consider a confirmed one-item isolation test and compare identical probes."],
            ["The binding is currently enabled.", "The correlated record indicates an orphan or registration concern, not just an installed owner."], risk="manual_network_change"))
    if baseline_diff and baseline_diff.get("changes"):
        changes = baseline_diff["changes"]
        results.append(_scenario_row("configuration_changed_since_baseline", "Network configuration differs from the selected baseline", "snapshot", changes,
            "The selected snapshots contain structural additions, removals or configuration changes. Timing alone does not identify the cause.",
            ["A deliberate VPN/network change.", "Application installation or removal.", "Windows servicing or adapter renumbering."],
            ["Correlate the snapshot times with a user-confirmed change or Windows update event.", "Check the changed component and repeat consistent target probes."],
            ["Snapshot schemas and privacy modes are compatible.", "Only complete inventories are compared; Windows-update causation is never inferred from changes alone."], risk="read_only"))
    return results
