"""Same-configuration repair verification without conflating execution and efficacy."""
from __future__ import annotations

import dataclasses
from typing import Any

from ..core.snapshots import SnapshotError, compare_snapshots, create_snapshot


def _verification_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return dataclasses.asdict(value) if dataclasses.is_dataclass(value) else vars(value)


def _verification_probe_score(stage: str) -> int:
    # Certificate/protocol/timeout differences within a stage are not ranked as
    # improvement; only demonstrable progress through the protocol stack counts.
    if stage == "http_ok":
        return 4
    if stage in ("http_timeout", "http_error", "http_empty", "http_protocol_error", "tls_ok"):
        return 3
    if stage in ("tls_timeout", "tls_error", "tls_cert_error", "tcp_ok"):
        return 2
    if stage in ("tcp_timeout", "tcp_error"):
        return 1
    return 0


def _verification_attempts(probe: dict[str, Any]) -> list[dict[str, Any]]:
    return [_verification_mapping(item) for item in (probe.get("attempts") or [probe])]


def compare_verification(before_report: Any, after_report: Any) -> dict[str, Any]:
    before, after = _verification_mapping(before_report), _verification_mapping(after_report)
    result: dict[str, Any] = {"status": "incomparable", "effective": False,
        "interpretation": "Repair execution and observed network improvement are separate outcomes.",
        "reasons": [], "probe_changes": [], "configuration_diff": None}
    if sorted(before.get("hosts", [])) != sorted(after.get("hosts", [])):
        result["reasons"].append("Target domains differ; rerun the same targets.")
    if before.get("scan_options", {}) != after.get("scan_options", {}):
        result["reasons"].append("Diagnostic parameters differ; rerun identical options.")
    elif not before.get("scan_options"):
        result["reasons"].append("Recorded diagnostic parameters are missing; equal defaults cannot be assumed.")
    if before.get("cancelled") or after.get("cancelled"):
        result["reasons"].append("A scan was cancelled; evidence is incomplete.")
    if any(a.get("stage") == "overall_timeout" for report in (before, after)
           for p in report.get("probes", []) for a in _verification_attempts(_verification_mapping(p))):
        result["reasons"].append("An overall measurement deadline expired; protocol progress cannot be compared reliably.")
    if result["reasons"]:
        return result
    old_probes = {_verification_probe_identity(p): _verification_mapping(p) for p in before.get("probes", [])}
    new_probes = {_verification_probe_identity(p): _verification_mapping(p) for p in after.get("probes", [])}
    if len(old_probes) != len(before.get("probes", [])) or len(new_probes) != len(after.get("probes", [])):
        result["reasons"].append("Duplicate host/family probe identities make verification ambiguous.")
        return result
    if not old_probes or set(old_probes) != set(new_probes):
        result["reasons"].append("Matching active-probe observations are missing; configuration changes alone do not verify network improvement.")
        return result
    improved, regressed, address_differences = [], [], []
    for identity in sorted(old_probes):
        old, new = old_probes[identity], new_probes[identity]
        before_attempts, after_attempts = _verification_attempts(old), _verification_attempts(new)
        old_scores = [_verification_probe_score(p.get("stage", "")) for p in before_attempts]
        new_scores = [_verification_probe_score(p.get("stage", "")) for p in after_attempts]
        old_rate = sum(p.get("stage") == "http_ok" for p in before_attempts) / len(before_attempts)
        new_rate = sum(p.get("stage") == "http_ok" for p in after_attempts) / len(after_attempts)
        phase_progress = min(new_scores) > min(old_scores) and max(new_scores) >= max(old_scores)
        phase_regression = min(new_scores) < min(old_scores) or max(new_scores) < max(old_scores)
        change = {"host": identity[0], "family": identity[1],
                  "before_stage": old.get("stage"), "after_stage": new.get("stage"),
                  "before_success_rate": old_rate, "after_success_rate": new_rate,
                  "before_attempt_count": len(before_attempts), "after_attempt_count": len(after_attempts),
                  "before_ip": old.get("ip"), "after_ip": new.get("ip"),
                  "durations_ms": {phase: {"before": old.get(phase + "_ms"), "after": new.get(phase + "_ms")}
                                   for phase in ("dns", "tcp", "tls", "http")}}
        if old_rate < new_rate or phase_progress:
            improved.append(identity)
            change["result"] = "observed_improvement"
        elif new_rate < old_rate or phase_regression:
            regressed.append(identity)
            change["result"] = "observed_regression"
        else:
            change["result"] = "not_verified"
        old_addresses = {p.get("ip") for p in before_attempts if p.get("ip")}
        new_addresses = {p.get("ip") for p in after_attempts if p.get("ip")}
        if old_addresses != new_addresses:
            address_differences.append(identity)
        result["probe_changes"].append(change)
    try:
        result["configuration_diff"] = compare_snapshots(create_snapshot(before), create_snapshot(after))
    except SnapshotError as exc:
        result["configuration_diff_error"] = str(exc)
    if regressed:
        result["status"] = "regressed"
        result["reasons"].append("At least one same-target protocol path regressed; do not claim repair success.")
    elif improved:
        result["status"], result["effective"] = "improved", True
        result["reasons"].append("The same target/options made demonstrable protocol progress or a higher HTTP-response rate; this does not prove causation.")
    else:
        result["status"] = "not_verified"
        result["reasons"].append("No protocol progress or higher HTTP-response rate was demonstrated. A faster single duration does not establish efficacy.")
    if address_differences:
        result["reasons"].append("Resolved IP sets changed for some targets; server/address variation is an alternative explanation.")
    return result


def _verification_probe_identity(value: Any) -> tuple[str, str]:
    row = _verification_mapping(value)
    return str(row.get("host", "")), str(row.get("family", ""))
