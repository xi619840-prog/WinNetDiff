"""One evidence contract shared by findings, scenarios and report assembly.

Grades describe observations, never the probability of a culprit. Repetition
needs a concrete host/family/destination and identical measurement context.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import json
from typing import Any
from winnetdiff.analysis.ownership import associate_hosts

EVIDENCE_GRADES = {
    "E1": "Observed: a directly measured state or one failed attempt; cause is unconfirmed.",
    "E2": "Repeated: the same phase difference repeats across attempts or independent targets.",
    "E3": "Corroborated: repeated differential measurements plus independent relevant configuration evidence; causality remains unproven.",
}


def evidence_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return dataclasses.asdict(value) if dataclasses.is_dataclass(value) else vars(value)


def probe_attempts(probes: list[Any]) -> list[dict[str, Any]]:
    result = []
    for value in probes:
        probe = evidence_mapping(value)
        for row in probe.get("attempts") or [probe]:
            item = dict(evidence_mapping(row))
            for key in ("host", "family", "context"):
                item.setdefault(key, probe.get(key, {} if key == "context" else ""))
            # Do not fill in a missing attempt IP from the selected best probe:
            # the other attempt may have measured another DNS answer.
            result.append(item)
    return result


def _evidence_path(row: dict[str, Any]) -> tuple[str, str, str, str] | None:
    host, family, address = str(row.get("host") or "").lower(), str(row.get("family") or ""), str(row.get("ip") or "")
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if not host or family not in ("IPv4", "IPv6") or parsed.version != (4 if family == "IPv4" else 6):
        return None
    context = row.get("context")
    required_context = {"port", "sni", "method", "path", "connect_timeout", "tls_timeout", "http_timeout"}
    if not isinstance(context, dict) or not required_context <= set(context):
        return None
    return host, family, str(parsed), json.dumps(context, sort_keys=True, ensure_ascii=False, default=str)


def corroborating_orphans(security: dict[str, Any], routes: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Corroborate *observed* orphan candidates without requiring NDIS binding.

    WFP callout drivers and user-mode security services need not be represented
    in Get-NetAdapterBinding. Running state must be independently observable
    from a *completed* runtime inventory. Missing uninstall registration alone
    never proves a component is orphaned or that it caused a TLS failure.
    """
    complete = security.get("completeness") or {}
    if complete.get("installed_apps") is not True or complete.get("service_registry") is not True:
        return []
    # NDIS binding metadata is optional corroboration, not an admission gate:
    # WFP drivers and user-mode security services may have no binding there.
    runtime = [row for key in ("drivers_wmi", "driverquery", "services_wmi")
               if complete.get(key) is True for row in security.get(key, [])]
    registry = security.get("service_registry", [])
    records = security.get("evidence", [])
    # Rebuild from the observations, so a forged/stale serialized graph label
    # cannot invent either a host or an orphan.
    actual_ownership = associate_hosts(security, routes, security.get('wfp_context')) if 'ownership' in security else {}
    host_rows = actual_ownership.get('components', [])
    protected_hosts = {str(row.get('Name') or '').casefold() for row in host_rows
                       if row.get('OwnerApps') or row.get('PossibleHosts')}
    # BdNet/BdSentry are OEM/shared clues. If an independently inventoried
    # potential host is still installed, missing a same-name service entry is
    # not sufficient to treat that shared binary as an orphan.
    related_app_installed = any(
        any(vendor in " ".join(str(app.get(k) or "").casefold()
            for k in ("DisplayName", "Publisher", "InstallLocation"))
            for vendor in ("surfshark", "avira"))
        for app in security.get("installed_apps", [])
    )
    # An independent *correlated* provider/endpoint clue supports a shared OEM
    # component, but a random missing application or arbitrary vendor name does not.
    related_endpoint = any(
        row.get("Status") in ("orphan_candidate", "orphan_security_provider")
        and row.get("Group") in ("Surfshark", "Avira", "SharedEndpoint")
        and not row.get("OwnerApps")
        and (row.get("Running") is True or row.get("Status") == "orphan_security_provider")
        for row in records
    )
    result = []
    for evidence in records:
        name = str(evidence.get("Name") or "").casefold()
        if not name or name in protected_hosts or evidence.get("OwnerApps") or evidence.get("Running") is not True:
            continue
        if evidence.get("Group") == "SharedEndpoint" and related_app_installed:
            continue
        running_peers = [row for row in runtime
                         if str(row.get("Name") or "").casefold() == name
                         and (str(row.get("State") or "").casefold() in
                              ("running", "运行中", "正在运行", "執行中")
                              or row.get("Started") is True)]
        if not running_peers:
            continue
        path = str(evidence.get("Path") or next(
            (row.get("PathName") for row in running_peers if row.get("PathName")), "")).casefold()
        registered = any(
            str(row.get("Name") or "").casefold() == name or
            (path and str(row.get("PathName") or "").casefold() == path)
            for row in registry
        )
        status = evidence.get("Status")
        if status == "registration_missing" and not registered:
            result.append(evidence)
        elif status == "orphan_candidate" and registered:
            # A running file can still be a leftover component. Its existence
            # is not negative evidence. It must also have a complete uninstall
            # inventory and no identified installed owner (checked above).
            result.append(evidence)
        elif (status == "owner_unknown" and evidence.get("Group") == "SharedEndpoint"
              and related_endpoint):
            # Treat as a correlated ownership clue, not a proven WFP filter or
            # a license to uninstall an OEM/shared component automatically.
            result.append(evidence)
    # Re-check generic evidence against raw runtime and complete inventories;
    # a serialized graph label alone cannot supply corroboration.
    accepted = {str(row.get('Name') or '').casefold() for row in result}
    bindings = (routes or {}).get('bindings', [])
    for row in host_rows:
        name = str(row.get('Name') or '').casefold()
        peers = [r for r in runtime if str(r.get('Name') or '').casefold() == name
                 and (r.get('Started') is True or str(r.get('State') or '').casefold() in ('running', '运行中', '正在运行', '執行中'))]
        linked = any(link.get('kind') == 'ndis_service' and link.get('live') is True and link.get('enabled') is True for link in row.get('NetworkLinks', []))
        registered = any(str(r.get('Name') or '').casefold() == name for r in registry)
        inconsistent = ((row.get('Inconsistency') == 'registration_missing' and not registered)
                        or row.get('Inconsistency') == 'running_binary_missing' and row.get('File', {}).get('Exists') is False)
        if (name and name not in accepted and name not in protected_hosts and peers and linked and inconsistent
                and actual_ownership.get('bounded_complete') is True and row.get('EligibleCorroboration') is True):
            result.append(row); accepted.add(name)
    return result


def _comparative_context(host: str, context: dict[str, Any]) -> str:
    value = dict(context)
    # Across independent targets the intended SNI follows each host; all other
    # request parameters and phase budgets must still be identical.
    if str(value.get("sni") or "").casefold() == host.casefold():
        value["sni"] = "<target-host>"
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def assess_phase_evidence(probes: list[Any], stages: set[str] | tuple[str, ...], *,
                          corroboration: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Assess matching failures without joining IPs, families or timeout causes."""
    attempts = probe_attempts(probes)
    selected = [row for row in attempts if row.get("stage") in stages and
                (not str(row.get("stage", "")).startswith("tls_") or row.get("tcp_ms") is not None)]
    measured_stages = set(stages) - {"overall_timeout", "cancelled", "probe_error", "unrun"}
    paths: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for row in attempts:
        path = _evidence_path(row)
        if path is not None:
            paths.setdefault(path, []).append(row)
    repeated, persistent = [], []
    concrete_targets: dict[tuple[str, str, str], set[str]] = {}
    for path, rows in paths.items():
        for stage in sorted(measured_stages):
            matching = [r for r in rows if r in selected and r.get("stage") == stage]
            if matching:
                comparison = stage, path[1], _comparative_context(path[0], json.loads(path[3]))
                concrete_targets.setdefault(comparison, set()).add(path[0])
            # Duplicate serialization of one attempt cannot create repetition.
            identities = {r.get("attempt") for r in matching if isinstance(r.get("attempt"), int)}
            if len(identities) >= 2:
                detail = {"host": path[0], "family": path[1], "ip": path[2], "context": json.loads(path[3]), "stage": stage}
                repeated.append(detail)
                if all(r.get("stage") == stage for r in rows):
                    persistent.append(detail)
    persistent_groups: dict[tuple[str, str, str], set[str]] = {}
    for path in persistent:
        comparison = path["stage"], path["family"], _comparative_context(path["host"], path["context"])
        persistent_groups.setdefault(comparison, set()).add(path["host"])
    persistent_multi = any(len(hosts) >= 2 for hosts in persistent_groups.values())
    repeated_measurement = bool(repeated) or any(len(hosts) >= 2 for hosts in concrete_targets.values())
    grade = "E3" if persistent_multi and corroboration else "E2" if repeated_measurement else "E1"
    return {"grade": grade, "attempts": selected, "repeated_paths": repeated,
            "persistent_paths": persistent, "persistent_multitarget": persistent_multi,
            "corroboration": list(corroboration or [])}
