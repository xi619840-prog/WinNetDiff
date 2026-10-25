"""Versioned, local-only network snapshots with deterministic structural diffs.

Snapshots are evidence documents, never executable repair plans. Imported content
is bounded and validated before comparison; an incomplete inventory cannot imply
that an item was removed.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

from .privacy import PSEUDONYM_SCHEME, pseudonym_digest, pseudonym_key_id, redacted_data
from .atomic import atomic_write_text

SNAPSHOT_FORMAT = "winnetdiff.snapshot"
SNAPSHOT_SCHEMA_VERSION = 1
MAX_SNAPSHOT_BYTES = 25 * 1024 * 1024
MAX_CATEGORY_ITEMS = 20000
SNAPSHOT_CATEGORIES = (
    "adapters", "routes", "default_routes", "dns", "proxy", "environment",
    "services", "drivers", "bindings", "security_providers", "installed_apps",
)


class SnapshotError(ValueError):
    """An unsupported, ambiguous, unsafe or malformed snapshot document."""


def _report_data(report: Any) -> dict[str, Any]:
    if dataclasses.is_dataclass(report):
        return dataclasses.asdict(report)
    if isinstance(report, dict):
        return report
    if hasattr(report, "__dict__"):
        return vars(report)
    raise SnapshotError("A report object or mapping is required")


def _canonical(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError) as exc:
        raise SnapshotError("Snapshot values must be finite JSON data") from exc


def _pick(row: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {key: row[key] for key in keys if key in row}


def _stable_id(category: str, identity: Any) -> str:
    # Do not expose raw interface GUIDs, addresses, user aliases or private paths
    # as dictionary keys. Keyed IDs stay comparable on one installation without
    # being reversible by enumerating private address or interface-index spaces.
    return pseudonym_digest("snapshot-row", category + "\0" + _canonical(identity), 24)


def _identity_scheme(snapshot: dict[str, Any]) -> tuple[str, str]:
    # Snapshots written before keyed IDs carry no scheme; they compare only with each other.
    return str(snapshot.get("identity_scheme", "sha256-v0")), str(snapshot.get("identity_key_id", ""))


def _scrub_snapshot(value: Any) -> Any:
    return redacted_data(value)


def _rows(category: str, rows: list[dict[str, Any]], identity, full: bool) -> list[dict[str, Any]]:
    indexed = {}
    for row in rows:
        if not isinstance(row, dict):
            raise SnapshotError(f"{category}: expected object rows")
        ident = _stable_id(category, identity(row))
        clean = row if full else _scrub_snapshot(row)
        if ident in indexed:
            if _canonical(indexed[ident]["value"]) == _canonical(clean):
                continue
            raise SnapshotError(f"{category}: duplicate ambiguous identity {ident}")
        indexed[ident] = {"id": ident, "value": clean}
    return [indexed[key] for key in sorted(indexed)]


def _merge_named_sources(sources: list[tuple[str, list[dict[str, Any]]]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for source, rows in sources:
        for row in rows:
            name = str(row.get("Name") or "").casefold()
            if not name:
                continue
            value = _pick(row, "Name", "DisplayName", "State", "Started", "StartMode", "ServiceType", "PathName", "RegistryStart", "RegistryType")
            grouped.setdefault(name, {"Name": row.get("Name"), "sources": {}})
            previous = grouped[name]["sources"].get(source)
            if previous is not None and _canonical(previous) != _canonical(value):
                raise SnapshotError(f"{source}: duplicate ambiguous service or driver {name}")
            grouped[name]["sources"][source] = value
    return list(grouped.values())


def create_snapshot(report: Any, label: str = "", full: bool = False) -> dict[str, Any]:
    data = _report_data(report)
    route, proxy, security = data.get("route", {}), data.get("proxy", {}), data.get("security", {})
    categories: dict[str, Any] = {}
    categories["adapters"] = _rows("adapters", [
        _pick(row, "Name", "InterfaceDescription", "Status", "ifIndex", "HardwareInterface", "Virtual", "InterfaceGuid", "Classification")
        for row in route.get("adapters", [])],
        lambda r: str(r.get("InterfaceGuid") or r.get("Name") or r.get("ifIndex")).casefold(), full)
    identity_route = lambda r: [r.get("AddressFamily"), r.get("DestinationPrefix"), r.get("InterfaceIndex"),
                                r.get("NextHop", r.get("Gateway")), r.get("PolicyStore")]
    route_keys = ("InterfaceAlias", "InterfaceIndex", "AddressFamily", "DestinationPrefix", "NextHop", "Gateway", "RouteMetric", "InterfaceMetric", "EffectiveMetric", "ConnectionState", "State", "PolicyStore")
    categories["routes"] = _rows("routes", [_pick(r, *route_keys) for r in route.get("routes", [])], identity_route, full)
    categories["default_routes"] = _rows("default_routes", [
        dict(_pick(r, *route_keys), DestinationPrefix=r.get("DestinationPrefix", prefix))
        for key, prefix in (("defaults_ipv4", "0.0.0.0/0"), ("defaults_ipv6", "::/0"))
        for r in route.get(key, [])], identity_route, full)
    dns = route.get("dns_servers", [])
    categories["dns"] = _rows("dns", [_pick(r, "InterfaceIndex", "InterfaceAlias", "AddressFamily", "ServerAddresses") for r in dns],
        lambda r: [r.get("InterfaceIndex", r.get("InterfaceAlias")), r.get("AddressFamily")], full)
    proxy_rows = [{"scope": key, "settings": proxy.get(key, {})} for key in
                  ("wininet", "wininet_user", "wininet_machine", "winhttp", "policy", "policy_user", "effective_scope")]
    # Avoid noisy command transcripts; retain actual settings and direct/proxy state.
    for row in proxy_rows:
        if row["scope"] == "winhttp":
            row["settings"] = _pick(proxy.get("winhttp", {}), "raw", "is_direct", "error", "ok")
    categories["proxy"] = _rows("proxy", proxy_rows, lambda r: r["scope"], full)
    categories["environment"] = _rows("environment", [{"scope": scope, "settings": proxy.get("environ_" + scope, {})}
        for scope in ("user", "machine", "process")], lambda r: r["scope"], full)
    services = _merge_named_sources([("registry", security.get("service_registry", [])), ("wmi", security.get("services_wmi", []))])
    categories["services"] = _rows("services", services, lambda r: str(r["Name"]).casefold(), full)
    drivers = _merge_named_sources([("wmi", security.get("drivers_wmi", [])), ("driverquery", security.get("driverquery", []))])
    categories["drivers"] = _rows("drivers", drivers, lambda r: str(r["Name"]).casefold(), full)
    categories["bindings"] = _rows("bindings", [_pick(r, "Name", "InterfaceDescription", "DisplayName", "ComponentID", "Enabled", "Classification") for r in route.get("bindings", [])],
        lambda r: [str(r.get("Name", "")).casefold(), str(r.get("ComponentID", "")).casefold()], full)
    categories["security_providers"] = _rows("security_providers", [
        _pick(r, "displayName", "pathToSignedProductExe", "pathToSignedReportingExe", "productState")
        for r in security.get("antivirus_products", [])], lambda r: str(r.get("displayName", "")).casefold(), full)
    categories["installed_apps"] = _rows("installed_apps", [
        _pick(r, "DisplayName", "Publisher", "DisplayVersion", "InstallLocation", "Scope", "RegistryKey") for r in security.get("installed_apps", [])],
        lambda r: [r.get("Scope"), r.get("RegistryKey") or [str(r.get("DisplayName", "")).casefold(),
                   str(r.get("Publisher", "")).casefold(), r.get("DisplayVersion"), r.get("InstallLocation")]], full)
    query = route.get("query_status", {})
    complete = security.get("completeness", {})
    route_complete = lambda key: query.get(key) == "ok"
    completeness = {
        "adapters": route_complete("adapters"), "routes": route_complete("routes"),
        "default_routes": route_complete("routes"), "bindings": route_complete("bindings"),
        "dns": route_complete("dns_servers"), "proxy": not bool(proxy.get("errors")) and bool(proxy),
        "environment": not bool(proxy.get("errors")) and bool(proxy),
        "services": bool(complete.get("service_registry")) and bool(complete.get("services_wmi")),
        "drivers": bool(complete.get("drivers_wmi")) and bool(complete.get("driverquery")),
        "security_providers": bool(complete.get("antivirus_products")),
        "installed_apps": bool(complete.get("installed_apps")),
    }
    result = {"format": SNAPSHOT_FORMAT, "schema_version": SNAPSHOT_SCHEMA_VERSION,
              "application_version": str(data.get("version", "unknown")), "locale": str(data.get("locale", "en")),
              "created_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
              "observed_at": str(data.get("generated_at", "")), "label": str(label)[:500],
              "privacy": "full" if full else "redacted", "categories": categories,
              "completeness": completeness,
              "identity_scheme": PSEUDONYM_SCHEME, "identity_key_id": pseudonym_key_id(),
              "collection_errors": {"proxy": proxy.get("errors", []), "route": route.get("errors", []), "security": security.get("errors", [])},
              "cancelled": bool(data.get("cancelled", False))}
    if not full:
        result["collection_errors"] = _scrub_snapshot(result["collection_errors"])
        result["label"] = redacted_data(result["label"])
    if result["cancelled"]:
        result["completeness"] = {key: False for key in SNAPSHOT_CATEGORIES}
    _validate_snapshot(result)
    return result


def _validate_tree(value: Any, depth: int = 0) -> None:
    if depth > 40:
        raise SnapshotError("Snapshot nesting exceeds 40 levels")
    if isinstance(value, dict):
        if len(value) > 10000 or any(not isinstance(key, str) or len(key) > 4096 for key in value):
            raise SnapshotError("Invalid or excessive object keys")
        for item in value.values():
            _validate_tree(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_CATEGORY_ITEMS:
            raise SnapshotError("Snapshot list exceeds item limit")
        for item in value:
            _validate_tree(item, depth + 1)
    elif isinstance(value, str):
        if len(value) > 2 * 1024 * 1024:
            raise SnapshotError("Snapshot text field exceeds limit")
    elif value is not None and not isinstance(value, (int, float, bool)):
        raise SnapshotError("Snapshot contains non-JSON data")


def _validate_snapshot(snapshot: Any) -> dict[str, Any]:
    if not isinstance(snapshot, dict) or snapshot.get("format") != SNAPSHOT_FORMAT:
        raise SnapshotError("Not a WinNetDiff snapshot")
    if type(snapshot.get("schema_version")) is not int or snapshot["schema_version"] != SNAPSHOT_SCHEMA_VERSION:
        raise SnapshotError("Unsupported snapshot schema version")
    if snapshot.get("privacy") not in ("full", "redacted"):
        raise SnapshotError("Snapshot privacy mode is missing or unsupported")
    categories, completeness = snapshot.get("categories"), snapshot.get("completeness")
    if not isinstance(categories, dict) or set(categories) != set(SNAPSHOT_CATEGORIES):
        raise SnapshotError("Snapshot categories do not match schema version 1")
    if not isinstance(completeness, dict) or set(completeness) != set(SNAPSHOT_CATEGORIES) or any(type(v) is not bool for v in completeness.values()):
        raise SnapshotError("Each category needs an explicit completeness boolean")
    if "identity_scheme" in snapshot or "identity_key_id" in snapshot:
        key_id = snapshot.get("identity_key_id")
        if (snapshot.get("identity_scheme") != PSEUDONYM_SCHEME or not isinstance(key_id, str)
                or len(key_id) != 16 or any(c not in "0123456789abcdef" for c in key_id)):
            raise SnapshotError("Unsupported snapshot identity scheme")
    _validate_tree(snapshot)
    _canonical(snapshot)  # Reject NaN/Infinity from permissive JSON decoders.
    for category, rows in categories.items():
        if not isinstance(rows, list) or len(rows) > MAX_CATEGORY_ITEMS:
            raise SnapshotError(f"{category}: expected a bounded entry list")
        seen = set()
        for row in rows:
            if (not isinstance(row, dict) or set(row) != {"id", "value"}
                    or not isinstance(row["id"], str) or len(row["id"]) != 24
                    or any(c not in "0123456789abcdef" for c in row["id"])
                    or not isinstance(row["value"], dict)):
                raise SnapshotError(f"{category}: malformed entry")
            if row["id"] in seen:
                raise SnapshotError(f"{category}: duplicate entry identity")
            seen.add(row["id"])
    return snapshot


def save_snapshot(path: str | Path, report: Any, label: str = "", full: bool = False,
                  overwrite: bool = False) -> dict[str, Any]:
    snapshot = create_snapshot(report, label=label, full=full)
    text = json.dumps(snapshot, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    atomic_write_text(path, text, overwrite=overwrite)
    return snapshot


def load_snapshot(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    if target.stat().st_size > MAX_SNAPSHOT_BYTES:
        raise SnapshotError("Snapshot file exceeds 25 MiB")
    try:
        with target.open("rb") as stream:
            raw = stream.read(MAX_SNAPSHOT_BYTES + 1)
        if len(raw) > MAX_SNAPSHOT_BYTES:
            raise SnapshotError("Snapshot file exceeds 25 MiB")
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise SnapshotError("Duplicate JSON object key")
                result[key] = value
            return result
        snapshot = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SnapshotError("Snapshot is not valid bounded UTF-8 JSON") from exc
    return _validate_snapshot(snapshot)


def _enabled_state(category: str, value: dict[str, Any]) -> Any:
    if category == "bindings" and type(value.get("Enabled")) is bool:
        return value["Enabled"]
    if category == "proxy":
        settings = value.get("settings", {})
        if isinstance(settings, dict):
            if "values" in settings:
                settings = settings.get("values", {})
            if settings.get("ProxyEnable") in (0, 1):
                return bool(settings["ProxyEnable"])
    if category == "services":
        start = value.get("sources", {}).get("registry", {}).get("RegistryStart")
        if type(start) is int:
            return start != 4
    return None


def _changed_fields(before: Any, after: Any, prefix: str = "") -> list[str]:
    if isinstance(before, dict) and isinstance(after, dict):
        result = []
        for key in sorted(set(before) | set(after)):
            path = prefix + "." + key if prefix else key
            if key not in before or key not in after:
                result.append(path)
            else:
                result.extend(_changed_fields(before[key], after[key], path))
        return result
    return [] if _canonical(before) == _canonical(after) else [prefix]


def compare_snapshots(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    _validate_snapshot(before)
    _validate_snapshot(after)
    if before["privacy"] != after["privacy"]:
        raise SnapshotError("Compare snapshots with the same privacy mode")
    if _identity_scheme(before) != _identity_scheme(after):
        # Different keys would make every entry look removed and re-added.
        raise SnapshotError("Snapshots use different identity keys; create both on the same installation "
                            "(baselines from earlier versions must be recreated)")
    changes, unavailable = [], []
    for category in SNAPSHOT_CATEGORIES:
        if not before["completeness"][category] or not after["completeness"][category]:
            unavailable.append(category)
            continue
        old = {row["id"]: row["value"] for row in before["categories"][category]}
        new = {row["id"]: row["value"] for row in after["categories"][category]}
        for identity in sorted(set(old) | set(new)):
            a, b = old.get(identity), new.get(identity)
            if a is None:
                kind, fields = "added", []
            elif b is None:
                kind, fields = "removed", []
            else:
                fields = _changed_fields(a, b)
                if not fields:
                    continue
                start, end = _enabled_state(category, a), _enabled_state(category, b)
                kind = ("enabled" if end else "disabled") if start is not None and end is not None and start != end else "changed"
            changes.append({"kind": kind, "category": category, "id": identity,
                            "before": a, "after": b, "changed_fields": fields})
    return {"format": "winnetdiff.snapshot-diff", "schema_version": 1,
            "before_label": before.get("label", ""), "after_label": after.get("label", ""),
            "before_observed_at": before.get("observed_at", ""), "after_observed_at": after.get("observed_at", ""),
            "privacy": before["privacy"], "changes": changes, "unavailable_categories": unavailable,
            "counts": {kind: sum(c["kind"] == kind for c in changes) for kind in ("added", "removed", "enabled", "disabled", "changed")},
            "interpretation": "Changes are observations, not proof of causality. Incomplete inventories are not compared."}
