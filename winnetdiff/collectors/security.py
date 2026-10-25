from __future__ import annotations
import argparse
import base64
import codecs
import csv
import ctypes
import datetime as dt
import io
import ipaddress
import json
import locale
import ntpath
import os
import platform
import queue
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional
if os.name == 'nt':
    import winreg
else:
    winreg = None
from winnetdiff.core.atomic import publish_file
from winnetdiff.core.messages import Message, msg
from winnetdiff.core.i18n import tr
from winnetdiff.core.models import Finding
from winnetdiff.core.process import ps_json, run_command


SECURITY_VENDOR_RE = re.compile(
    r"surfshark|avira|bdnet|bdsentry|endpointprotection|endpoint protection|"
    r"geevpn|闪连|閃連|proton|openvpn|wintun|wireguard|flclash|clash|"
    r"sangfor|深信服|ruijie|锐捷|銳捷|npcap|virtualbox|docker", re.I)


ENDPOINT_SDK_PATH = r"C:\Program Files\Surfshark\Endpoint Protection SDK\endpointprotection.exe"


def inspect_inf_provider(inf_name, _directory=None):
    """Read INF Version strings via SetupAPI. This never installs a driver or runs INF code."""
    name = str(inf_name or "")
    result = {"InfPath": name, "ProviderName": None, "Class": None, "ClassGuid": None,
              "ProviderSource": "Local INF Version via SetupAPI", "Error": ""}
    if not re.fullmatch(r"[\w .-]+\.inf", name, re.I) or ntpath.basename(name) != name:
        result["Error"] = tr('僅接受本機 Windows INF 資料夾內的 INF 檔名')
        return result
    if os.name != "nt":
        result["Error"] = tr('SetupAPI 僅支援 Windows')
        return result
    directory = Path(_directory) if _directory is not None else Path(os.environ.get("SystemRoot", r"C:\Windows")) / "INF"
    path = directory / name
    from ctypes import wintypes
    class INFCONTEXT(ctypes.Structure):
        _fields_ = [("Inf", ctypes.c_void_p), ("CurrentInf", ctypes.c_void_p),
                    ("Section", wintypes.UINT), ("Line", wintypes.UINT)]
    try:
        api = ctypes.WinDLL("setupapi", use_last_error=True)
        api.SetupOpenInfFileW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                           ctypes.POINTER(wintypes.UINT)]
        api.SetupOpenInfFileW.restype = ctypes.c_void_p
        api.SetupFindFirstLineW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                           ctypes.POINTER(INFCONTEXT)]
        api.SetupFindFirstLineW.restype = wintypes.BOOL
        api.SetupGetStringFieldW.argtypes = [ctypes.POINTER(INFCONTEXT), wintypes.DWORD,
            wintypes.LPWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        api.SetupGetStringFieldW.restype = wintypes.BOOL
        api.SetupCloseInfFile.argtypes = [ctypes.c_void_p]
        api.SetupCloseInfFile.restype = None
        handle = api.SetupOpenInfFileW(str(path), None, 2, None)  # INF_STYLE_WIN4, read only
        if handle in (None, ctypes.c_void_p(-1).value):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            for key in ("Provider", "Class", "ClassGuid"):
                context = INFCONTEXT()
                if not api.SetupFindFirstLineW(handle, "Version", key, ctypes.byref(context)):
                    if key == "Provider":
                        result["Error"] = tr('INF Version 未找到 Provider')
                    continue
                buffer = ctypes.create_unicode_buffer(4096)
                required = wintypes.DWORD()
                if not api.SetupGetStringFieldW(ctypes.byref(context), 1, buffer, len(buffer), ctypes.byref(required)):
                    raise ctypes.WinError(ctypes.get_last_error())
                result["ProviderName" if key == "Provider" else key] = buffer.value
        finally:
            api.SetupCloseInfFile(handle)
    except (OSError, AttributeError) as exc:
        result["Error"] = f"{type(exc).__name__}: {exc}"
    return result


def _cancelled(cancel=None):
    return cancel is not None and cancel.is_set()


def normalize_binary_path(value: str) -> str:
    """Resolve common service ImagePath forms without executing or guessing NT devices."""
    value = str(value or "").strip()
    if not value:
        return ""
    if value.startswith('"'):
        value = value.split('"', 2)[1]
    else:
        match = re.match(r"^(.*?\.(?:exe|sys|dll))(?=\s|$)", value, re.I)
        value = match.group(1) if match else value
    value = re.sub(r"^\\(?:\?\?\\|\\\?\\)", "", value)
    windows = os.environ.get("SystemRoot", r"C:\Windows")
    value = re.sub(r"^\\SystemRoot(?=\\)", lambda _: windows, value, flags=re.I)
    value = re.sub(r"%([^%]+)%", lambda m: os.environ.get(m[1], m[0]), value)
    if re.match(r"^system32\\", value, re.I):
        value = ntpath.join(windows, value)
    return ntpath.normpath(value)


def parse_driverquery_csv(raw: str) -> list[dict[str, Any]]:
    """driverquery /v /fo csv /nh positional schema; localized headings are unnecessary."""
    records = []
    for row in csv.reader(io.StringIO(raw)):
        if not row or not any(row):
            continue
        if len(row) < 6:
            raise ValueError(msg("driverquery CSV 欄位不足：{count}（應至少 6）", count=len(row)))
        records.append({"Name": row[0], "DisplayName": row[1], "Description": row[2],
                        "ServiceType": row[3], "StartMode": row[4], "State": row[5],
                        "PathName": row[13] if len(row) > 13 else "", "raw_columns": row})
    return records


def _registry_values(root, path, names, view=0):
    values = {}
    with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
        for name in names:
            try:
                values[name] = winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                values[name] = None
    return values


def registry_services_inventory(cancel=None):
    items, errors = [], []
    if winreg is None:
        return items, [tr('Services 登錄查詢僅支援 Windows')]
    basepath = r"SYSTEM\CurrentControlSet\Services"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, basepath, 0, winreg.KEY_READ) as base:
            for index in range(winreg.QueryInfoKey(base)[0]):
                if _cancelled(cancel):
                    errors.append(tr('Services 登錄查詢已取消'))
                    break
                name = winreg.EnumKey(base, index)
                try:
                    v = _registry_values(winreg.HKEY_LOCAL_MACHINE, basepath + "\\" + name,
                                         ("DisplayName", "ImagePath", "Start", "Type"))
                    items.append({"Name": name, "DisplayName": v["DisplayName"],
                                  "PathName": v["ImagePath"], "RegistryStart": v["Start"],
                                  "RegistryType": v["Type"]})
                except OSError as exc:
                    errors.append(f"Services\\{name}：{type(exc).__name__}: {exc}")
    except OSError as exc:
        errors.append(f"Services：{type(exc).__name__}: {exc}")
    return items, errors


def registry_service_hits():
    return [x for x in registry_services_inventory()[0] if SECURITY_VENDOR_RE.search(str(x))]


def installed_apps_inventory(cancel=None):
    items, errors = [], []
    if winreg is None:
        return items, [tr('應用程式登錄查詢僅支援 Windows')]
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    for root, scope in ((winreg.HKEY_CURRENT_USER, "user"), (winreg.HKEY_LOCAL_MACHINE, "machine")):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as base:
                    for index in range(winreg.QueryInfoKey(base)[0]):
                        if _cancelled(cancel):
                            errors.append(tr('應用程式清單查詢已取消'))
                            return items, errors
                        name = winreg.EnumKey(base, index)
                        try:
                            v = _registry_values(root, path + "\\" + name,
                                ("DisplayName", "Publisher", "InstallLocation", "UninstallString",
                                 "QuietUninstallString", "DisplayVersion"), view)
                            if v.get("DisplayName"):
                                items.append(dict(v, Scope=scope, RegistryView=view, RegistryKey=name))
                        except OSError as exc:
                            errors.append(f"Uninstall\\{name}：{type(exc).__name__}: {exc}")
            except FileNotFoundError:
                pass  # An absent optional uninstall key is a successful empty scope.
            except OSError as exc:
                errors.append(tr(msg("{scope} 應用程式清單（{view}）：{detail}", scope=scope, view=view, detail=f"{type(exc).__name__}: {exc}")))
    seen = set()
    unique = []
    for item in items:
        ident = (item["DisplayName"], item.get("DisplayVersion"), item.get("InstallLocation"))
        if ident not in seen:
            seen.add(ident)
            unique.append(item)
    return unique, errors


def installed_apps_matches():
    return [x["DisplayName"] for x in installed_apps_inventory()[0]
            if SECURITY_VENDOR_RE.search(_application_identity(x))]


def _application_identity(app):
    """Uninstall commands are evidence to display, never product identity tokens."""
    return " ".join(str(app.get(key) or "") for key in ("DisplayName", "Publisher", "InstallLocation"))


def inspect_security_files(paths, cancel=None):
    unique = {}
    for path in paths:
        if path:
            unique.setdefault(str(path).lower(), str(path))
    paths = list(unique.values())
    if _cancelled(cancel):
        return [], [tr('檔案簽章查詢已取消')]
    unresolved = [{"Path": p, "Exists": None,
                   "Error": tr('非本機磁碟絕對路徑，未猜測 NT 裝置映射、UNC 或 URI 檔案位置')}
                  for p in paths if not re.match(r"^[A-Za-z]:\\", p)]
    paths = [p for p in paths if re.match(r"^[A-Za-z]:\\", p)]
    # Each -EncodedCommand is UTF-16LE then Base64-encoded. Keep a conservative
    # command-line budget (including powershell.exe options), even for very long
    # paths. Parse results by path and surface partial/incomplete inventories.
    script_template = r"""
$signatureImportError = $null
try {
  Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
} catch { $signatureImportError = $_.Exception.Message }
$paths = ConvertFrom-Json '%s'
$rows = @(foreach ($path in $paths) {
  $row = [ordered]@{ Path=$path; Exists=$null; SignatureStatus=$null; Publisher=$null;
    CompanyName=$null; ProductName=$null; FileDescription=$null; Error=$null }
  try {
    $row.Exists = Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop
    if ($row.Exists) {
      $f = Get-Item -LiteralPath $path -ErrorAction Stop
      $row.CompanyName = $f.VersionInfo.CompanyName
      $row.ProductName = $f.VersionInfo.ProductName
      $row.FileDescription = $f.VersionInfo.FileDescription
      try {
        if ($signatureImportError) { throw $signatureImportError }
        $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        $row.SignatureStatus = [string]$sig.Status
        if ($sig.SignerCertificate) { $row.Publisher = $sig.SignerCertificate.Subject }
      } catch { $row.Error = 'Signature: ' + $_.Exception.Message }
    }
  } catch { $row.Error = $_.Exception.Message }
  [pscustomobject]$row
})
ConvertTo-Json -InputObject $rows -Depth 5 -Compress
"""
    def script_for(batch):
        # Paths are data inside a quoted literal, never evaluated as expressions.
        encoded_paths = json.dumps(batch, ensure_ascii=True).replace("'", "''")
        return script_template % encoded_paths

    def encoded_length(script):
        return len(base64.b64encode(script.encode('utf-16le')))

    batches, batch = [], []
    for path in paths:
        candidate = batch + [path]
        if batch and (len(candidate) > 25 or encoded_length(script_for(candidate)) > 20000):
            batches.append(batch)
            batch = [path]
        else:
            batch = candidate
    if batch:
        batches.append(batch)
    rows, errors = list(unresolved), []
    for batch in batches:
        if _cancelled(cancel):
            errors.append(tr('檔案簽章查詢已取消'))
            break
        script = script_for(batch)
        if encoded_length(script) > 20000:
            errors.append(f'Signature batch too long for EncodedCommand: {batch[0][:80]}')
            rows.extend({'Path': p, 'Exists': None, 'Error': 'Path exceeds safe command budget'} for p in batch)
            continue
        result, err = ps_json(script, timeout=35)
        rows.extend(result)
        observed = {str(item.get('Path') or '').casefold() for item in result}
        for missing in batch:
            if missing.casefold() not in observed:
                rows.append({'Path': missing, 'Exists': None, 'Error': 'Signature query returned no row for path'})
        if err:
            errors.append(f'Signature query batch: {err}')
    errors.extend(f"{x.get('Path')}：{x['Error']}" for x in rows if x.get('Error'))
    return rows, errors


def _product_group(text, component=False):
    text = str(text).lower()
    # OEM/shared metadata is not proof that the SDK vendor application is installed.
    if component and 'surfshark' not in text and re.search(r'bdnet|bdsentry|endpointprotection|endpoint protection', text):
        return 'SharedEndpoint'
    # Installed application identities remain separate from shared components.
    for group, pattern in (("Surfshark", r"surfshark"), ("Avira", r"avira"),
        ("GeeVPN", r"geevpn|闪连|閃連"), ("ProtonVPN", r"proton"),
        ("OpenVPN", r"openvpn"), ("WireGuard", r"wireguard"),
        ("Clash", r"flclash|clash"), ("Sangfor", r"sangfor|深信服"),
        ("Ruijie", r"ruijie|锐捷|銳捷"), ("VirtualBox", r"virtualbox"),
        ("Docker", r"docker"), ("Npcap", r"npcap")):
        if re.search(pattern, text):
            return group
    if re.search(r"bdnet|bdsentry|endpointprotection|endpoint protection", text):
        return "SharedEndpoint"
    if "wintun" in text:
        return "SharedWintun"
    return "Unknown"


def classify_security(sec):
    """Correlate inventories. Missing installation registration is suspicion, not malware proof."""
    complete = sec.get("completeness", {})
    apps = sec.get("installed_apps", [])
    app_complete = complete.get("installed_apps", False)
    services = sec.get("service_registry", [])
    service_complete = complete.get("service_registry", False)
    drivers = sec.get("drivers_wmi", []) + sec.get("driverquery", [])
    running_services = sec.get("services_wmi", [])
    files = {str(x.get("Path", "")).lower(): x for x in sec.get("files", [])}
    app_groups = {_product_group(_application_identity(x)) for x in apps}
    service_names = {str(x.get("Name", "")).lower() for x in services}
    runtime = {str(x.get("Name", "")).lower(): x for x in running_services + drivers}
    records = []
    candidates = services + drivers + running_services
    seen = set()
    for item in candidates:
        if not SECURITY_VENDOR_RE.search(str(item)):
            continue
        name = str(item.get("Name", ""))
        ident = name.lower()
        if ident in seen:
            continue
        seen.add(ident)
        peers = [x for x in candidates if str(x.get("Name", "")).lower() == ident]
        image = next((normalize_binary_path(x.get("PathName", "")) for x in peers if x.get("PathName")), "")
        metadata = files.get(image.lower(), {})
        group = _product_group(" ".join(str(x) for x in peers) + " " + str(metadata), component=True)
        owner_apps = [x for x in apps if _product_group(_application_identity(x)) == group] if group not in ("Unknown", "SharedEndpoint", "SharedWintun") else []
        # A matching installed location is stronger than a generic driver keyword.
        for app in apps:
            location = str(app.get("InstallLocation") or "").rstrip("\\/")
            if location and image.lower().startswith(location.lower() + "\\") and app not in owner_apps:
                owner_apps.append(app)
        state = str(runtime.get(ident, {}).get("State", item.get("State", "")))
        running = state.lower() in ("running", "运行中", "正在运行", "執行中")
        reasons = []
        severity, confidence, status = "資訊", "中", "component_present"
        if owner_apps:
            status = "owner_installed"
            reasons.append("可關聯仍在安裝清單中的軟體；合法性與故障需另行驗證")
        elif not app_complete:
            status = "inventory_incomplete"
            reasons.append("應用程式清單不完整，不能判定主程式是否缺失")
        elif group in ("SharedEndpoint", "SharedWintun", "Unknown"):
            status, severity = "owner_unknown", "可疑"
            reasons.append("元件可能由多種軟體共用，無法僅憑名稱確定產品歸屬")
        else:
            status, severity = "orphan_candidate", "高優先級" if running else "可疑"
            reasons.append(msg('完整卸載登錄清單未見 {group}；仍可能是可攜版、企業部署或未登錄 SDK', group=group))
        alias_registration = bool(image) and any(
            normalize_binary_path(x.get("PathName", "")).lower() == image.lower() for x in services)
        if ident not in service_names and not alias_registration and service_complete:
            reasons.append("驅動／執行期枚舉仍可見，但 Services 登錄清單未見同名項")
            if not owner_apps:
                status, severity, confidence = "registration_missing", "高優先級" if running else "可疑", "高"
        if metadata.get("Exists") is False:
            reasons.append("映像檔已不存在；登錄或載入狀態需重開機後複核")
            if not owner_apps and app_complete:
                severity = "高優先級" if running else "可疑"
        elif metadata.get("Exists") is None:
            reasons.append("映像檔存在狀態尚未取得；不可視為檔案缺失")
        if running:
            reasons.append("目前枚舉狀態為 Running")
        records.append({"Name": name, "Group": group, "Status": status,
            "Severity": severity, "Confidence": confidence, "Running": running,
            "Path": image, "File": metadata, "OwnerApps": [x.get("DisplayName") for x in owner_apps],
            "Reasons": reasons, "Sources": peers})
    for product in sec.get("antivirus_products", []):
        group = _product_group(product.get("displayName", ""))
        if group in ("Unknown", "SharedEndpoint", "SharedWintun"):
            continue
        matched = group in app_groups
        image = normalize_binary_path(product.get("pathToSignedProductExe", ""))
        metadata = files.get(image.lower(), {})
        orphan = app_complete and not matched
        records.append({"Name": product.get("displayName"), "Group": group,
            "Status": "orphan_security_provider" if orphan else "provider_registered",
            "Severity": "高優先級" if orphan and metadata.get("Exists") is False else "可疑" if orphan else "資訊",
            "Confidence": "高" if orphan and metadata.get("Exists") is False else "中",
            "Path": image, "File": metadata, "Running": False,
            "Reasons": ["安全中心仍登記此產品；登記不代表目前能正常防護",
                "主程式未見於完整卸載登錄清單，需原廠工具確認" if orphan else
                "主程式在安裝清單中，或清單不完整；不能判定孤兒項"], "Sources": [product]})
    for filepath in sec.get("files", []):
        if filepath.get("Exists") is not True:
            continue
        image = str(filepath.get("Path", ""))
        if not SECURITY_VENDOR_RE.search(image):
            continue
        if any(normalize_binary_path(x.get("PathName", "")).lower() == image.lower() for x in candidates):
            continue
        records.append({"Name": ntpath.basename(image), "Group": _product_group(image + str(filepath), component=True),
            "Status": "file_without_service" if service_complete else "inventory_incomplete",
            "Severity": "可疑" if service_complete else "資訊", "Confidence": "中",
            "Path": image, "File": filepath, "Running": False, "Sources": [],
            "Reasons": ["檔案存在，未找到映像路徑相符的服務；可能為備份、待載入或殘留檔案，不代表正在攔截網路"]})
    return records


def collect_security(cancel=None):
    errors, complete = [], {}
    result = {}
    queries = (
        ("antivirus_products", "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Select-Object displayName,pathToSignedProductExe,pathToSignedReportingExe,productState", 15),
        ("drivers_wmi", "Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop | Select-Object Name,DisplayName,State,Started,StartMode,ServiceType,PathName", 20),
        ("services_wmi", "Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Select-Object Name,DisplayName,State,Started,StartMode,ServiceType,PathName,ProcessId", 20),
    )
    for key, script, timeout in queries:
        if _cancelled(cancel):
            result[key], err = [], tr('查詢已取消')
        else:
            result[key], err = ps_json("ConvertTo-Json -InputObject @(" + script + ") -Depth 5 -Compress", timeout)
        complete[key] = not bool(err)
        if err:
            errors.append(f"{key}：{err}")
    result["service_registry"], err = registry_services_inventory(cancel)
    complete["service_registry"] = not bool(err)
    errors.extend(err)
    result["installed_apps"], err = installed_apps_inventory(cancel)
    complete["installed_apps"] = not bool(err)
    errors.extend(err)
    result["installed_matches"] = [x["DisplayName"] for x in result["installed_apps"] if SECURITY_VENDOR_RE.search(_application_identity(x))]
    drv = run_command(["driverquery.exe", "/v", "/fo", "csv", "/nh"], timeout=20) if not _cancelled(cancel) else {"ok": False, "stderr": tr('已取消'), "stdout": ""}
    result["driverquery"] = []
    complete["driverquery"] = bool(drv.get("ok"))
    if drv.get("ok"):
        try:
            result["driverquery"] = parse_driverquery_csv(drv["stdout"])
        except (ValueError, csv.Error) as exc:
            errors.append('driverquery CSV: ' + tr(exc))
            complete["driverquery"] = False
    else:
        errors.append('driverquery: ' + (drv.get('stderr') or drv.get('stdout') or tr('查詢失敗')))
    result["driverquery_hits"] = [x for x in result["driverquery"] if SECURITY_VENDOR_RE.search(str(x))]
    result["driverquery_command"] = {k: v for k, v in drv.items() if k not in ("stdout",)}
    paths = [ENDPOINT_SDK_PATH]
    windows = os.environ.get("SystemRoot", r"C:\Windows")
    paths.extend(ntpath.join(windows, "System32", "drivers", name) for name in ("BdNet.sys", "BdSentry.sys"))
    for item in result["drivers_wmi"] + result["services_wmi"] + result["service_registry"] + result["driverquery"]:
        if SECURITY_VENDOR_RE.search(str(item)):
            paths.append(normalize_binary_path(item.get("PathName", "")))
    paths.extend(normalize_binary_path(x.get("pathToSignedProductExe", "")) for x in result["antivirus_products"]
                 if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", str(x.get("pathToSignedProductExe", ""))))
    paths = list(dict.fromkeys(paths))
    if len(paths) > 100:
        errors.append(tr(msg("檔案簽章查詢限制為 100 項，另有 {count} 項未查", count=len(paths)-100)))
    result["files"], err = inspect_security_files(paths[:100], cancel)
    complete["files"] = not bool(err) and len(paths) <= 100
    errors.extend(err)
    result["errors"], result["completeness"] = errors, complete
    result["evidence"] = classify_security(result)
    endpoint = next((x for x in result["files"] if str(x.get("Path", "")).lower() == ENDPOINT_SDK_PATH.lower()), {})
    trusted = (endpoint.get("Exists") is True and endpoint.get("SignatureStatus") == "Valid"
               and re.search(r"surfshark|avira", str(endpoint.get("Publisher", "")), re.I) is not None)
    result["advanced_candidates"] = [{"command": '& "' + ENDPOINT_SDK_PATH + '" uninstallSdk',
        "file_identity_verified": trusted, "applicable": False,
        "reason": "歷史候選。即使簽章有效，也未證實這個版本支援 uninstallSdk；需原廠文件／支援確認、檢查目前防毒提供者及備份，再由專家人工執行並保存實際退出碼。",
        "execution": "本工具不執行此命令，非零退出碼不可視為清理成功。"}] if endpoint.get("Exists") else []
    return result


def security_findings(sec):
    findings = []
    evidence = sec.get("evidence")
    if evidence is None:
        evidence = classify_security(sec)
    for item in evidence:
        status = item.get("Status", "component_present")
        titles = {"owner_installed": "已關聯安裝中軟體的第三方元件", "orphan_candidate": "疑似孤兒安全／VPN 元件",
            "registration_missing": "驅動仍枚舉到，但服務登錄未找到", "owner_unknown": "共用元件歸屬待核實",
            "orphan_security_provider": "疑似孤兒安全中心提供者", "file_without_service": "發現未關聯服務的元件檔案",
            "inventory_incomplete": "清單不完整，元件歸屬無法判定", "provider_registered": "安全中心已登記的產品"}
        detail = json.dumps(item, ensure_ascii=False, default=str)
        commands = []
        if item.get("Path"):
            escaped = str(item["Path"]).replace("'", "''")
            commands.append("Get-AuthenticodeSignature -LiteralPath '" + escaped + "'")
        reasons = item.get('Reasons', [])
        # Keep each authored reason independently translatable and preserve any
        # raw product/group parameter attached to a Message across exports.
        reason_message = msg('; '.join('{reason_' + str(index) + '}' for index in range(len(reasons))),
                             **{'reason_' + str(index): reason if isinstance(reason, Message) else msg(reason)
                                for index, reason in enumerate(reasons)})
        interpretation = msg('{reasons}{guidance}', reasons=reason_message,
            guidance=msg('。優先核對簽章、產品、目前防毒提供者並使用原廠移除流程。名稱命中不代表惡意或故障。'))
        findings.append(Finding(item.get("Severity", "資訊"), "安全/驅動",
            msg(titles.get(status, "第三方安全／網路元件") + "：{name}", name=str(item.get("Name", ""))),
            detail, interpretation,
            commands=commands, rollback="僅稽核。未刪除服務、驅動檔或 WMI 項目。",
            confidence=item.get("Confidence", "中")))
    for err in sec.get("errors", []):
        findings.append(Finding("資訊", "安全/驅動", "部分安全檢查未完成", str(err),
            "查詢失敗不等於元件不存在。可在確認後以管理員權限重新稽核。", confidence="低"))
    for candidate in sec.get("advanced_candidates", []):
        findings.append(Finding("資訊", "安全/驅動", "Endpoint SDK 歷史人工審閱候選",
            json.dumps(candidate, ensure_ascii=False), candidate["reason"], confidence="低"))
    return findings


def summarize_wfp_xml(path, cancel=None):
    """Streaming parser; bounded metadata and no retained XML subtrees."""
    counts = {"providers": 0, "filters": 0, "callouts": 0}
    matches, samples, stack, active = [], [], [], []
    size = Path(path).stat().st_size
    if size > 128 * 1024 * 1024:
        raise ValueError('WFP XML exceeds the 128 MiB read budget')
    ownership_records, ownership_truncated = [], False
    # Reject DTDs in any encoding/position before building the summary. Expat
    # sees the declaration itself, including after long comments or UTF-16.
    from xml.parsers import expat
    guard = expat.ParserCreate()
    def reject_doctype(*args):
        raise ValueError('WFP XML DTD is not accepted')
    guard.StartDoctypeDeclHandler = reject_doctype
    with Path(path).open('rb') as stream:
        try:
            while True:
                if _cancelled(cancel):
                    return {'counts': counts, 'matches': matches, 'samples': samples, 'bytes': size,
                            'cancelled': True, 'ownership_records': [], 'ownership_truncated': True}
                chunk = stream.read(65536)
                guard.Parse(chunk, not chunk)
                if not chunk: break
        except expat.ExpatError as exc:
            raise ET.ParseError(str(exc)) from exc
    for event, elem in ET.iterparse(path, events=("start", "end")):
        if _cancelled(cancel):
            return {"counts": counts, "matches": matches, "samples": samples, "bytes": size, "cancelled": True,
                    'ownership_records': ownership_records, 'ownership_truncated': True}
        tag = str(elem.tag).split("}")[-1].lower()
        if event == "start":
            parent = stack[-1][0] if stack else ""
            stack.append((tag, elem))
            if parent in counts and tag in ("item", "provider", "filter", "callout"):
                active.append({"depth": len(stack), "kind": parent, "parts": [], "length": 0, 'fields': {}})
        else:
            if active and elem.text:
                record = active[-1]
                direct = len(stack) == record['depth'] + 1
                action_key = tag == 'calloutkey' and len(stack) == record['depth'] + 2 and stack[-2][0] == 'action'
                if (direct and tag in ('providerkey', 'calloutkey', 'filterkey', 'servicename')) or action_key:
                    record['fields'].setdefault(tag, []).append(elem.text.strip()[:512])
            if active and elem.text and active[-1]["length"] < 8192:
                chunk = elem.text.strip()[:1024]
                if chunk:
                    active[-1]["parts"].append(tag + "=" + chunk)
                    active[-1]["length"] += len(chunk)
            if active and active[-1]["depth"] == len(stack):
                record = active.pop()
                counts[record["kind"]] += 1
                text = " | ".join(record["parts"])
                row = {"kind": record["kind"], "detail": text}
                fields = {key: values[0] for key, values in record['fields'].items() if len(set(values)) == 1}
                def wfp_guid(value):
                    try:
                        return str(uuid.UUID(value.strip('{}')))
                    except (ValueError, AttributeError):
                        return ''
                key_name = {'providers': 'providerkey', 'callouts': 'calloutkey', 'filters': 'filterkey'}[record['kind']]
                key = wfp_guid(fields.get(key_name, ''))
                if key:
                    if len(ownership_records) < 2048:
                        ownership_records.append({'kind': record['kind'], 'object_key': key,
                            'provider_key': wfp_guid(fields.get('providerkey', '')),
                            'callout_key': wfp_guid(fields.get('calloutkey', '')),
                            'service_name': fields.get('servicename', '') if record['kind'] == 'providers' else ''})
                    else:
                        ownership_truncated = True
                if len(samples) < 12:
                    samples.append(row)
                if SECURITY_VENDOR_RE.search(text) and len(matches) < 100:
                    matches.append(row)
            stack.pop()
            elem.clear()
            if stack:
                try:
                    stack[-1][1].remove(elem)
                except ValueError:
                    pass
    return {"counts": counts, "matches": matches, "samples": samples, "bytes": size,
            'ownership_records': ownership_records, 'ownership_truncated': ownership_truncated,
            "cancelled": False, "note": tr('最多保留 100 個廠商關鍵字比對項。名稱命中不等於故障；原始 XML 可能包含完整本機網路資訊。')}


def export_wfp(path, cancel=None, overwrite=False):
    import tempfile
    path = Path(path).absolute()
    if path.exists() and not overwrite:
        raise FileExistsError(tr('WFP 匯出目的地已存在，請選擇新檔案。'))
    path.parent.mkdir(parents=True, exist_ok=True)
    if _cancelled(cancel):
        return {'ok': False, 'error': tr('已取消')}
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', suffix='.xml', dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary)
    try:
        res = run_command(["netsh.exe", "wfp", "show", "state", "file=" + str(temporary)], timeout=40)
        output = {"path": str(path), "command": res, "ok": bool(res.get("ok")) and temporary.is_file()}
        if output["ok"]:
            try:
                output["summary"] = summarize_wfp_xml(temporary, cancel)
                if output["summary"].get('cancelled') or _cancelled(cancel):
                    output.update(ok=False, error=tr('已取消'))
                else:
                    publish_file(temporary, path, overwrite=overwrite)
            except (OSError, ET.ParseError) as exc:
                output.update(ok=False, error=tr(msg("XML 摘要失敗，目的檔未變更：{detail}", detail=str(exc))))
        else:
            output['error'] = res.get('stderr') or res.get('stdout') or tr('WFP 匯出未產生檔案；可能需要管理員權限')
        return output
    finally:
        temporary.unlink(missing_ok=True)
