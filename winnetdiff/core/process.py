from __future__ import annotations
import argparse
import base64
import codecs
import csv
import ctypes
import datetime as dt
import functools
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
from winnetdiff.core.i18n import tr
from winnetdiff.core.messages import msg
if os.name == 'nt':
    import winreg
else:
    winreg = None


def _native_codepages() -> list[str]:
    pages = []
    if os.name == "nt":
        import ctypes
        for name in ("GetOEMCP", "GetACP"):
            try:
                pages.append("cp" + str(getattr(ctypes.windll.kernel32, name)()))
            except (AttributeError, OSError):
                pass
    pages.append(locale.getpreferredencoding(False))
    return list(dict.fromkeys(pages))


def decode_output(raw: bytes, hint: str | None = None) -> tuple[str, str, str]:
    """Strict decoding; never discard bytes or replace undecodable characters.

    A BOM is authoritative. PowerShell's forced UTF-8 stream is also
    authoritative. Native commands use UTF-8 then Windows OEM/ANSI pages.
    The returned error identifies a fallback or retained binary evidence.
    """
    if not raw:
        return "", "utf-8", ""
    if isinstance(raw, str):
        return raw, "already-text", ""
    bom_codec = None
    for bom, enc in ((codecs.BOM_UTF32_LE, "utf-32"),
                     (codecs.BOM_UTF32_BE, "utf-32"),
                     (codecs.BOM_UTF8, "utf-8-sig"),
                     (codecs.BOM_UTF16_LE, "utf-16"),
                     (codecs.BOM_UTF16_BE, "utf-16")):
        if raw.startswith(bom):
            bom_codec = enc
            break
    strict_hint = hint in ("utf-8", "utf8", "powershell")
    if bom_codec:
        candidates = [bom_codec]
    elif strict_hint:
        candidates = ["utf-8-sig"]
    else:
        candidates = ([hint] if hint and hint != "native" else [])
        candidates += ["utf-8"] + _native_codepages() + ["cp936", "gb18030"]
    failures = []
    for encoding in dict.fromkeys(candidates):
        try:
            decoded = raw.decode(encoding, errors="strict")
            # NUL bytes in purported console text often mean unmarked UTF-16.
            if "\x00" in decoded and encoding not in ("utf-16", "utf-32"):
                raise UnicodeError("NUL bytes in console text")
            return decoded, encoding, (tr(msg('解碼回退；{detail}', detail='; '.join(failures))) if failures else '')
        except (UnicodeError, LookupError) as exc:
            failures.append(f"{encoding}: {exc}")
    return '', 'undecodable', tr(msg('解碼失敗，原始位元組保留於 raw_base64；{detail}', detail='; '.join(failures)))


# CreateProcess searches the launching executable's directory and the current
# directory before System32 when given a bare name. A planted netsh.exe or
# powershell.exe beside a downloaded WinNetDiff.exe would otherwise run, and
# after UAC it would run elevated. Only these OS tools may be started by name;
# each resolves to an absolute path under the OS-reported system directory.
_SYSTEM_TOOLS = {
    'powershell': ('WindowsPowerShell', 'v1.0', 'powershell.exe'),
    'netsh': ('netsh.exe',), 'route': ('route.exe',), 'tasklist': ('tasklist.exe',),
    'netstat': ('netstat.exe',), 'whoami': ('whoami.exe',), 'ipconfig': ('ipconfig.exe',),
    'ping': ('ping.exe',), 'driverquery': ('driverquery.exe',),
}


def _windows_host() -> bool:
    return os.name == 'nt'


def _fully_qualified(path: str) -> bool:
    """Drive or UNC plus root; rejects bare, relative and drive-relative paths."""
    drive, rest = ntpath.splitdrive(str(path))
    return bool(drive) and rest[:1] in ('\\', '/')


@functools.lru_cache(maxsize=1)
def system_directory() -> str:
    """The OS-reported system directory; never PATH, the CWD or %SystemRoot%."""
    import ctypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    kernel.GetSystemDirectoryW.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(520)
    length = kernel.GetSystemDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise OSError(ctypes.get_last_error(), 'GetSystemDirectoryW failed')
    return buffer.value


def resolve_system_tool(name: str, system_dir: str | None = None) -> str:
    leaf = str(name)
    if not leaf or leaf in ('.', '..') or leaf != ntpath.basename(leaf):
        raise ValueError('refusing relative executable path ' + repr(name))
    key = leaf.lower()[:-4] if leaf.lower().endswith('.exe') else leaf.lower()
    parts = _SYSTEM_TOOLS.get(key)
    if parts is None:
        raise ValueError(repr(name) + ' is not an allowlisted Windows system tool')
    base = system_directory() if system_dir is None else system_dir
    if not _fully_qualified(base):
        raise OSError('system directory is not a fully qualified path')
    return ntpath.join(base, *parts)


def prepare_argv(args: list[str], system_dir: str | None = None) -> list[str]:
    """Return argv whose program is never located through a search path on Windows."""
    argv = list(args)
    if not argv:
        raise ValueError('empty command')
    if _windows_host() and not _fully_qualified(str(argv[0])):
        argv[0] = resolve_system_tool(str(argv[0]), system_dir)
    return argv


def run_command(args: list[str], timeout: float = 12,
                encoding_hint: str | None = None) -> dict[str, Any]:
    """Execute an argv vector without a shell and preserve decoding evidence."""
    kw: dict[str, Any] = {"capture_output": True, "timeout": timeout, "text": False}
    if os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    raw_out, raw_err = b"", b""
    returncode, execution_error = None, ""
    timed_out = False
    try:
        argv = prepare_argv(args)
    except (OSError, ValueError) as exc:
        # A refused or unresolvable program is an incomplete query, not evidence.
        argv, execution_error = None, f"RefusedExecutable: {exc}"
    try:
        if argv is not None:
            result = subprocess.run(argv, **kw)
            raw_out, raw_err, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as exc:
        raw_out, raw_err = exc.stdout or b"", exc.stderr or b""
        execution_error = tr(msg('TimeoutExpired: 指令超過 {timeout:g} 秒', timeout=timeout))
        timed_out = True
    except OSError as exc:
        execution_error = f"{type(exc).__name__}: {exc}"
    stdout, out_encoding, out_error = decode_output(raw_out, encoding_hint)
    stderr, err_encoding, err_error = decode_output(raw_err, encoding_hint)
    if execution_error:
        stderr = "\n".join(x for x in (stderr, execution_error) if x)
    # Exact bytes are retained even on a successful legacy-codepage fallback.
    return {"ok": returncode == 0 and out_encoding != "undecodable" and err_encoding != "undecodable",
            "returncode": returncode, "stdout": stdout.strip(), "stderr": stderr.strip(),
            "stdout_encoding": out_encoding, "stderr_encoding": err_encoding,
            "decode_errors": [x for x in (out_error, err_error) if x],
            "stdout_raw_base64": base64.b64encode(raw_out).decode("ascii"),
            "stderr_raw_base64": base64.b64encode(raw_err).decode("ascii"),
            "timed_out": timed_out}


def powershell(script: str, timeout: float = 18) -> dict[str, Any]:
    """Windows PowerShell 5.1: UTF-16LE command input, explicit UTF-8 pipes."""
    preamble = ("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
                "$WarningPreference='SilentlyContinue'; $InformationPreference='SilentlyContinue'; "
                "[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false); "
                "$OutputEncoding=[Console]::OutputEncoding; ")
    payload = preamble + "try { " + script + " } catch { [Console]::Error.WriteLine($_.ToString()); exit 1 }"
    encoded = base64.b64encode(payload.encode("utf-16-le")).decode("ascii")
    return run_command(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                        "-EncodedCommand", encoded], timeout=timeout, encoding_hint="powershell")


def ps_json(script: str, timeout: float = 18) -> tuple[list[dict[str, Any]], str]:
    res = powershell(script, timeout)
    if not res["ok"]:
        return [], res.get("stderr") or res.get("stdout") or "; ".join(res.get("decode_errors", [])) or tr('PowerShell 查詢失敗')
    try:
        # An empty stream is an incomplete query, not a proven empty result.
        obj = json.loads(res["stdout"].lstrip("\ufeff"))
        if obj is None:
            return [], ""
        items = obj if isinstance(obj, list) else [obj]
        if any(not isinstance(x, dict) for x in items):
            raise ValueError(tr('預期 JSON 物件或物件陣列'))
        return items, ""
    except (json.JSONDecodeError, ValueError) as exc:
        return [], tr(msg('PowerShell JSON 無法解析：{detail}；原始輸出：{raw}', detail=exc, raw=res['stdout'][:500]))
