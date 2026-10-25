"""One field-aware privacy policy for reports, snapshots and diff exports.

Stable opaque markers retain comparisons. Raw inventories are available only
through the caller's explicit full/private export option.

Opaque markers are HMAC-SHA256 pseudonyms under a random per-installation key.
An unkeyed hash of a private IPv4 address or a MAC address with a known vendor
prefix is reversible by enumeration in seconds and links every report that
contains the same value; a keyed pseudonym is neither, unless the key leaks.
"""
from __future__ import annotations
import hashlib
import hmac
import ipaddress
import json
import ntpath
import os
import platform
import re
import secrets
import threading
from pathlib import Path
from typing import Any
from winnetdiff.core.atomic import atomic_write_text
from winnetdiff.core.keyfile import publish_private_key, read_private_key


PRIVATE_FIELDS = frozenset({
    'sid', 'machine', 'device', 'username', 'computername', 'hostname',
    'token', 'api_key', 'apikey', 'access_token', 'authorization',
    'password', 'passwd', 'secret', 'ssid', 'profilename',
})
IDENTIFIER_FIELDS = frozenset({
    'interfaceguid', 'interfaceid', 'guid', 'pnpdeviceid', 'instanceid',
    'registrykey', 'macaddress', 'physicaladdress',
    'node_id', 'source_id', 'target_id', 'object_key', 'provider_key', 'callout_key', 'filter_key',
})
VERSION_FIELDS = frozenset({'version', 'displayversion', 'application_version', 'fileversion', 'productversion'})
PATH_FIELDS = frozenset({
    'path', 'pathname', 'installlocation', 'uninstallstring', 'quietuninstallstring',
    'pathtosignedproductexe', 'pathtosignedreportingexe', 'backup',
})
_OPAQUE = re.compile(r'^<(?:id|ip|mac)-[0-9a-f]+>$|^<private-value-redacted>$')
PSEUDONYM_SCHEME = 'hmac-sha256-v1'
_PSEUDONYM_LOCK = threading.Lock()
_PSEUDONYM_STATE: dict[str, Any] = {'key': None, 'source': ''}


def pseudonym_key_path() -> Path:
    """Per-user key location; the override exists so test runs never touch a profile."""
    override = os.environ.get('WINNETDIFF_PSEUDONYM_KEY_FILE')
    if override:
        return Path(override)
    return Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.config'))) / 'WinNetDiff' / 'pseudonym.key'


def _read_key(path: Path) -> bytes:
    text = (read_private_key(path) if os.name == 'nt' else path.read_text(encoding='ascii')).strip()
    if not re.fullmatch(r'[0-9a-f]{64}', text):
        raise ValueError('pseudonym key file is not 64 lowercase hex characters')
    return bytes.fromhex(text)


def _publish_install_key(path: Path, text: str) -> None:
    if os.name == 'nt':
        publish_private_key(path, text)
    else:
        atomic_write_text(path, text, overwrite=False)


def _load_install_key(path: Path) -> tuple[bytes, str]:
    """Read or atomically create the install key; never overwrite an existing file.

    An unreadable or malformed key is left untouched for the user to inspect and
    this process uses an ephemeral key. Snapshots record the key fingerprint, so
    files written under different keys refuse to compare instead of mismatching.
    """
    try:
        return _read_key(path), 'install'
    except FileNotFoundError:
        pass
    except (OSError, ValueError, UnicodeError):
        return secrets.token_bytes(32), 'ephemeral'
    key = secrets.token_bytes(32)
    try:
        # Exclusive publish: a concurrent first run cannot replace another key.
        _publish_install_key(path, key.hex() + '\n')
        return key, 'install'
    except OSError:
        # Windows can report ACCESS_DENIED/SHARING_VIOLATION, rather than
        # FILE_EXISTS, if another process is reading the winner during rename.
        # A valid protected key that appeared meanwhile is authoritative. Never
        # replace it; failed/unsafe reads still fall back to a session key.
        try:
            return _read_key(path), 'install'
        except (OSError, ValueError, UnicodeError):
            return secrets.token_bytes(32), 'ephemeral'


def set_pseudonym_key(key: bytes | None, source: str = 'explicit') -> None:
    """Install an explicit key, or None to reload lazily from the key file."""
    if key is not None and (not isinstance(key, bytes) or len(key) < 16):
        raise ValueError('pseudonym key must be at least 16 bytes')
    with _PSEUDONYM_LOCK:
        _PSEUDONYM_STATE.update(key=key, source=source if key is not None else '')


def pseudonym_key() -> bytes:
    with _PSEUDONYM_LOCK:
        if _PSEUDONYM_STATE['key'] is None:
            _PSEUDONYM_STATE['key'], _PSEUDONYM_STATE['source'] = _load_install_key(pseudonym_key_path())
        return _PSEUDONYM_STATE['key']


def pseudonym_key_source() -> str:
    pseudonym_key()
    return _PSEUDONYM_STATE['source']


def pseudonym_digest(purpose: str, data: str, length: int) -> str:
    message = ('winnetdiff/' + purpose + '/v1\0' + data).encode('utf-8', 'surrogatepass')
    return hmac.new(pseudonym_key(), message, hashlib.sha256).hexdigest()[:length]


def pseudonym_key_id() -> str:
    """Public fingerprint used only to detect files created under different keys."""
    return pseudonym_digest('key-id', '', 16)


def _opaque(value: Any, kind: str = 'id') -> Any:
    if value in (None, '') or isinstance(value, str) and _OPAQUE.fullmatch(value):
        return value
    # The kind is a display prefix only, as before: one value maps to one token.
    return '<' + kind + '-' + pseudonym_digest('opaque', str(value), 12) + '>'


# Only a small allowlist of file extensions is safe enough to retain in a
# public report. Directory names and ambiguous command paths stay concealed.
_SAFE_LEAF = re.compile(r'(?i)^[^\\/\s<>|,;"\']+\.(?:sys|exe|dll|inf|json|xml|log|py|txt|cat|ps1|cmd|bat|msi)$')


def _privacy_path(path: str, *, is_directory: bool = False) -> str:
    stripped = path.strip().strip('"')
    leaf = ntpath.basename(stripped.replace('/', '\\'))
    if not is_directory and _SAFE_LEAF.fullmatch(leaf):
        return '<local-path>/' + leaf
    return '<local-path>'


def _private_path(match: re.Match) -> str:
    return _privacy_path(match.group(0).rstrip('.,;:'))


def redact(value: str, *, mask_ips: bool = True) -> str:
    text = str(value)
    if text.lstrip().startswith(('{', '[')):
        try:
            structured = json.loads(text)
            if isinstance(structured, (dict, list)):
                return json.dumps(redacted_data(structured), ensure_ascii=False, indent=2)
        except (ValueError, RecursionError):
            pass
    # Error prefixes often precede an embedded JSON object. Keep its field
    # context too, including escaped quotes inside credentials and versions.
    decoder = json.JSONDecoder()
    fragments, end = [], 0
    for match in list(re.finditer(r'[\[{]', text))[:32]:
        if match.start() < end:
            continue
        try:
            structured, consumed = decoder.raw_decode(text[match.start():])
        except (ValueError, RecursionError):
            continue
        if isinstance(structured, (dict, list)):
            fragments.extend([redact(text[end:match.start()], mask_ips=mask_ips),
                              json.dumps(redacted_data(structured), ensure_ascii=False)])
            end = match.start() + consumed
    if fragments:
        fragments.append(redact(text[end:], mask_ips=mask_ips))
        return ''.join(fragments)
    text = re.sub(r'(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@', r'\1<credentials>@', text)
    text = re.sub(r'(?i)(?<![\w/])[^\s;=@:/]+:[^\s;@/]+@', '<credentials>@', text)
    # Cover colon, dash and route-print's six space-separated octets.
    text = re.sub(r'(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])',
                  lambda m: _opaque(m[0].replace('-', ':').lower(), 'mac'), text)
    text = re.sub(r'(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[ \t]+){5}[0-9a-f]{2}(?![0-9a-f])',
                  lambda m: _opaque(':'.join(m[0].lower().split()), 'mac'), text)
    identities = [(os.environ.get('USERNAME', ''), '<user>'),
                  (os.environ.get('COMPUTERNAME', ''), '<computer>'), (platform.node(), '<computer>')]
    for identity, marker in identities:
        if identity and len(identity) >= 2 and not identity.isdecimal():
            # User/device identifiers also occur inside directory and adapter names.
            pattern = re.escape(identity)
            if identity.isascii():
                pattern = r'(?<![A-Za-z0-9])' + pattern + r'(?![A-Za-z0-9])'
            text = re.sub(pattern, lambda m: marker, text, flags=re.I)
    text = re.sub(r'(?i)([A-Z]:[\\/]+(?:Users|Documents and Settings)[\\/]+)[^\\/\r\n"\'<>]+', r'\1<user>', text)
    # Quoted paths may contain spaces; however an unquoted path MUST stop at
    # whitespace or an argument separator. Never stitch a prior directory
    # together with a later filename merely because it has a .sys/.exe suffix.
    text = re.sub(r'(?i)"[A-Z]:[\\/][^"\r\n]*"', _private_path, text)
    text = re.sub(r'''(?i)(?<![A-Za-z0-9+.-])[A-Z]:[\\/][^\s"\'<>|,;]+''', _private_path, text)

    text = re.sub(r'\\\\[^\\\s]+\\[^\r\n"\'<>|,;]+', _private_path, text)
    # An ambiguous *unquoted* path with an internal whitespace token and a
    # backslash cannot be split safely. Mask the remainder of that apparent
    # path rather than disclosing a second directory fragment.
    text = re.sub(r'(<local-path>)(?:[ \t]+[^\s=;<>"\']+[\\/][^\s=;<>"\']+)+',
                  r'\1', text)

    if mask_ips:
        def mask(match):
            try:
                return _opaque(str(ipaddress.ip_address(match[0])), 'ip')
            except ValueError:
                return match[0]
        text = re.sub(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', mask, text)
        text = re.sub(r'(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}(?![\w:])', mask, text)
    text = re.sub(r'(https?://[^\s?#"\']+)[?#][^\s"\']*', r'\1?<query-redacted>', text)
    text = re.sub(r'(?i)(authorization\s*:\s*)(?:Bearer|Basic)\s+[^\r\n,;]+', r'\1<secret-redacted>', text)
    text = re.sub(r'''(?ix)(["']?(?:api[_-]?key|access[_-]?token|token|password|passwd|secret|authorization)["']?\s*[=:]\s*)(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s,;"'<>{}\[\]]+)''', r'\1<secret-redacted>', text)
    return text


def redacted_data(data: Any) -> Any:
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            field = str(key).lower()
            if 'base64' in field or field in PRIVATE_FIELDS:
                result[key] = '<private-value-redacted>' if value not in (None, '') else value
            elif field == 'host' and 'scheme' in data and 'port' in data:
                # Enterprise proxy DNS names are local identities too. This
                # endpoint shape is separate from ordinary target-domain rows.
                result[key] = _opaque(value)
            elif field in ('proxy', 'bypass') and 'access_type' in data and isinstance(value, str):
                result[key] = _opaque(value)
            elif field in IDENTIFIER_FIELDS:
                result[key] = _opaque(value)
            elif field in VERSION_FIELDS and isinstance(value, str):
                result[key] = redact(value, mask_ips=False)
            elif field in PATH_FIELDS and isinstance(value, str) and re.search(r'(?i)([A-Z]:[\\/]|\\\\)', value):
                candidate = value.strip().strip('"')
                candidate = re.split(r'(?i)(?<=\.exe)\s|(?<=\.sys)\s|(?<=\.dll)\s', candidate, maxsplit=1)[0].strip('"')
                # InstallLocation is a directory even if its leaf resembles
                # a filename. Other fields retain only a known, whitespace-free
                # filename; never publish a private directory leaf.
                result[key] = _privacy_path(candidate, is_directory=(field == 'installlocation'))
            else:
                result[key] = redacted_data(value)
        return result
    if isinstance(data, (list, tuple)):
        return [redacted_data(value) for value in data]
    return redact(data) if isinstance(data, str) else data
