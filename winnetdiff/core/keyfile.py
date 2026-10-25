"""Windows key files with a protected user/SYSTEM DACL from creation.

Read security information and content from the same handle. Refuse insecure
existing files instead of silently changing the permissions of a user's file.
"""
from __future__ import annotations
import ctypes
import os
import secrets
from pathlib import Path
from ctypes import wintypes
from winnetdiff.core.windows import current_token_sid


def _key_apis():
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    security = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    for name in ('ReadFile', 'WriteFile'):
        fn = getattr(kernel, name)
        fn.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                       ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        fn.restype = wintypes.BOOL
    kernel.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel.FlushFileBuffers.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    security.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    security.GetSecurityInfo.restype = wintypes.DWORD
    security.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)]
    security.GetSecurityDescriptorControl.restype = wintypes.BOOL
    security.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    security.GetAce.restype = wintypes.BOOL
    security.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    security.ConvertSidToStringSidW.restype = wintypes.BOOL
    return kernel, security


def _key_sid_text(kernel, security, sid):
    result = ctypes.c_void_p()
    if not security.ConvertSidToStringSidW(sid, ctypes.byref(result)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.wstring_at(result)
    finally:
        kernel.LocalFree(result)


def _check_key_acl(kernel, security, handle, user):
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    error = security.GetSecurityInfo(handle, 1, 0x5, ctypes.byref(owner), None,
                                    ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if error:
        raise ctypes.WinError(error)
    try:
        control, revision = wintypes.WORD(), wintypes.DWORD()
        if not security.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not dacl.value or not control.value & 0x1000 or _key_sid_text(kernel, security, owner) != user:
            raise PermissionError('Pseudonym key requires a protected user-owned DACL')
        # ACL header: revision BYTE, reserved BYTE, size WORD, ACE count WORD.
        count = ctypes.c_ushort.from_address(dacl.value + 4).value
        users = set()
        for index in range(count):
            ace = ctypes.c_void_p()
            if not security.GetAce(dacl, index, ctypes.byref(ace)):
                raise ctypes.WinError(ctypes.get_last_error())
            kind, flags = ctypes.string_at(ace, 2)
            if kind != 0 or flags != 0:  # Only explicit ACCESS_ALLOWED_ACE.
                raise PermissionError('Unexpected pseudonym key ACE')
            sid = _key_sid_text(kernel, security, ctypes.c_void_p(ace.value + 8))
            if sid not in (user, 'S-1-5-18'):
                raise PermissionError('Pseudonym key grants another principal access')
            users.add(sid)
        if user not in users:
            raise PermissionError('Pseudonym key has no user ACE')
    finally:
        kernel.LocalFree(descriptor)


def read_private_key(path: Path) -> str:
    kernel, security = _key_apis()
    # OPEN_REPARSE_POINT prevents following a substituted key symlink.
    # Permit other publishers to test an exclusive rename while this handle is
    # open. Content and ACL are still read from this handle, with writes denied.
    handle = kernel.CreateFileW(str(path), 0x80020000, 5, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        _check_key_acl(kernel, security, handle, current_token_sid())
        buffer, size = ctypes.create_string_buffer(128), wintypes.DWORD()
        if not kernel.ReadFile(handle, buffer, len(buffer), ctypes.byref(size), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if size.value >= len(buffer):
            raise ValueError('Pseudonym key file is too large')
        return buffer.raw[:size.value].decode('ascii')
    finally:
        kernel.CloseHandle(handle)


def publish_private_key(path: Path, text: str) -> None:
    kernel, security = _key_apis()
    user = current_token_sid()
    descriptor = ctypes.c_void_p()
    sddl = f'O:{user}D:P(A;;FA;;;SY)(A;;FA;;;{user})'
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    class Attributes(ctypes.Structure):
        _fields_ = [('length', wintypes.DWORD), ('descriptor', ctypes.c_void_p), ('inherit', wintypes.BOOL)]
    attributes = Attributes(ctypes.sizeof(Attributes), descriptor, False)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(16) + '.tmp')
    created = False
    try:
        handle = kernel.CreateFileW(str(temporary), 0x40020000, 0, ctypes.byref(attributes), 1, 0x80, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        created = True
        try:
            _check_key_acl(kernel, security, handle, user)
            data, size = text.encode('ascii'), wintypes.DWORD()
            if not kernel.WriteFile(handle, data, len(data), ctypes.byref(size), None) or size.value != len(data):
                raise ctypes.WinError(ctypes.get_last_error())
            if not kernel.FlushFileBuffers(handle):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            kernel.CloseHandle(handle)
        # Same-volume Windows rename is exclusive; readers see only complete keys.
        os.rename(temporary, path)
    finally:
        kernel.LocalFree(descriptor)
        if created:
            temporary.unlink(missing_ok=True)
