"""PC026 Windows same-handle reader; no roots, principals or platform overrides.

GetKernelObjectSecurity requests owner/group/DACL/SACL together. A scoped
SeSecurityPrivilege adjustment uses only an already assigned process privilege
and restores its previous state; no partial-descriptor fallback is permitted.
Directory handles deny delete sharing; file handles deny write/delete sharing.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path, PureWindowsPath
import re
import struct
import threading

_PRIVILEGE_LOCK = threading.RLock()

from tests.p05_pc021_streaming import _WindowsIO as ContentIO
from velo_transfer import windows_platform as acl


class NativeReadError(RuntimeError):
    pass


def _note(primary, text):
    """Best-effort cleanup diagnostics must never replace a primary error."""
    try:
        primary.add_note(text)
    except BaseException:
        pass


def check_path(value):
    raw = str(value)
    path = PureWindowsPath(raw)
    if (not re.fullmatch(r'[A-Z]:\\.*', raw) or not path.is_absolute()
            or raw.startswith('\\\\') or '/' in raw or '\0' in raw
            or len(raw) > 32767 or ':' in raw[2:]):
        raise NativeReadError('unsafe native absolute path')
    for part in raw[3:].split('\\'):
        if (not part or part in {'.', '..'} or part[-1:] in {'.', ' '}
                or '~' in part or re.fullmatch(r'(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', part, re.I)):
            raise NativeReadError('unsafe native path component')
    return path


def descriptor_snapshot(data):
    """Evaluate the DACL from the same complete self-relative raw SD bytes."""
    if not isinstance(data, bytes) or not 20 <= len(data) <= (1 << 20):
        raise NativeReadError('full security descriptor unavailable')
    rev, reserved, control, owner, group, sacl, dacl = struct.unpack_from('<BBHIIII', data)
    if rev != 1 or reserved or not control & 0x8000 or not control & 4 or not dacl:
        raise NativeReadError('invalid or unprotected self-relative descriptor')
    def sid(offset):
        if offset < 20 or offset % 4 or offset + 8 > len(data):
            raise NativeReadError('descriptor SID bounds')
        head = data[offset:offset + 8]
        end = offset + 8 + 4 * head[1]
        if head[0] != 1 or not 1 <= head[1] <= 15 or end > len(data):
            raise NativeReadError('descriptor SID bounds')
        values = struct.unpack_from('<' + 'I' * head[1], data, offset + 8)
        return acl._canonical_sid('S-1-' + str(int.from_bytes(head[2:], 'big'))
            + ''.join('-' + str(value) for value in values))
    owner_sid = sid(owner)
    if group:
        sid(group)
    aces = []
    for offset in (sacl, dacl):
        if not offset:
            continue
        if offset < 20 or offset % 4 or offset + 8 > len(data):
            raise NativeReadError('descriptor ACL bounds')
        version, _, size, count, _ = struct.unpack_from('<BBHHH', data, offset)
        if version not in (2, 4) or size < 8 or offset + size > len(data) or count > 4096:
            raise NativeReadError('descriptor ACL bounds')
        pos = offset + 8
        for _ in range(count):
            if pos + 4 > offset + size:
                raise NativeReadError('descriptor ACE bounds')
            length = struct.unpack_from('<H', data, pos + 2)[0]
            if length < 4 or length % 4 or pos + length > offset + size:
                raise NativeReadError('descriptor ACE bounds')
            if offset == dacl:
                aces.append(acl._decode_ace(data[pos:pos + length]))
            pos += length
    return acl.AclSnapshot(owner_sid, tuple(aces))


class NativeIO(ContentIO):
    def __init__(self):
        super().__init__()
        self.advapi = ctypes.WinDLL('advapi32', use_last_error=True)
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.security = self.advapi.GetKernelObjectSecurity
        self.security.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                                  ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        self.security.restype = ctypes.c_int
        self.valid = self.advapi.IsValidSecurityDescriptor
        self.valid.argtypes = [ctypes.c_void_p]; self.valid.restype = ctypes.c_int
        self.length = self.advapi.GetSecurityDescriptorLength
        self.length.argtypes = [ctypes.c_void_p]; self.length.restype = ctypes.c_uint32
        self.final_name = self.kernel.GetFinalPathNameByHandleW
        self.final_name.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
        self.final_name.restype = ctypes.c_uint32

    def open(self, path, directory):
        # FILE_LIST_DIRECTORY participates in the native sharing check; metadata-
        # only directory access does not make deny-delete sharing effective.
        # READ_CONTROL + ACCESS_SYSTEM_SECURITY; only assigned privilege is used.
        with _security_privilege(self.advapi, self.kernel):
            return self._open(path, (0x81 if directory else 0x80000000) | 0x01020000,
                              3 if directory else 1, 3)

    def descriptor(self, handle):
        size = ctypes.c_uint32()
        if self.security(handle, 0xF, None, 0, ctypes.byref(size)) or ctypes.get_last_error() != 122:
            raise NativeReadError('full security descriptor sizing failed')
        if not 20 <= size.value <= (1 << 20):
            raise NativeReadError('full security descriptor length invalid')
        buffer = ctypes.create_string_buffer(size.value)
        if not self.security(handle, 0xF, buffer, len(buffer), ctypes.byref(size)):
            raise NativeReadError('full security descriptor unavailable: ' + str(ctypes.get_last_error()))
        if not self.valid(buffer) or self.length(buffer) != size.value or size.value != len(buffer):
            raise NativeReadError('full security descriptor invalid/short')
        data = buffer.raw
        descriptor_snapshot(data)
        return data

    def name(self, handle):
        buffer = ctypes.create_unicode_buffer(32768)
        size = self.final_name(handle, buffer, len(buffer), 0)
        if not size or size >= len(buffer) or not buffer.value.startswith('\\\\?\\'):
            raise NativeReadError('final handle path unavailable')
        return buffer.value[4:]


class _Luid(ctypes.Structure):
    _fields_ = [('low', ctypes.c_uint32), ('high', ctypes.c_int32)]


class _Privileges(ctypes.Structure):
    _fields_ = [('count', ctypes.c_uint32), ('luid', _Luid), ('attributes', ctypes.c_uint32)]


class _security_privilege:
    def __init__(self, advapi, kernel):
        self.advapi, self.kernel, self.token, self.adjusted = advapi, kernel, ctypes.c_void_p(), False

    def __enter__(self):
        _PRIVILEGE_LOCK.acquire()
        a, k = self.advapi, self.kernel
        k.CloseHandle.argtypes = [ctypes.c_void_p]; k.CloseHandle.restype = ctypes.c_int
        k.GetCurrentProcess.restype = ctypes.c_void_p
        a.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
        a.OpenProcessToken.restype = ctypes.c_int
        a.LookupPrivilegeValueW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(_Luid)]
        a.LookupPrivilegeValueW.restype = ctypes.c_int
        a.AdjustTokenPrivileges.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(_Privileges),
            ctypes.c_uint32, ctypes.POINTER(_Privileges), ctypes.POINTER(ctypes.c_uint32)]
        a.AdjustTokenPrivileges.restype = ctypes.c_int
        if not a.OpenProcessToken(k.GetCurrentProcess(), 0x28, ctypes.byref(self.token)):
            _PRIVILEGE_LOCK.release()
            raise NativeReadError('security privilege token unavailable')
        try:
            change = _Privileges(); change.count = 1; change.attributes = 2
            if not a.LookupPrivilegeValueW(None, 'SeSecurityPrivilege', ctypes.byref(change.luid)):
                raise NativeReadError('security privilege unavailable')
            self.previous, needed = _Privileges(), ctypes.c_uint32()
            ctypes.set_last_error(0)
            ok = a.AdjustTokenPrivileges(self.token, False, ctypes.byref(change),
                ctypes.sizeof(self.previous), ctypes.byref(self.previous), ctypes.byref(needed))
            self.adjusted = bool(ok)
            if not ok or ctypes.get_last_error() != 0:
                raise NativeReadError('complete SD requires assigned SeSecurityPrivilege')
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, kind, exc, tb):
        try:
            if self.adjusted and not self.advapi.AdjustTokenPrivileges(self.token, False,
                    ctypes.byref(self.previous), 0, None, None):
                raise NativeReadError('security privilege restoration failed')
        finally:
            if self.token.value:
                self.kernel.CloseHandle(self.token)
                self.token = ctypes.c_void_p()
            _PRIVILEGE_LOCK.release()


class WindowsSession:
    def __init__(self):
        if os.name != 'nt':
            raise NativeReadError('native Windows reader unavailable')
        # File APIs use a thread token when impersonating; never authenticate
        # one principal while using another principal for the actual reads.
        advapi, kernel = acl._native_apis()
        kernel.GetCurrentThread.restype = ctypes.c_void_p
        advapi.OpenThreadToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
            ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
        advapi.OpenThreadToken.restype = ctypes.c_int
        thread_token = ctypes.c_void_p()
        if advapi.OpenThreadToken(kernel.GetCurrentThread(), 8, True, ctypes.byref(thread_token)):
            kernel.CloseHandle.argtypes = [ctypes.c_void_p]; kernel.CloseHandle.restype = ctypes.c_int
            kernel.CloseHandle(thread_token)
            raise NativeReadError('impersonated reader principal is unsupported')
        if ctypes.get_last_error() != 1008:
            raise NativeReadError('effective reader token unavailable')
        self.sid = acl.current_process_sid()
        self.trusted = frozenset(('S-1-5-18', 'S-1-5-32-544', self.sid))
        self.api, self.objects, self.closed = NativeIO(), {}, False
        self.lock = threading.RLock()

    def _observe(self, handle, directory):
        identity = self.api.identity(handle, directory)
        raw = self.api.descriptor(handle)
        metadata = None if directory else self.api.metadata(handle)
        return identity, raw, metadata

    def _bind(self, path, directory, kind):
        if self.closed:
            raise NativeReadError('native consumption session closed')
        key = str(path)
        if key not in self.objects:
            handle = self.api.open(path, directory)
            try:
                observed = self._observe(handle, directory)
                if self.api.name(handle) != key:
                    raise NativeReadError('native path alias differs from final handle name')
                acl._evaluate(descriptor_snapshot(observed[1]), kind, self.trusted)
            except BaseException as primary:
                try:
                    self.api.close(handle)
                except BaseException:
                    _note(primary, 'native_binding_close_failed')
                raise
            self.objects[key] = (handle, directory, observed)
        handle, actual_directory, observed = self.objects[key]
        if actual_directory != directory:
            raise NativeReadError('native object type drift')
        acl._evaluate(descriptor_snapshot(observed[1]), kind, self.trusted)
        if self._observe(handle, directory) != observed:
            raise NativeReadError('native retained identity/ACL/metadata drift')
        probe = self.api.open(path, directory)
        primary = None
        try:
            if self.api.name(probe) != key or self._observe(probe, directory) != observed:
                raise NativeReadError('native path identity/ACL/metadata drift')
        except BaseException as exc:
            primary = exc
            raise
        finally:
            try:
                self.api.close(probe)
            except BaseException:
                if primary is None:
                    raise
                _note(primary, 'native_probe_close_failed')
        return handle, observed

    def read(self, path, *, private=False):
        with self.lock:
            return self._read_bound(path, private=private)

    def _read_bound(self, path, *, private):
        stream = self._stream_bound(path, private=private)
        chunks = []
        while True:
            try: chunks.append(next(stream))
            except StopIteration as end:
                return b''.join(chunks), *end.value

    def stream(self, path):
        # Keep the same retained handles, principal and full SD gate while
        # parsing bounded chunks; no complete SSE body is accumulated here.
        with self.lock:
            return (yield from self._stream_bound(path, private=False))

    def _stream_bound(self, path, *, private):
        check_path(path)
        chain = list(reversed(path.parents)) + [path]
        if len(chain) > 64:
            raise NativeReadError('native ancestor depth limit')
        observations = []
        for item in chain:
            directory = item != path
            handle, observed = self._bind(item, directory,
                'ancestor' if directory else ('state' if private else 'policy'))
            observations.append(observed)
        if len({row[0][0] for row in observations}) != 1:
            raise NativeReadError('native volume differs across ancestor chain')
        self.api.rewind(handle)
        count = 0
        while chunk := self.api.read(handle):
            count += len(chunk)
            if count > observations[-1][2][0]:
                raise NativeReadError('native content extra read')
            yield chunk
        if count != observations[-1][2][0]:
            raise NativeReadError('native content short read')
        for item in chain:
            self._bind(item, item != path, 'ancestor' if item != path else ('state' if private else 'policy'))
        leaf = observations[-1]
        identity = {'platform':'windows', 'volume_serial':f'{leaf[0][0]:016x}',
            'file_id':leaf[0][1].hex(), 'owner_sid':descriptor_snapshot(leaf[1]).owner_sid,
            'principal_sid':self.sid, 'acl_sha256':hashlib.sha256(leaf[1]).hexdigest()}
        return tuple(observations), identity

    def close(self):
        with self.lock:
            self._close_bound()

    def _close_bound(self):
        if self.closed:
            return
        self.closed = True
        errors = []
        for handle, _, _ in reversed(tuple(self.objects.values())):
            try:
                self.api.close(handle)
            except Exception as exc:
                errors.append(str(exc))
        self.objects.clear()
        if errors:
            raise NativeReadError('native close failures: ' + repr(errors))

    def __del__(self):
        if hasattr(self, 'closed'):
            self.close()
