"""PC026 11 private Windows directory allocation, without namespace authority.

Parent private ACLs exclude untrusted namespace writers; retained no-delete
ancestor handles pin their names across CreateDirectoryW and immediate no-follow
binding. Trusted-principal malicious replacement is outside the inherited model.
Every observed drift refuses; native race/ABI qualification remains separate.
The allocator and any 09 publisher own independent handles. Keep this allocator
alive through publisher close and recheck the lease before and after handoff.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import hashlib
import re
import struct
import threading

from tests import p05_pc026_windows_reader as reader


class AllocationError(RuntimeError):
    def __init__(self, code, *, phase='NOT_ATTEMPTED', name=None, winerror=None):
        super().__init__(code)
        self.code, self.phase, self.name, self.winerror = code, phase, name, winerror


@dataclass(frozen=True, slots=True, eq=False)
class DirectoryLease:
    path: object
    _identity: tuple

    @property
    def identity(self):
        """Detached diagnostic identity, never an approval or a parent grant."""
        return dict(self._identity)


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32), ('descriptor', ctypes.c_void_p),
                ('inherit_handle', ctypes.c_int32)]


def _private_sddl(sid):
    sid = reader.acl._canonical_sid(sid)
    trusted = tuple(dict.fromkeys(('S-1-5-18', 'S-1-5-32-544', sid)))
    # Actual user can own its new directory without assigning another owner.
    # Protected DACL, inheritable private rights for future publisher files.
    return 'O:' + sid + 'D:P' + ''.join('(A;OICI;FA;;;' + s + ')' for s in trusted)


class _DirectoryAPI:
    """Private native adapter: explicit SD buffer lives until CreateDirectoryW ends."""
    def __init__(self):
        self.advapi, self.kernel = reader.acl._native_apis()
        self.convert = self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
        self.convert.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32,
                                ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32)]
        self.convert.restype = ctypes.c_int32
        self.create = self.kernel.CreateDirectoryW
        self.create.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(_SecurityAttributes)]
        self.create.restype = ctypes.c_int32
        self.free = self.kernel.LocalFree
        self.free.argtypes = [ctypes.c_void_p]
        self.free.restype = ctypes.c_void_p

    def create_private(self, path, sid):
        descriptor, size = ctypes.c_void_p(), ctypes.c_uint32()
        phase, primary = 'NOT_ATTEMPTED', None
        try:
            if not self.convert(_private_sddl(sid), 1, ctypes.byref(descriptor), ctypes.byref(size)):
                raise AllocationError('security_descriptor_conversion_failed', winerror=ctypes.get_last_error())
            if not descriptor.value or not 20 <= size.value <= (1 << 20):
                raise AllocationError('security_descriptor_conversion_invalid')
            attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, 0)
            phase = 'UNKNOWN'  # Exception from native invocation cannot establish outcome.
            if not self.create(str(path), ctypes.byref(attributes)):
                phase = 'CREATE_FAILED'
                raise AllocationError('directory_create_failed', phase=phase,
                                      winerror=ctypes.get_last_error())
            phase = 'CREATED_UNBOUND'
        except BaseException as exc:
            primary = exc
            if not isinstance(exc, AllocationError):
                primary = AllocationError('directory_create_unknown', phase=phase)
                raise primary from exc
            raise
        finally:
            if descriptor.value:
                # One release attempt, including failed conversion with a buffer.
                try:
                    if self.free(descriptor):
                        raise AllocationError('security_descriptor_release_failed', phase=phase)
                except BaseException as close_error:
                    if primary is None:
                        raise AllocationError('security_descriptor_release_failed', phase=phase) from close_error
                    reader._note(primary, 'security_descriptor_release_failed')


def _session():
    return reader.WindowsSession()


def _directory_api():
    return _DirectoryAPI()


def _path(value):
    try:
        path = reader.check_path(value)
    except Exception as cause:
        raise AllocationError('directory_path_invalid') from cause
    # No long-path opt-in is presumed. Plain DOS CreateDirectoryW needs the
    # conservative legacy directory limit (MAX_PATH minus twelve characters).
    if len(str(path).encode('utf-16-le')) // 2 >= 248 or len(path.parents) + 1 > 64:
        raise AllocationError('directory_path_limit')
    return path


class WindowsDirectoryAllocator:
    """Own native ancestor/child handles; directory is a low-level input only."""
    def __init__(self, directory, *, max_directories: int):
        self._lock = threading.RLock()
        self.closed = self.failed = False
        self._session = None
        self._leases = {}
        self._attempts = 0
        self.last_phase = 'NOT_ATTEMPTED'
        self.last_name = None
        try:
            if type(max_directories) is not int or max_directories <= 0:
                raise AllocationError('directory_budget_invalid')
            self.directory = _path(directory)
            self.max_directories = max_directories
        except Exception as exc:
            self.closed = True
            if isinstance(exc, AllocationError):
                raise
            raise AllocationError('directory_input_invalid') from exc
        try:
            self._session = _session()  # Actual TokenUser, Windows only; no overrides.
            self._api = _directory_api()
            self._chain = list(reversed(self.directory.parents)) + [self.directory]
            observations = [self._session._bind(p, True, 'state' if p == self.directory else 'ancestor')[1]
                            for p in self._chain]
            if len({row[0][0] for row in observations}) != 1:
                raise AllocationError('ancestor_volume_differs')
            self._volume = observations[-1][0][0]
            self.root = self._lease(self.directory, observations[-1])
        except BaseException as primary:
            self.failed = True
            try:
                self.close()
            except BaseException:
                reader._note(primary, 'allocator_acquisition_close_failed')
            raise AllocationError('directory_root_binding_failed') from primary

    def _lease(self, path, observation):
        identity, sd, _ = observation
        values = dict(platform='windows', volume_serial=f'{identity[0]:016x}',
                      file_id=identity[1].hex(), owner_sid=reader.descriptor_snapshot(sd).owner_sid,
                      principal_sid=self._session.sid, acl_sha256=hashlib.sha256(sd).hexdigest())
        lease = DirectoryLease(path, tuple(values.items()))
        self._leases[str(path)] = lease
        return lease

    def _available(self):
        if self.closed or self.failed:
            raise AllocationError('allocator_unavailable')

    def _parent(self, lease):
        if (type(lease) is not DirectoryLease
                or self._leases.get(str(lease.path)) is not lease):
            raise AllocationError('directory_parent_not_owned')
        return lease.path

    def _principal(self):
        probe = _session()  # Also rejects an effective thread impersonation token.
        primary = None
        try:
            if probe.sid != self._session.sid:
                raise AllocationError('directory_principal_changed')
        except BaseException as exc:
            primary = exc
            raise
        finally:
            try:
                probe.close()
            except BaseException:
                if primary is None:
                    raise
                reader._note(primary, 'principal_probe_close_failed')

    def _recheck(self):
        self._principal()
        for path in self._chain:
            observed = self._session._bind(path, True, 'state' if path == self.directory else 'ancestor')[1]
            if observed[0][0] != self._volume:
                raise AllocationError('ancestor_volume_differs')
        for lease in self._leases.values():
            observed = self._session._bind(lease.path, True, 'state')[1]
            if observed[0][0] != self._volume:
                raise AllocationError('directory_volume_differs')

    def recheck(self, lease):
        with self._lock:
            self._available()
            self._parent(lease)  # Pure ownership errors leave allocator usable.
            try:
                self._recheck()
            except BaseException as cause:
                self.failed = True
                raise AllocationError('directory_recheck_failed', phase=self.last_phase,
                                      name=self.last_name) from cause

    def allocate(self, parent, name):
        with self._lock:
            self._available()
            path = self._parent(parent)
            if (type(name) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}', name)
                    or re.fullmatch(r'(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])', name, re.I)):
                raise AllocationError('directory_name_invalid')
            candidate = _path(path / name)
            if self._attempts >= self.max_directories:
                raise AllocationError('directory_budget_exceeded', name=name)
            self.last_phase, self.last_name = 'NOT_ATTEMPTED', name
            try:
                self._recheck()
            except BaseException as cause:
                self.failed = True
                raise AllocationError('directory_recheck_failed', name=name) from cause
            # Reserve while holding the allocator lock; all invoked native
            # acquisitions consume the slot, including failures and unknowns.
            self._attempts += 1
            phase = 'UNKNOWN'
            try:
                self._api.create_private(candidate, self._session.sid)
                phase = 'CREATED_UNBOUND'
                observed = self._session._bind(candidate, True, 'state')[1]
                if observed[0][0] != self._volume:
                    raise AllocationError('directory_volume_differs')
                if not struct.unpack_from('<H', observed[1], 2)[0] & 0x1000:
                    raise AllocationError('created_dacl_not_protected')
                self._recheck()  # All previously owned parents remain unchanged.
                self._session._bind(candidate, True, 'state')  # Repeat path probe.
                lease = self._lease(candidate, observed)
                self.last_phase = 'BOUND'
                return lease
            except BaseException as cause:
                self.failed = True
                if isinstance(cause, AllocationError) and phase == 'UNKNOWN':
                    phase = cause.phase
                if phase == 'NOT_ATTEMPTED':
                    self._attempts -= 1  # SD preparation failed before native create.
                self.last_phase = phase
                raise AllocationError('directory_allocation_failed', phase=phase, name=name,
                                      winerror=getattr(cause, 'winerror', None)) from cause

    def diagnostics(self):
        with self._lock:
            return dict(attempts=self._attempts, directories=max(0, len(self._leases) - 1),
                        phase=self.last_phase, name=self.last_name, failed=self.failed, closed=self.closed)

    def close(self):
        with self._lock:
            if self.closed:
                return
            self.closed = True  # Never retry uncertain CloseHandle.
            if self._session is not None:
                try:
                    self._session.close()
                except BaseException as cause:
                    self.failed = True
                    raise AllocationError('allocator_close_failed', phase=self.last_phase,
                                          name=self.last_name) from cause

    def __enter__(self):
        with self._lock:
            self._available()
            return self

    def __exit__(self, kind, primary, tb):
        try:
            self.close()
        except BaseException:
            if primary is None:
                raise
            reader._note(primary, 'allocator_close_failed')
