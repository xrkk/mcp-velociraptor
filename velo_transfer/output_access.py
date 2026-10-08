"""Windows access handoff for one verified, published guest push tree.

The service persists an intent before calling this module. Native handles pin
the exact existing objects before any grant; temporary/work/config ACLs are not
changed. Content receipts describe the bytes verified before editable handoff.
"""
from __future__ import annotations

import ctypes
import os
import stat
from pathlib import Path

from .bundle import verify_tree
from .errors import TransferContentError as Error
from .manifest import _no_link, check_relative, digest_json, directory_identity, safe_chain
from .windows_platform import AclSnapshot, _evaluate, _read_security

SHARED_SIDS = ('S-1-5-32-545', 'S-1-5-11', 'S-1-5-6')  # Users, authenticated users, services
MODIFY = 0x001301BF  # Read/write/execute/delete/synchronize, no WRITE_DAC/WRITE_OWNER.


def configured_mode():
    mode = os.environ.get('VELOCIRAPTOR_TRANSFER_OUTPUT_ACCESS', 'private')
    if mode not in ('private', 'shared_modify'):
        raise Error('invalid_output_access_mode')
    return mode


def validate_output_security(snapshot, trusted):
    """Allow only this handoff's Modify grants in an otherwise private tree."""
    private = []
    for ace in snapshot.aces:
        if ace.ace_type == 1 and ace.mask & MODIFY:
            raise Error('output_acl_deny')
        if ace.ace_type == 0 and ace.sid in SHARED_SIDS and not ace.mask & ~MODIFY:
            if ace.flags & ~0x1F:
                raise Error('windows_acl_unsupported')
            continue
        private.append(ace)
    _evaluate(AclSnapshot(snapshot.owner_sid, tuple(private), snapshot.dacl_present),
              'stage', trusted)


def read_output_security(path):
    """Keep the actual ACL-query path and native refusal in worker diagnostics."""
    try:
        return _read_security(path)
    except Error as exc:
        context = {**exc.context, 'path': str(path), 'operation': 'GetNamedSecurityInfoW'}
        if isinstance(context.get('winerror'), int) and os.name == 'nt':
            native = ctypes.WinError(context['winerror'])
            context.update(os_error=str(native), errno=native.errno)
            raise Error(exc.code, **context) from native
        raise Error(exc.code, **context) from exc


class _Trustee(ctypes.Structure):
    _fields_ = [('multiple', ctypes.c_void_p), ('operation', ctypes.c_int),
                ('form', ctypes.c_int), ('kind', ctypes.c_int), ('sid', ctypes.c_void_p)]


class _Access(ctypes.Structure):
    _fields_ = [('permissions', ctypes.c_uint), ('mode', ctypes.c_int),
                ('inheritance', ctypes.c_uint), ('trustee', _Trustee)]


class _FileId(ctypes.Structure):
    _fields_ = [('volume', ctypes.c_ulonglong), ('identifier', ctypes.c_ubyte * 16)]


class _Native:
    def __init__(self):
        if os.name != 'nt':
            raise Error('windows_platform_unsupported')
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.advapi = ctypes.WinDLL('advapi32', use_last_error=True)
        self.open = self.kernel.CreateFileW
        self.open.argtypes = [ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_uint,
                              ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
        self.open.restype = ctypes.c_void_p
        self.close = self.kernel.CloseHandle
        self.close.argtypes = [ctypes.c_void_p]
        self.close.restype = ctypes.c_int
        self.free = self.kernel.LocalFree
        self.free.argtypes = [ctypes.c_void_p]
        self.free.restype = ctypes.c_void_p
        self.file_id = self.kernel.GetFileInformationByHandleEx
        self.file_id.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
        self.file_id.restype = ctypes.c_int
        self.get_sd = self.advapi.GetSecurityInfo
        self.get_sd.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint,
                               ctypes.c_void_p, ctypes.c_void_p,
                               ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                               ctypes.POINTER(ctypes.c_void_p)]
        self.get_sd.restype = ctypes.c_uint
        self.set_sd = self.advapi.SetSecurityInfo
        self.set_sd.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint,
                               ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self.set_sd.restype = ctypes.c_uint
        self.add = self.advapi.SetEntriesInAclW
        self.add.argtypes = [ctypes.c_uint, ctypes.POINTER(_Access), ctypes.c_void_p,
                            ctypes.POINTER(ctypes.c_void_p)]
        self.add.restype = ctypes.c_uint
        self.sid = self.advapi.ConvertStringSidToSidW
        self.sid.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
        self.sid.restype = ctypes.c_int

    @staticmethod
    def fail(path, operation, code):
        native = ctypes.WinError(code)
        raise Error('output_acl_failed', path=str(path), operation=operation,
                    winerror=int(code), errno=native.errno, os_error=str(native)) from native

    def pin(self, path, *, writable):
        # OPEN_REPARSE_POINT + BACKUP_SEMANTICS; no delete sharing.
        handle = self.open(str(path), 0x20000 | (0x40000 if writable else 0),
                           0x3, None, 3, 0x02200000, None)
        if handle == ctypes.c_void_p(-1).value or handle is None:
            self.fail(path, 'CreateFileW', ctypes.get_last_error())
        try:
            self.check(handle, path)
        except BaseException:
            self.close(handle)
            raise
        return handle

    def check(self, handle, path):
        actual = _FileId()
        if not self.file_id(handle, 18, ctypes.byref(actual), ctypes.sizeof(actual)):
            self.fail(path, 'GetFileInformationByHandleEx', ctypes.get_last_error())
        info = _no_link(path)
        if (actual.volume != info.st_dev or
                int.from_bytes(bytes(actual.identifier), 'little') != info.st_ino):
            raise Error('output_identity_changed', path=str(path))

    def grant(self, handle, path, directory):
        descriptor, dacl, replacement = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        sids = []
        try:
            code = self.get_sd(handle, 1, 4, None, None, ctypes.byref(dacl), None,
                               ctypes.byref(descriptor))
            if code:
                self.fail(path, 'GetSecurityInfo', code)
            if not dacl.value:
                raise Error('windows_acl_unprotected', path=str(path))
            entries = (_Access * len(SHARED_SIDS))()
            for index, text in enumerate(SHARED_SIDS):
                sid = ctypes.c_void_p()
                if not self.sid(text, ctypes.byref(sid)):
                    self.fail(path, 'ConvertStringSidToSidW', ctypes.get_last_error())
                sids.append(sid)
                entries[index] = _Access(MODIFY, 1, 3 if directory else 0,
                                         _Trustee(None, 0, 0, 5, sid.value))
            code = self.add(len(entries), entries, dacl, ctypes.byref(replacement))
            if code:
                self.fail(path, 'SetEntriesInAclW', code)
            code = self.set_sd(handle, 1, 4, None, None, replacement, None)
            if code:
                self.fail(path, 'SetSecurityInfo', code)
        finally:
            for pointer in (*sids, replacement, descriptor):
                if pointer.value:
                    self.free(pointer)


def grant_output_tree(root, manifest, budget, expected_identity, trusted):
    """Grant existing and future members; return a point-in-time ACL receipt."""
    root = Path(root)
    verify_tree(root, manifest, budget, expected_identity)
    paths = [root]
    for entry in manifest['entries']:
        paths.append(root.joinpath(*check_relative(entry['path']).split('/')))
    native = _Native()
    held = []
    members = []
    try:
        # Pin ancestors too: ordinary-user output parents may be writable. No
        # ancestor ACL is changed and no reparse/identity change is accepted.
        for path in reversed(root.parents):
            budget.check()
            safe_chain(path, path)
            held.append(native.pin(path, writable=False))
        for path in paths:
            budget.check()
            safe_chain(path, root)
            info = _no_link(path)
            directory = stat.S_ISDIR(info.st_mode)
            if not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                raise Error('output_identity_changed', path=str(path))
            handle = native.pin(path, writable=True)
            held.append(handle)
            before = read_output_security(path)
            try:
                validate_output_security(before, trusted)
            except Error as exc:
                raise Error(exc.code, **{**exc.context, 'path': str(path)}) from exc
            members.append((path, handle, directory, before))
        if directory_identity(root) != expected_identity:
            raise Error('output_identity_changed', path=str(root))
        # Explicit grants also cover protected child DACLs. Publish the root
        # grant last; all objects remain pinned throughout the handoff.
        for path, handle, directory, before in reversed(members):
            budget.check()
            native.check(handle, path)
            native.grant(handle, path, directory)
        records = []
        for path, handle, directory, before in members:
            budget.check()
            native.check(handle, path)
            after = read_output_security(path)
            try:
                validate_output_security(after, trusted)
            except Error as exc:
                raise Error(exc.code, **{**exc.context, 'path': str(path)}) from exc
            if after.owner_sid != before.owner_sid:
                raise Error('output_owner_changed', path=str(path))
            for sid in SHARED_SIDS:
                masks = 0
                for ace in after.aces:
                    if (ace.ace_type == 0 and ace.sid == sid and not ace.flags & 8 and
                            (not directory or ace.flags & 3 == 3)):
                        masks |= ace.mask
                if masks & MODIFY != MODIFY:
                    raise Error('output_acl_not_verified', path=str(path))
            if not set(before.aces).issubset(set(after.aces)):
                raise Error('output_acl_changed', path=str(path))
            records.append({'path': path.relative_to(root).as_posix(),
                            'owner': after.owner_sid,
                            'aces': [vars(ace) for ace in after.aces]})
        return {'objects': len(members), 'acl_sha256': digest_json(records)}
    finally:
        for handle in reversed(held):
            native.close(handle)
