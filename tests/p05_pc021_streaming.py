"""Private PC021 bounded I/O. No POSIX preservation fallback.

FileBasicInfo/StandardInfo use the fixed Windows ABI (40/24 bytes):
https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_basic_info
https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_standard_info
The cleanup BOOLEAN is the one-byte FILE_DISPOSITION_INFO member:
https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_disposition_info
Only access time is excluded from change checks: reading can update it.
Ancestors are retained without delete sharing; source handles also deny
write sharing. A part's ownership comes from its CREATE_NEW handle, never
from a subsequent path probe. Cleanup uses that identity and a DELETE
handle, not a following path unlink.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
from contextlib import contextmanager
from pathlib import Path

from tests import p05_pc021_readback as rb


class StreamingError(rb.ReadbackError):
    pass


class _Basic(ctypes.Structure):
    _fields_ = [(name, ctypes.c_int64) for name in
                ('created', 'accessed', 'written', 'changed')] + [('attributes', ctypes.c_uint32)]


class _Standard(ctypes.Structure):
    _fields_ = [('allocated', ctypes.c_int64), ('size', ctypes.c_int64),
               ('links', ctypes.c_uint32), ('deleted', ctypes.c_ubyte),
               ('directory', ctypes.c_ubyte)]


class _WindowsIO(rb._WindowsIO):
    def __init__(self):
        super().__init__()
        dll = ctypes.WinDLL('kernel32', use_last_error=True)
        self.seek_file = dll.SetFilePointerEx
        self.seek_file.argtypes = [ctypes.c_void_p, ctypes.c_int64, ctypes.c_void_p, ctypes.c_uint32]
        self.seek_file.restype = ctypes.c_int32
        self.set_info = dll.SetFileInformationByHandle
        self.set_info.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_uint32]
        self.set_info.restype = ctypes.c_int32

    def metadata(self, handle):
        basic, standard = _Basic(), _Standard()
        for code, value in ((0, basic), (1, standard)):
            if not self.info(handle, code, ctypes.byref(value), ctypes.sizeof(value)):
                raise StreamingError(f'metadata({code}) failed: {ctypes.get_last_error()}')
        if standard.size < 0 or standard.deleted or standard.directory:
            raise StreamingError('metadata: source is not a live ordinary file')
        return (standard.size, basic.created, basic.written, basic.changed, basic.attributes)

    def open_parent(self, path):
        # Permit PC022 GENERIC_WRITE refreshes, but pin directory names.
        return self._open(path, 0x80, 3, 3)

    def open_published(self, path):
        # Deny content writes while permitting deletion of the owned part link.
        return self._open(path, 0x80000000, 5, 3)

    def _open(self, path, access, sharing, disposition):
        handle = self.create(str(path), access, sharing, None, disposition, 0x02200000, None)
        if handle is None or handle == ctypes.c_void_p(-1).value:
            raise StreamingError(f'CreateFileW({disposition}) failed: {ctypes.get_last_error()}')
        return handle

    def create_part(self, path):
        import msvcrt
        handle = self._open(path, 0xC0000000, 0, 1)  # CREATE_NEW, exclusive
        fd = None
        try:
            identity = self.identity(handle, False)
            fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY | os.O_NOINHERIT)
            # Ownership transfers to the CRT fd, then to the Python file.
            stream = os.fdopen(fd, 'wb', buffering=0)
            return stream, handle, identity
        except BaseException as exc:
            try:
                if fd is None:
                    self.close(handle)
                else:
                    os.close(fd)
            except Exception as close:
                exc.add_note('part acquisition close failure: ' + repr(close))
            raise

    def rewind(self, handle):
        if not self.seek_file(handle, 0, None, 0):
            raise StreamingError(f'SetFilePointerEx failed: {ctypes.get_last_error()}')

    def open_delete(self, path):
        return self._open(path, 0x10080, 7, 3)

    def delete(self, handle):
        disposition = ctypes.c_ubyte(1)  # FILE_DISPOSITION_INFO BOOLEAN
        if not self.set_info(handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
            raise StreamingError(f'owned cleanup disposition failed: {ctypes.get_last_error()}')


def _native():
    return _WindowsIO()


@contextmanager
def _owned_handles(api):
    """Close each acquisition once; secondary failures never mask primary."""
    pending = []
    primary = None
    try:
        yield pending
    except BaseException as exc:
        primary = exc
    closes = []
    for handle in reversed(pending):
        try:
            api.close(handle)
        except Exception as exc:
            closes.append(repr(exc))
    if primary is not None:
        if closes:
            primary.add_note('streaming close failures: ' + repr(closes))
        raise primary
    if closes:
        raise StreamingError('streaming close failed', aggregated=closes)


class BoundPath:
    def __init__(self, api, path, *, directory=False, writable_parent=False,
                 published=False):
        self.api, self.path = api, path
        self.directory, self.writable_parent = directory, writable_parent
        self.published = published
        self.objects = []

    def _open(self, component, directory):
        if directory and self.writable_parent:
            return self.api.open_parent(component)
        if not directory and self.published:
            return self.api.open_published(component)
        return self.api.open(component, directory)

    def __enter__(self):
        if not self.path.is_absolute() or '..' in self.path.parts:
            raise StreamingError('binding requires absolute plain path')
        self.lifetime = _owned_handles(self.api)
        self.handles = self.lifetime.__enter__()
        try:
            components = [(p, True) for p in reversed(self.path.parents)]
            components.append((self.path, self.directory))
            for component, directory in components:
                handle = self._open(component, directory)
                self.handles.append(handle)
                identity = self.api.identity(handle, directory)
                self.objects.append((component, directory, identity, handle))
            if self.objects[-1][2][0] != self.objects[-2][2][0]:
                raise StreamingError('binding volume differs from parent')
            self.handle, self.identity = self.objects[-1][3], self.objects[-1][2]
            return self
        except BaseException as exc:
            self.lifetime.__exit__(type(exc), exc, exc.__traceback__)
            raise

    def verify(self):
        for component, directory, identity, retained in self.objects:
            if self.api.identity(retained, directory) != identity:
                raise StreamingError('retained identity drift')
            with _owned_handles(self.api) as probes:
                probe = self._open(component, directory)
                probes.append(probe)
                if self.api.identity(probe, directory) != identity:
                    raise StreamingError('path binding drift')

    def __exit__(self, *args):
        return self.lifetime.__exit__(*args)


def _chunks(api, handle, limit):
    while True:
        chunk = api.read(handle)
        if not isinstance(chunk, bytes) or len(chunk) > limit:
            raise StreamingError('bounded ReadFile returned invalid chunk')
        if not chunk:
            return
        yield chunk


def _check(count, digest, size, sha):
    if count != size or digest.hexdigest() != sha:
        raise StreamingError('stream count/size/hash differs from frozen DownloadResult')


def copy_to_part(api, source, part, parent, size, sha, limit, refresh_parent):
    """Same source handle copy plus bounded byte-for-byte persisted readback."""
    with BoundPath(api, source) as original:
        before = api.metadata(original.handle)
        if before[0] != size:
            raise StreamingError('source logical size differs before copy')
        parent.verify()
        stream, handle, owned_identity = api.create_part(part)
        primary = None
        try:
            if owned_identity[0] != parent.identity[0]:
                raise StreamingError('created part volume differs from parent')
            count, digest = 0, hashlib.sha256()
            for chunk in _chunks(api, original.handle, limit):
                count += len(chunk)
                if count > size:
                    raise StreamingError('extra source read')
                if stream.write(chunk) != len(chunk):
                    raise StreamingError('short part write')
                digest.update(chunk)
            _check(count, digest, size, sha)
            if api.metadata(original.handle) != before:
                raise StreamingError('source metadata drift after copy')
            original.verify()
            stream.flush()
            os.fsync(stream.fileno())
            if api.identity(handle, False) != owned_identity or api.metadata(handle)[0] != size:
                raise StreamingError('created part handle identity/size drift')
        except BaseException as exc:
            primary = exc
        try:
            stream.close()  # sole owner of HANDLE; never CloseHandle it again
        except Exception as exc:
            if primary is None:
                primary = StreamingError('part close failed: ' + repr(exc))
            else:
                primary.add_note('part close failure: ' + repr(exc))
        if primary is not None:
            raise primary
        parent.verify()
        refresh_parent(part.parent)
        parent.verify()
        with BoundPath(api, part) as persisted:
            if persisted.identity != owned_identity:
                raise StreamingError('owned part identity changed before readback')
            part_before = api.metadata(persisted.handle)
            if part_before[0] != size:
                raise StreamingError('owned part logical size differs')
            api.rewind(original.handle)
            count, digest = 0, hashlib.sha256()
            for chunk in _chunks(api, persisted.handle, limit):
                if chunk != api.read(original.handle):
                    raise StreamingError('owned part byte-for-byte readback differs')
                count += len(chunk)
                if count > size:
                    raise StreamingError('extra part readback')
                digest.update(chunk)
            if api.read(original.handle) != b'':
                raise StreamingError('short part readback')
            _check(count, digest, size, sha)
            if api.metadata(persisted.handle) != part_before:
                raise StreamingError('part metadata drift during readback')
            persisted.verify()
        if api.metadata(original.handle) != before:
            raise StreamingError('source metadata drift after readback')
        original.verify()
    # Source/ancestor close failures above prevent publication too.
    return owned_identity


def fingerprint(path, limit, *, api=None, expected_identity=None):
    # Package graph construction/transport validation is read-only and
    # portable. Preservation always supplies its explicit Windows API here;
    # _native/create_part/refresh/publication never select a POSIX writer.
    if api is None and os.name != 'nt':
        from tests import p05_pc021_readonly as readonly
        if expected_identity is not None:
            raise StreamingError('Windows ownership identity requires an explicit native reader')
        try:
            return readonly.fingerprint(path, limit)
        except readonly.ContentReadError as exc:
            raise StreamingError(str(exc)) from exc
    api = _native() if api is None else api
    with BoundPath(api, path) as bound:
        if expected_identity is not None and bound.identity != expected_identity:
            raise StreamingError('readback identity differs from created part')
        before = api.metadata(bound.handle)
        count, digest = 0, hashlib.sha256()
        for chunk in _chunks(api, bound.handle, limit):
            count += len(chunk)
            digest.update(chunk)
        if count != before[0] or api.metadata(bound.handle) != before:
            raise StreamingError('readback size/metadata drift')
        bound.verify()
    return count, digest.hexdigest()


def cleanup_owned_part(api, part, parent, identity):
    parent.verify()
    with _owned_handles(api) as handles:
        handle = api.open_delete(part)
        handles.append(handle)
        if api.identity(handle, False) != identity:
            raise StreamingError('cleanup ownership differs from CREATE_NEW handle')
        parent.verify()
        api.delete(handle)  # delete the verified object/link, never a following path
    parent.verify()
    if part.exists() or part.is_symlink():
        raise StreamingError('owned part remains after cleanup')
