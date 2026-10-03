"""Private Windows no-follow issuer readback. No production POSIX fallback.

All ancestor handles remain open without write/delete sharing during readback.
Actual disk handles are checked for type, reparse attributes and FileIdInfo;
path reopens must retain those identities and the file must share A's volume.
FileIdInfo failures fail closed (no PC022 directory-ABI erratum fallback).
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path


class ReadbackError(RuntimeError):
    def __init__(self, message, *, aggregated=()):
        super().__init__(message)
        self.aggregated = list(aggregated)


class _AttributeTag(ctypes.Structure):
    _fields_ = [('attributes', ctypes.c_uint32), ('tag', ctypes.c_uint32)]


class _FileId(ctypes.Structure):
    _fields_ = [('volume', ctypes.c_uint64), ('identifier', ctypes.c_ubyte * 16)]


class _WindowsIO:
    def __init__(self):
        if os.name != 'nt':
            raise ReadbackError('Windows-only no-follow readback; no POSIX fallback')
        dll = ctypes.WinDLL('kernel32', use_last_error=True)
        self.create = dll.CreateFileW
        self.create.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        self.create.restype = ctypes.c_void_p
        self.info = dll.GetFileInformationByHandleEx
        self.info.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        self.info.restype = ctypes.c_int
        self.kind = dll.GetFileType
        self.kind.argtypes = [ctypes.c_void_p]
        self.kind.restype = ctypes.c_uint32
        self.read_file = dll.ReadFile
        self.read_file.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                   ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        self.read_file.restype = ctypes.c_int
        self.close_handle = dll.CloseHandle
        self.close_handle.argtypes = [ctypes.c_void_p]
        self.close_handle.restype = ctypes.c_int

    def open(self, path, directory):
        # LIST access makes directory sharing enforce write/delete exclusion.
        # Metadata-only access does not participate in that sharing check.
        handle = self.create(str(path), 0x81 if directory else 0x80000000,
                             1, None, 3, 0x02000000 | 0x00200000, None)
        if handle is None or handle == ctypes.c_void_p(-1).value:
            raise ReadbackError(f'CreateFileW failed: {ctypes.get_last_error()}')
        return handle

    def identity(self, handle, directory):
        attributes, identity = _AttributeTag(), _FileId()
        if self.kind(handle) != 1:
            raise ReadbackError('readback object is not FILE_TYPE_DISK')
        for code, structure in ((9, attributes), (18, identity)):
            if not self.info(handle, code, ctypes.byref(structure), ctypes.sizeof(structure)):
                raise ReadbackError(f'GetFileInformationByHandleEx({code}) failed: {ctypes.get_last_error()}')
        if attributes.attributes & 0x400 or attributes.tag:
            raise ReadbackError('readback object is reparse')
        if bool(attributes.attributes & 0x10) != directory:
            raise ReadbackError('readback object type differs')
        return identity.volume, bytes(identity.identifier)

    def read(self, handle):
        buffer, count = ctypes.create_string_buffer(65536), ctypes.c_uint32()
        if not self.read_file(handle, buffer, len(buffer), ctypes.byref(count), None):
            raise ReadbackError(f'ReadFile failed: {ctypes.get_last_error()}')
        if count.value > len(buffer):
            raise ReadbackError('ReadFile count exceeds buffer')
        return buffer.raw[:count.value]

    def close(self, handle):
        if not self.close_handle(handle):
            raise ReadbackError(f'CloseHandle failed: {ctypes.get_last_error()}')


def _native():
    return _WindowsIO()


def _read_no_follow(path: Path) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute() or '..' in path.parts:
        raise ReadbackError('readback requires an absolute plain path')
    api = _native()
    handles, objects, closes = [], [], []
    primary = None
    data = b''
    try:
        # Anchor first, then walk down while retaining every verified handle.
        ancestors = list(reversed(path.parents))
        for component, directory in [(p, True) for p in ancestors] + [(path, False)]:
            handle = api.open(component, directory)
            handles.append(handle)
            identity = api.identity(handle, directory)
            objects.append((component, directory, identity))
        if objects[-1][2][0] != objects[-2][2][0]:
            raise ReadbackError('file and activation directory differ in volume')
        chunks = []
        while True:
            chunk = api.read(handles[-1])
            if not chunk:
                break
            chunks.append(chunk)
        data = b''.join(chunks)
        # Check both retained handles and fresh path-to-handle identities.
        for retained, (component, directory, identity) in zip(tuple(handles), objects):
            if api.identity(retained, directory) != identity:
                raise ReadbackError('retained handle identity changed')
            probe = api.open(component, directory)
            handles.append(probe)
            if api.identity(probe, directory) != identity:
                raise ReadbackError('readback path identity changed')
    except BaseException as exc:
        primary = exc
    finally:
        for handle in reversed(handles):
            try:
                api.close(handle)
            except Exception as exc:
                closes.append(repr(exc))
    if primary is not None:
        if closes:
            # Preserve the actual primary exception plus secondary failures.
            primary.add_note('readback close failures: ' + repr(closes))
            if isinstance(primary, ReadbackError):
                primary.aggregated.extend(closes)
        raise primary
    if closes:
        raise ReadbackError('readback close failed', aggregated=closes)
    return data
