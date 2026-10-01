"""PC021 direct regression. Host I/O is an explicit simulation, not fallback."""
from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import p05_pc021_package as pkg
from tests import p05_pc021_streaming as io


class HostIO:
    """Test-only ordinary filesystem handles; production never selects this."""
    def __init__(self):
        self.handles = []
        self.closed = []
        self.deleted = []
        self.read_sizes = []

    def open(self, path, directory):
        obj = (path, directory, None if directory else path.open('rb'))
        self.handles.append(obj)
        return obj

    def open_parent(self, path):
        return self.open(path, True)

    def open_published(self, path):
        return self.open(path, False)

    def identity(self, handle, directory):
        path, kind, stream = handle
        st = path.lstat() if stream is None else os.fstat(stream.fileno())
        if kind != directory or path.is_symlink():
            raise io.StreamingError('type/reparse refusal')
        return st.st_dev, st.st_ino

    def metadata(self, handle):
        st = os.fstat(handle[2].fileno())
        return st.st_size, st.st_mtime_ns, st.st_ctime_ns

    def create_part(self, path):
        stream = path.open('xb', buffering=0)
        handle = (path, False, stream)
        return stream, handle, self.identity(handle, False)

    def read(self, handle):
        value = handle[2].read(65536)
        self.read_sizes.append(len(value))
        return value

    def rewind(self, handle):
        handle[2].seek(0)

    def close(self, handle):
        self.closed.append(handle)
        if handle[2] is not None:
            handle[2].close()

    def open_delete(self, path):
        return self.open(path, False)

    def delete(self, handle):
        self.deleted.append(handle[0])
        handle[0].unlink()


class PackageStreamingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'trusted' / 'content.bin'
        self.source.parent.mkdir()
        self.parent = self.root / 'phase'
        self.parent.mkdir()
        self.part = self.parent / 'attempt.part'

    def copy(self, data, *, api=None, size=None, sha=None):
        self.source.write_bytes(data)
        api = HostIO() if api is None else api
        with io.BoundPath(api, self.parent, directory=True, writable_parent=True) as parent:
            identity = io.copy_to_part(api, self.source, self.part, parent,
                                      len(data) if size is None else size,
                                      hashlib.sha256(data).hexdigest() if sha is None else sha,
                                      pkg.CHUNK_LIMIT, lambda p: None)
        return api, identity

    def test_empty_and_multichunk_direct_copy_and_readback(self):
        for data in (b'', b'x' * 150000):
            with self.subTest(size=len(data)):
                api, identity = self.copy(data)
                self.assertEqual(self.part.read_bytes(), data)
                self.assertEqual(io.fingerprint(self.part, pkg.CHUNK_LIMIT, api=api,
                                               expected_identity=identity),
                                 (len(data), hashlib.sha256(data).hexdigest()))
                self.assertLessEqual(max(api.read_sizes), pkg.CHUNK_LIMIT)
                self.assertEqual(len(api.closed), len(api.handles))
                self.part.unlink()

    def test_metadata_only_drift_refused_with_same_bytes(self):
        outer = self
        class Drift(HostIO):
            count = 0
            def metadata(self, handle):
                value = super().metadata(handle)
                if handle[0] == outer.source:
                    self.count += 1
                    if self.count > 1:
                        return value[:-1] + (value[-1] + 1,)
                return value
        with self.assertRaisesRegex(io.StreamingError, 'metadata drift'):
            self.copy(b'identical bytes', api=Drift())
        self.assertTrue(self.part.exists())

    def test_path_binding_same_bytes_different_object_refused(self):
        outer = self
        class Drift(HostIO):
            probes = 0
            def open(self, path, directory):
                h = super().open(path, directory)
                if path == outer.source:
                    self.probes += 1
                return h
            def identity(self, handle, directory):
                ident = super().identity(handle, directory)
                if handle[0] == outer.source and self.probes > 1:
                    return ident[0], ident[1] + 1
                return ident
        with self.assertRaisesRegex(io.StreamingError, 'path binding drift'):
            self.copy(b'same bytes', api=Drift())

    def test_short_extra_hash_and_read_errors_preserve_part(self):
        for fault in ('short', 'extra', 'hash', 'read'):
            with self.subTest(fault=fault):
                class Fault(HostIO):
                    count = 0
                    def read(self, handle):
                        self.count += 1
                        if fault == 'read':
                            raise io.StreamingError('read injected')
                        if fault == 'short':
                            return b''
                        if fault == 'extra':
                            return b'extra bytes'
                        return super().read(handle)
                with self.assertRaises(io.StreamingError):
                    self.copy(b'abc', api=Fault(), sha='0' * 64 if fault == 'hash' else None)
                self.assertTrue(self.part.exists())
                self.part.unlink()

    def test_short_write_flush_fsync_and_close_fail_preserve_part(self):
        for fault in ('write', 'flush', 'fsync', 'close'):
            with self.subTest(fault=fault):
                class Fault(HostIO):
                    def create_part(self, path):
                        stream, handle, ident = super().create_part(path)
                        class Wrapper:
                            def write(self, value):
                                return len(value)-1 if fault == 'write' else stream.write(value)
                            def flush(self):
                                if fault == 'flush': raise OSError('flush injected')
                                return stream.flush()
                            def fileno(self): return stream.fileno()
                            def close(self):
                                stream.close()
                                if fault == 'close': raise OSError('close injected after native close')
                        return Wrapper(), handle, ident
                with patch.object(io.os, 'fsync', side_effect=OSError('fsync injected')) if fault == 'fsync' else patch.object(io, '_native', side_effect=AssertionError('unused')):
                    with self.assertRaises((io.StreamingError, OSError)):
                        self.copy(b'abc', api=Fault())
                self.assertTrue(self.part.exists())
                self.part.unlink()

    def test_cleanup_never_adopts_new_object_identity(self):
        api, identity = self.copy(b'abc')
        replacement = self.parent / 'replacement'
        replacement.write_bytes(b'abc')
        replacement.replace(self.part)
        with io.BoundPath(api, self.parent, directory=True, writable_parent=True) as parent:
            with self.assertRaisesRegex(io.StreamingError, 'CREATE_NEW'):
                io.cleanup_owned_part(api, self.part, parent, identity)
        self.assertEqual(api.deleted, [])
        self.assertEqual(self.part.read_bytes(), b'abc')

    def test_parent_drift_blocks_cleanup(self):
        api, identity = self.copy(b'abc')
        with io.BoundPath(api, self.parent, directory=True, writable_parent=True) as parent:
            moved = self.root / 'old-parent'
            self.parent.rename(moved)
            self.parent.mkdir()
            replacement = self.parent / 'attempt.part'
            replacement.write_bytes(b'other attempt')
            with self.assertRaises(io.StreamingError):
                io.cleanup_owned_part(api, self.part, parent, identity)
        self.assertEqual(replacement.read_bytes(), b'other attempt')
        self.assertEqual((moved / 'attempt.part').read_bytes(), b'abc')
        self.assertEqual(api.deleted, [])

    def test_close_failures_keep_primary_and_attempt_each_acquisition_once(self):
        class Fault(HostIO):
            def read(self, handle):
                self.failed = True
                raise io.StreamingError('read primary')
            def close(self, handle):
                super().close(handle)
                if getattr(self, 'failed', False):
                    raise io.StreamingError('close secondary')
        api = Fault()
        with self.assertRaisesRegex(io.StreamingError, 'read primary') as caught:
            self.copy(b'abc', api=api)
        self.assertTrue(any('close' in note for note in caught.exception.__notes__))
        self.assertEqual(len(api.closed), len(api.handles))

    def test_windows_abi_sizes_and_no_platform_fallback(self):
        self.assertEqual(ctypes.sizeof(io._Basic), 40)
        self.assertEqual(ctypes.sizeof(io._Standard), 24)
        if os.name != 'nt':
            with self.assertRaisesRegex(io.rb.ReadbackError, 'Windows-only'):
                io._native()

    def test_metadata_uses_actual_handle_basic_and_standard_info(self):
        api = object.__new__(io._WindowsIO)
        calls = []
        def info(handle, code, pointer, size):
            calls.append((handle, code, size))
            if code == 0:
                self.assertEqual(size, 40)
                value = ctypes.cast(pointer, ctypes.POINTER(io._Basic)).contents
                value.created, value.accessed = 100, 200
                value.written, value.changed, value.attributes = 300, 400, 32
            else:
                self.assertEqual((code, size), (1, 24))
                value = ctypes.cast(pointer, ctypes.POINTER(io._Standard)).contents
                value.size, value.allocated = 16777216, 4096
                value.links, value.deleted, value.directory = 1, 0, 0
            return 1
        api.info = info
        self.assertEqual(api.metadata(123), (16777216, 100, 300, 400, 32))
        self.assertEqual(calls, [(123, 0, 40), (123, 1, 24)])
        for code in (0, 1):
            api.info = lambda h, c, p, n: 0 if c == code else info(h, c, p, n)
            with patch.object(ctypes, 'get_last_error', return_value=87, create=True):
                with self.assertRaisesRegex(io.StreamingError, f'metadata\\({code}\\) failed: 87'):
                    api.metadata(123)


if __name__ == '__main__':
    unittest.main()
