"""PC026 09 single-record Windows publisher; no production root authorization.

Uses retained PC026 reader directory leases and a CREATE_NEW writer with DELETE
access. FileRenameInfo operates on that handle, with ReplaceIfExists=FALSE and
no cross-volume copy fallback. The writer is closed before the native reader
reopens the final file: its read-only sharing would otherwise conflict with the
writer's write/DELETE access. No file is deleted, retried or treated as approved.

Source closure must include tests.p05_pc026_windows_reader and its ContentIO,
readback, descriptor and Windows ACL dependencies. No alternate OS/SID/API is a
public parameter. Native execution and directory power-loss durability remain
unverified by the host models of this module.
"""
from __future__ import annotations

import ctypes
import hashlib
import threading
import uuid

from tests import p05_pc026_windows_reader as reader
from velociraptor_observation_archive import ArchiveCodec


class PublishError(RuntimeError):
    """Public non-secret failure plus conservative residual-object boundary."""

    def __init__(self, code, *, phase="NOT_CREATED", pending=None, final=None):
        super().__init__(code)
        self.code, self.phase = code, phase
        self.pending, self.final = pending, final


class _NativeFailure(RuntimeError):
    pass


class _CreateFailure(_NativeFailure):
    def __init__(self, *, created):
        super().__init__("pending_create_failed")
        self.created = created


class _RenameInfo(ctypes.Structure):
    # BOOL/DWORD union occupies four bytes, then native HANDLE alignment.
    # FileName is a variable UTF-16 WCHAR array; never ctypes.c_wchar (Linux is 4).
    _fields_ = [("replace", ctypes.c_uint32), ("root", ctypes.c_void_p),
                ("length", ctypes.c_uint32), ("name", ctypes.c_uint16 * 1)]


def _rename_buffer(destination):
    name = str(destination).encode("utf-16-le")
    offset = _RenameInfo.name.offset
    storage = ctypes.create_string_buffer(max(ctypes.sizeof(_RenameInfo), offset + len(name)))
    header = _RenameInfo.from_buffer(storage)
    header.replace, header.root, header.length = 0, None, len(name)
    ctypes.memmove(ctypes.addressof(storage) + offset, name, len(name))
    return storage, offset + len(name)


class _PublisherIO(reader.NativeIO):
    """Real synchronous Win32 adapter; tests patch factories, not public inputs."""

    def __init__(self):
        super().__init__()
        self.write_file = self.kernel.WriteFile
        self.write_file.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                                    ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        self.write_file.restype = ctypes.c_int
        self.flush_file = self.kernel.FlushFileBuffers
        self.flush_file.argtypes = [ctypes.c_void_p]
        self.flush_file.restype = ctypes.c_int

    def create_pending(self, path):
        handle = None
        try:
            # GENERIC_READ|GENERIC_WRITE|DELETE|READ_CONTROL|ACCESS_SYSTEM_SECURITY.
            # CREATE_NEW, zero sharing, BACKUP_SEMANTICS|OPEN_REPARSE_POINT via _open.
            with reader._security_privilege(self.advapi, self.kernel):
                handle = self._open(path, 0xC1030000, 0, 1)
            return handle
        except BaseException as primary:
            if handle is not None:
                try:
                    self.close(handle)
                except BaseException:
                    primary.add_note("pending acquisition close failed")
            failure = _CreateFailure(created=handle is not None)
            if getattr(primary, "__notes__", None):
                failure.add_note("pending acquisition cleanup diagnostic")
            raise failure from primary

    def write(self, handle, data):
        buffer, count = ctypes.create_string_buffer(data, len(data)), ctypes.c_uint32()
        if not self.write_file(handle, buffer, len(data), ctypes.byref(count), None):
            raise _NativeFailure("write_failed")
        if count.value > len(data):
            raise _NativeFailure("write_count_invalid")
        return count.value

    def flush(self, handle):
        if not self.flush_file(handle):
            raise _NativeFailure("flush_failed")

    def rename(self, handle, destination):
        storage, size = _rename_buffer(destination)
        # FileRenameInfo=3. Full absolute DOS path, NULL RootDirectory; no replace
        # and no FileRenameInfoEx flags allowing copy or POSIX replacement.
        if not self.set_info(handle, 3, storage, size):
            raise _NativeFailure("rename_failed")


def _session():
    return reader.WindowsSession()


def _writer_api():
    return _PublisherIO()


class WindowsRecordPublisher:
    """Existing directory lease; publish one 08 original without chain authority.

    Four explicit codec budgets are required. max_records/max_total_bytes are
    codec policy, not instance-wide accounting. Directory is a low-level input,
    not a production approved namespace. close/context-manager owns only handles.
    On any failure the instance refuses further publication; do not replay an
    unknown operation through another publisher to hide uncertain residuals.
    """

    def __init__(self, directory, *, max_record_bytes: int, max_records: int,
                 max_total_bytes: int, max_json_depth: int):
        try:
            self.codec = ArchiveCodec(max_record_bytes=max_record_bytes, max_records=max_records,
                                      max_total_bytes=max_total_bytes, max_json_depth=max_json_depth)
            self.directory = reader.check_path(directory)
        except Exception as cause:
            raise PublishError("input_invalid") from cause
        self.lock = threading.RLock()
        self.closed = False
        self.failed = False
        self.session = None
        self.api = None
        self.last_pending = self.last_final = None
        self.last_phase = "NOT_CREATED"
        try:
            self.session = _session()  # Windows-only, actual token, no impersonation.
            self.api = _writer_api()
            self.chain = list(reversed(self.directory.parents)) + [self.directory]
            if len(self.chain) > 64:
                raise _NativeFailure("ancestor_depth_exceeded")
            self._directories()
        except BaseException as cause:
            error = PublishError("directory_binding_failed")
            if self.session is not None:
                try:
                    self.session.close()
                except BaseException:
                    error.add_note("directory_close_failed")
            self.closed = True
            raise error from cause

    def _principal(self):
        # A publisher may be used from a different thread than construction;
        # the effective thread token must still pass the original rejection gate.
        probe = _session()
        try:
            if probe.sid != self.session.sid:
                raise _NativeFailure("principal_changed")
        finally:
            probe.close()

    def _directories(self):
        observations = [self.session._bind(path, True, "ancestor")[1] for path in self.chain]
        if len({row[0][0] for row in observations}) != 1:
            raise _NativeFailure("ancestor_volume_differs")
        return observations[-1][0][0]

    def _file(self, handle, path, volume):
        identity = self.api.identity(handle, False)
        raw = self.api.descriptor(handle)
        metadata = self.api.metadata(handle)
        if self.api.name(handle) != str(path):
            raise _NativeFailure("file_alias_differs")
        if identity[0] != volume:
            raise _NativeFailure("file_volume_differs")
        reader.acl._evaluate(reader.descriptor_snapshot(raw), "state", self.session.trusted)
        return identity, raw, metadata

    @staticmethod
    def _transition(before, after):
        # Only size/write/change times may change during controlled write/rename.
        # Creation time and attributes remain fixed; identity/full SD never change.
        if before[:2] != after[:2] or before[2][1] != after[2][1] or before[2][4] != after[2][4]:
            raise _NativeFailure("file_identity_security_drift")

    def _content(self, handle, raw):
        self.api.rewind(handle)
        count, digest = 0, hashlib.sha256()
        while chunk := self.api.read(handle):
            if type(chunk) is not bytes or len(chunk) > 65536:
                raise _NativeFailure("invalid_read_chunk")
            end = count + len(chunk)
            if end > len(raw) or chunk != raw[count:end]:
                raise _NativeFailure("readback_bytes_differ")
            count = end
            digest.update(chunk)
        if count != len(raw) or digest.digest() != hashlib.sha256(raw).digest():
            raise _NativeFailure("readback_size_hash_differs")

    def _final_read(self, destination, raw):
        # Preserve private full-SD checks while bounding a changed final file;
        # WindowsSession.read otherwise collects its entire observed length.
        with self.session.lock:
            stream = self.session._stream_bound(destination, private=True)
            count = 0
            try:
                while True:
                    try:
                        chunk = next(stream)
                    except StopIteration as finished:
                        if count != len(raw):
                            raise _NativeFailure("final_size_differs")
                        return finished.value
                    end = count + len(chunk)
                    if end > len(raw) or chunk != raw[count:end]:
                        raise _NativeFailure("final_bytes_differ")
                    count = end
            finally:
                stream.close()

    def publish(self, raw: bytes) -> dict:
        with self.lock:
            if self.closed or self.failed:
                raise PublishError("publisher_unavailable")
            # Pure validation and name derivation precede all new file effects.
            try:
                record = self.codec.parse(raw)
            except Exception as cause:
                raise PublishError("record_invalid") from cause
            sequence = record["sequence"]
            if sequence > 99999999:
                raise PublishError("sequence_filename_limit")
            final = f"{sequence:08d}.json"
            pending = str(uuid.uuid4()) + ".pending"
            candidate, destination = self.directory / pending, self.directory / final
            reader.check_path(candidate)
            reader.check_path(destination)
            self.last_pending, self.last_final = pending, final
            handle = None
            phase = "NOT_CREATED"
            error = None
            result = None
            code = "directory_recheck_failed"
            try:
                code = "principal_recheck_failed"
                self._principal()
                code = "directory_recheck_failed"
                volume = self._directories()
                code = "pending_create_failed"
                # CREATE_NEW may succeed before acquisition/privilege restoration
                # reports failure. Preserve the candidate; never assert it absent.
                phase = "PENDING"
                try:
                    handle = self.api.create_pending(candidate)
                except _CreateFailure as cause:
                    phase = "PENDING" if cause.created else "NOT_CREATED"
                    raise
                code = "pending_security_failed"
                before = self._file(handle, candidate, volume)
                if before[2][0] != 0:
                    raise _NativeFailure("new_pending_not_empty")
                code = "write_failed"
                offset = 0
                while offset < len(raw):
                    chunk = raw[offset:offset + 65536]
                    written = self.api.write(handle, chunk)
                    if type(written) is not int or not 0 < written <= len(chunk):
                        raise _NativeFailure("write_zero_or_invalid_progress")
                    offset += written
                code = "flush_failed"
                self.api.flush(handle)
                code = "pending_readback_failed"
                written = self._file(handle, candidate, volume)
                self._transition(before, written)
                if written[2][0] != len(raw):
                    raise _NativeFailure("written_size_differs")
                self._content(handle, raw)
                if self._file(handle, candidate, volume) != written:
                    raise _NativeFailure("pending_readback_drift")
                self._directories()
                code = "rename_unknown"
                phase = "UNKNOWN"  # From the naming invocation onwards, conservative.
                self.api.rename(handle, destination)
                code = "published_handle_check_failed"
                named = self._file(handle, destination, volume)
                self._transition(written, named)
                if named[2][0] != len(raw):
                    raise _NativeFailure("named_size_differs")
                self._content(handle, raw)
                if self._file(handle, destination, volume) != named:
                    raise _NativeFailure("published_handle_drift")
                self._directories()
                code = "writer_close_failed"
                owned, handle = handle, None  # A close attempt is never retried.
                self.api.close(owned)
                code = "final_readback_failed"
                # Directory leases remain pinned; writer DELETE access is now gone.
                # This exact private read acquires/retains the final handle and SD.
                self._principal()
                observations, identity = self._final_read(destination, raw)
                if observations[-1] != named:
                    raise _NativeFailure("final_identity_content_drift")
                self._directories()
                result = {"ref": {"path": final, "size": len(raw),
                                  "sha256": hashlib.sha256(raw).hexdigest()},
                          "identity": identity}
            except BaseException as cause:
                self.failed = True
                error = PublishError(code, phase=phase, pending=pending, final=final)
                error.__cause__ = cause
            finally:
                # A final file handle lasts only this transaction; all directory
                # leases stay until close. Failed reads may also retain a leaf.
                leaf = self.session.objects.pop(str(destination), None)
                if leaf is not None:
                    try:
                        self.session.api.close(leaf[0])
                    except BaseException:
                        self.failed = True
                        if error is not None:
                            error.add_note("final_close_failed")
                        else:
                            error = PublishError("final_close_failed", phase=phase, pending=pending, final=final)
                if handle is not None:
                    try:
                        self.api.close(handle)
                    except BaseException:
                        if error is not None:
                            error.add_note("writer_close_failed")
                        else:
                            self.failed = True
                            error = PublishError("writer_close_failed", phase=phase, pending=pending, final=final)
            self.last_phase = phase
            if error is not None:
                raise error
            return result

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            if self.session is not None:
                try:
                    self.session.close()
                except BaseException as cause:
                    raise PublishError("directory_close_failed", phase=self.last_phase,
                                       pending=self.last_pending, final=self.last_final) from cause

    def __enter__(self):
        return self

    def __exit__(self, kind, primary, tb):
        try:
            self.close()
        except BaseException:
            if primary is None:
                raise
            primary.add_note("directory_close_failed")
