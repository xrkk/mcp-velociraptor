"""PC022 Windows durability primitives for P05 persistence points.

Implements the PC022 contract (P05 v19, section "PC022 限定 Windows 刷新保证"):
the ``windows_refresh_directory(D)`` helper with exactly three named handles
(``H_main``/``H_pre``/``H_post``), each getting exactly one close attempt;
finite, non-recursive handle lifetime; new-directory-hierarchy refresh with
per-level ordering; same-volume identity checks; and same-volume
``MoveFileExW`` replace with flags 9.

Windows-only by contract.  Importing on a non-Windows platform is allowed for
static analysis, but every call fails closed with
:class:`Pc022WindowsRefreshError`; there is deliberately no POSIX directory
fsync fallback (``os.open(directory, O_RDONLY)`` is EACCES on the target
Windows and must not be presented as a production path).

The success criterion is limited: the specified APIs returned success in this
process on the audited local NTFS environment with identity re-verification.
It is not a hardware/host power-loss durability guarantee and not a claim of
POSIX fsync equivalence.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Any


GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_READ_ATTRIBUTES = 0x0080
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
MOVEFILE_REPLACE_EXISTING = 0x00000001
MOVEFILE_WRITE_THROUGH = 0x00000008
MOVEFILE_FLAGS_9 = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
FILE_INFO_BY_HANDLE_CLASS_FILE_ATTRIBUTE_TAG_INFO = 9
FILE_INFO_BY_HANDLE_CLASS_FILE_ID_INFO = 18
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
    _fields_ = (("file_attributes", ctypes.c_uint32), ("reparse_tag", ctypes.c_uint32))


class FILE_ID_INFO(ctypes.Structure):
    _fields_ = (("volume_serial_number", ctypes.c_uint64), ("file_id", ctypes.c_ubyte * 16))


if os.name == "nt":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    CreateFileW = kernel32.CreateFileW
    CreateFileW.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    CreateFileW.restype = ctypes.c_void_p

    FlushFileBuffers = kernel32.FlushFileBuffers
    FlushFileBuffers.argtypes = (ctypes.c_void_p,)
    FlushFileBuffers.restype = ctypes.c_int32

    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = (ctypes.c_void_p,)
    CloseHandle.restype = ctypes.c_int32

    GetFileInformationByHandleEx = kernel32.GetFileInformationByHandleEx
    GetFileInformationByHandleEx.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int32,
        ctypes.c_void_p,
        ctypes.c_uint32,
    )
    GetFileInformationByHandleEx.restype = ctypes.c_int32

    MoveFileExW = kernel32.MoveFileExW
    MoveFileExW.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
    MoveFileExW.restype = ctypes.c_int32

    CreateDirectoryW = kernel32.CreateDirectoryW
    CreateDirectoryW.argtypes = (ctypes.c_wchar_p, ctypes.c_void_p)
    CreateDirectoryW.restype = ctypes.c_int32

    CreateHardLinkW = kernel32.CreateHardLinkW
    CreateHardLinkW.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p)
    CreateHardLinkW.restype = ctypes.c_int32
else:  # static-analysis-only host import; every call fails closed below
    kernel32 = None


class Pc022WindowsRefreshError(RuntimeError):
    """A PC022 persistence primitive refused to claim success.

    ``stage`` names the first failing stage; ``aggregated`` carries any later
    close-attempt failures so they are recorded without masking the primary
    failure.  A raised error never implies the data reached stable storage,
    and never authorizes a retry or fallback.
    """

    def __init__(
        self,
        stage: str,
        message: str,
        *,
        winerror: int | None = None,
        aggregated: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(f"{stage}: {message}")
        self.stage = stage
        self.winerror = winerror
        self.aggregated = list(aggregated or [])


def _require_nt() -> None:
    if kernel32 is None:
        raise Pc022WindowsRefreshError(
            "platform",
            "Windows-only primitive; no POSIX directory-fsync fallback is permitted",
        )


def _handle_value(handle: Any) -> int | None:
    if handle is None:
        return None
    if isinstance(handle, int):
        return handle
    return ctypes.cast(handle, ctypes.c_void_p).value


def _open_directory_handle(path: Path, desired_access: int) -> int:
    """CreateFileW with the PC022-fixed flags for directory objects."""
    ctypes.set_last_error(0)
    try:
        handle = CreateFileW(
            str(path),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    except Exception as exc:
        raise _api_error("open", f"CreateFileW raised {type(exc).__name__}: {exc}", exc)
    value = _handle_value(handle)
    if value is None or value == INVALID_HANDLE_VALUE:
        raise Pc022WindowsRefreshError(
            "open",
            f"CreateFileW failed for {path}",
            winerror=ctypes.get_last_error(),
        )
    return value


def _api_error(stage: str, message: str, exc: Exception | None = None) -> Pc022WindowsRefreshError:
    winerror = getattr(exc, "winerror", None) if exc is not None else None
    error = Pc022WindowsRefreshError(stage, message, winerror=ctypes.get_last_error() if winerror is None else winerror)
    if exc is not None:
        error.__cause__ = exc
    return error


def _close_once(handle: int, stage: str) -> Pc022WindowsRefreshError | None:
    """One attempt, never retry; the owner decides primary versus cleanup."""
    ctypes.set_last_error(0)
    try:
        closed = bool(CloseHandle(handle))
    except Exception as exc:
        return _api_error(stage, f"CloseHandle raised {type(exc).__name__}: {exc}", exc)
    return None if closed else _api_error(stage, "CloseHandle returned zero")


class _Lifetime:
    """Finite ownership of acquired handles, including uncertain close results."""
    def __init__(self) -> None:
        self.pending: list[tuple[int, str]] = []
        self.primary: BaseException | None = None

    def open(self, path: Path, access: int, close_stage: str) -> int:
        handle = _open_directory_handle(path, access)
        self.pending.append((handle, close_stage))
        return handle

    def close(self, handle: int, stage: str) -> None:
        # Relinquish the right to attempt a close BEFORE calling the API.
        self.pending.remove((handle, stage))
        failure = _close_once(handle, stage)
        if failure is not None:
            raise failure

    def finish(self) -> None:
        aggregated = []
        for handle, stage in reversed(self.pending):
            failure = _close_once(handle, stage)
            if failure is None:
                continue
            if self.primary is None:
                self.primary = failure
            else:
                aggregated.append({"stage": failure.stage, "winerror": failure.winerror, "message": str(failure)})
        self.pending.clear()
        if self.primary is not None:
            if isinstance(self.primary, Pc022WindowsRefreshError):
                self.primary.aggregated.extend(aggregated)
            elif aggregated:
                self.primary.add_note("PC022 cleanup close failures: " + repr(aggregated))
            raise self.primary


def _call_bool(stage: str, message: str, function, *args) -> None:
    ctypes.set_last_error(0)
    try:
        ok = bool(function(*args))
    except Exception as exc:
        raise _api_error(stage, message + f" ({type(exc).__name__}: {exc})", exc)
    if not ok:
        raise _api_error(stage, message)


def _query_attribute_tag(handle: int) -> FILE_ATTRIBUTE_TAG_INFO:
    info = FILE_ATTRIBUTE_TAG_INFO()
    _call_bool("attribute_tag", "GetFileInformationByHandleEx(FileAttributeTagInfo) failed",
               GetFileInformationByHandleEx, handle, FILE_INFO_BY_HANDLE_CLASS_FILE_ATTRIBUTE_TAG_INFO,
               ctypes.byref(info), ctypes.sizeof(info))
    return info


def _query_file_id(handle: int) -> tuple[int, int]:
    """Full FileIdInfo identity (64-bit volume, 128-bit ID); no API fallback.

    The integer representation preserves existing caller equality/hex behavior
    without truncating any of the 16 native FileId bytes.
    """
    info = FILE_ID_INFO()
    _call_bool("file_id", "GetFileInformationByHandleEx(FileIdInfo) failed",
               GetFileInformationByHandleEx, handle, FILE_INFO_BY_HANDLE_CLASS_FILE_ID_INFO,
               ctypes.byref(info), ctypes.sizeof(info))
    return info.volume_serial_number, int.from_bytes(bytes(info.file_id), "little")


def _verify_directory_object(info: FILE_ATTRIBUTE_TAG_INFO) -> None:
    if not info.file_attributes & FILE_ATTRIBUTE_DIRECTORY:
        raise Pc022WindowsRefreshError(
            "type", "object opened via the directory path is not a directory"
        )
    if info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise Pc022WindowsRefreshError(
            "reparse", "object opened via the directory path is a reparse point"
        )


def _identity(path: Path, desired_access: int, *, directory: bool) -> tuple[int, int]:
    _require_nt()
    lifetime = _Lifetime()
    try:
        handle = lifetime.open(path, desired_access, "identity_probe_close")
        info = _query_attribute_tag(handle)
        if directory:
            _verify_directory_object(info)
        else:
            if info.file_attributes & FILE_ATTRIBUTE_DIRECTORY:
                raise Pc022WindowsRefreshError("type", "file path opened a directory")
            if info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                raise Pc022WindowsRefreshError("reparse", "file path opened a reparse point")
        identity = _query_file_id(handle)
        lifetime.close(handle, "identity_probe_close")
    except BaseException as exc:
        lifetime.primary = exc
    finally:
        lifetime.finish()
    return identity


def handle_directory_identity(path: Path, *, desired_access: int = FILE_READ_ATTRIBUTES) -> tuple[int, int]:
    """No-follow directory FileIdInfo; probe closes once without masking errors."""
    return _identity(path, desired_access, directory=True)


def handle_file_identity(path: Path) -> tuple[int, int]:
    """No-follow ordinary-file FileIdInfo with the same close/error semantics."""
    return _identity(path, FILE_READ_ATTRIBUTES, directory=False)


def windows_refresh_directory(directory: Path) -> dict[str, Any]:
    """One PC022 directory refresh over the fixed three-handle algorithm.

    Steps (P05 v19 PC022 section): open H_main (GENERIC_WRITE, share 7,
    OPEN_EXISTING, BACKUP_SEMANTICS|OPEN_REPARSE_POINT) and verify
    directory/non-reparse plus record its FileIdInfo identity; open H_pre with
    the same no-follow semantics and require identical identity, closing it
    exactly once; FlushFileBuffers(H_main); close H_main exactly once; open
    H_post, require identical identity, close it exactly once, then return
    without opening any further handle.  Every successfully obtained handle
    gets exactly one close attempt, including on failure paths; later close
    failures are aggregated without masking the primary failure.
    """
    _require_nt()
    lifetime = _Lifetime()
    try:
        h_main = lifetime.open(directory, GENERIC_WRITE, "close_main")
        _verify_directory_object(_query_attribute_tag(h_main))
        main_identity = _query_file_id(h_main)
        h_pre = lifetime.open(directory, GENERIC_WRITE, "close_pre")
        if _query_file_id(h_pre) != main_identity:
            raise Pc022WindowsRefreshError("compare_pre", "path identity changed between H_main and H_pre")
        lifetime.close(h_pre, "close_pre")
        _call_bool("flush_main", "FlushFileBuffers(H_main) returned zero", FlushFileBuffers, h_main)
        lifetime.close(h_main, "close_main")
        h_post = lifetime.open(directory, GENERIC_WRITE, "close_post")
        if _query_file_id(h_post) != main_identity:
            raise Pc022WindowsRefreshError("compare_post", "path identity changed after CloseHandle(H_main)")
        lifetime.close(h_post, "close_post")
    except BaseException as exc:
        lifetime.primary = exc
    finally:
        lifetime.finish()
    return {
        "directory": str(directory),
        "volume_serial_number": main_identity[0],
        "file_id": hex(main_identity[1]),
        "flush": "FlushFileBuffers(H_main) returned nonzero",
    }


def require_same_volume(
    first: tuple[int, int], second: tuple[int, int], *, label: str
) -> None:
    if first[0] != second[0]:
        raise Pc022WindowsRefreshError(
            "cross_volume", f"{label} objects live on different NTFS volumes"
        )


def windows_replace_file(source: Path, target: Path) -> dict[str, Any]:
    """Same-volume atomic replace via MoveFileExW flags 9.

    The caller must have persisted ``source`` and verified both parents as
    plain non-reparse directories.  ``MOVEFILE_COPY_ALLOWED`` is deliberately
    not passed; a cross-volume request fails before any side effect.  A
    nonzero return proves only that this same-volume move/replace API call
    succeeded; parent refresh and readback remain separate required steps.
    """
    _require_nt()
    source_identity = handle_directory_identity(source.parent)
    target_identity = handle_directory_identity(target.parent)
    require_same_volume(source_identity, target_identity, label="replace")
    ctypes.set_last_error(0)
    ok = bool(MoveFileExW(str(source), str(target), MOVEFILE_FLAGS_9))
    if not ok:
        raise Pc022WindowsRefreshError(
            "replace",
            "MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH) returned zero",
            winerror=ctypes.get_last_error(),
        )
    return {"source": str(source), "target": str(target), "flags": MOVEFILE_FLAGS_9}


def create_hierarchy_and_refresh(base: Path, parts: tuple[str, ...]) -> Path:
    """Create each missing component under a verified base with per-level refresh.

    For every ``child`` the fixed order is: reverify ``parent``; CreateDirectoryW
    accepting only that this call actually created it; open and verify the
    child as a plain non-reparse directory on the same volume;
    ``windows_refresh_directory(child)``; ``windows_refresh_directory(parent)``;
    re-verify the child path-to-handle identity.  Any failure stops before the
    next level; no partial hierarchy is retried, isolated, or cleaned up here.
    """
    _require_nt()
    base_identity = handle_directory_identity(base, desired_access=FILE_READ_ATTRIBUTES)
    current = base
    current_identity = base_identity
    for part in parts:
        if part in {"", ".", ".."}:
            raise Pc022WindowsRefreshError("component", f"invalid path component {part!r}")
        child = current / part
        if handle_directory_identity(current) != current_identity:
            raise Pc022WindowsRefreshError("compare_hierarchy_parent", "parent identity changed before mkdir")
        ctypes.set_last_error(0)
        if not bool(CreateDirectoryW(str(child), None)):
            raise Pc022WindowsRefreshError(
                "mkdir",
                f"CreateDirectoryW failed for {child}",
                winerror=ctypes.get_last_error(),
            )
        child_identity = handle_directory_identity(child, desired_access=FILE_READ_ATTRIBUTES)
        require_same_volume(base_identity, child_identity, label="hierarchy")
        windows_refresh_directory(child)
        windows_refresh_directory(current)
        if handle_directory_identity(child, desired_access=FILE_READ_ATTRIBUTES) != child_identity:
            raise Pc022WindowsRefreshError(
                "compare_hierarchy", f"child identity drifted during refresh of {child}"
            )
        current = child
        current_identity = child_identity
    return current


def windows_publish_hard_link(source: Path, target: Path) -> dict[str, Any]:
    """Create-if-absent publication via CreateHardLinkW with identity proof.

    PC022 section 2: after a nonzero return, immediately verify through
    no-follow handles that ``source`` and ``target`` share volume/file
    identity; a collision or identity difference fails.  No overwrite, no
    copy fallback, no rename fallback, and no acceptance of an existing
    same-bytes target.
    """
    _require_nt()
    source_before = handle_file_identity(source)
    target_parent = handle_directory_identity(target.parent)
    require_same_volume(source_before, target_parent, label="hard link")
    ctypes.set_last_error(0)
    created = bool(CreateHardLinkW(str(target), str(source), None))
    if not created:
        raise Pc022WindowsRefreshError(
            "hard_link",
            "CreateHardLinkW returned zero",
            winerror=ctypes.get_last_error(),
        )
    source_identity = handle_file_identity(source)
    target_identity = handle_file_identity(target)
    if source_identity != target_identity:
        raise Pc022WindowsRefreshError(
            "hard_link_identity", "published target identity differs from source part"
        )
    return {"source": str(source), "target": str(target), "same_identity": True}
