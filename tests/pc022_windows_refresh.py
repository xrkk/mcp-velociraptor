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
from ctypes import wintypes
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
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
    _fields_ = (
        ("file_attributes", wintypes.DWORD),
        ("reparse_tag", wintypes.DWORD),
    )


class _FILETIME(ctypes.Structure):
    _fields_ = (("low", wintypes.DWORD), ("high", wintypes.DWORD))


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("file_attributes", wintypes.DWORD),
        ("creation_time", _FILETIME),
        ("last_access_time", _FILETIME),
        ("last_write_time", _FILETIME),
        ("volume_serial_number", wintypes.DWORD),
        ("file_size_high", wintypes.DWORD),
        ("file_size_low", wintypes.DWORD),
        ("number_of_links", wintypes.DWORD),
        ("file_index_high", wintypes.DWORD),
        ("file_index_low", wintypes.DWORD),
    )


if os.name == "nt":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    CreateFileW = kernel32.CreateFileW
    CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    CreateFileW.restype = wintypes.HANDLE

    FlushFileBuffers = kernel32.FlushFileBuffers
    FlushFileBuffers.argtypes = (wintypes.HANDLE,)
    FlushFileBuffers.restype = wintypes.BOOL

    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = (wintypes.HANDLE,)
    CloseHandle.restype = wintypes.BOOL

    GetFileInformationByHandleEx = kernel32.GetFileInformationByHandleEx
    GetFileInformationByHandleEx.argtypes = (
        wintypes.HANDLE,
        wintypes.INT,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    GetFileInformationByHandleEx.restype = wintypes.BOOL

    GetFileInformationByHandle = kernel32.GetFileInformationByHandle
    GetFileInformationByHandle.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
    )
    GetFileInformationByHandle.restype = wintypes.BOOL

    MoveFileExW = kernel32.MoveFileExW
    MoveFileExW.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
    MoveFileExW.restype = wintypes.BOOL

    CreateDirectoryW = kernel32.CreateDirectoryW
    CreateDirectoryW.argtypes = (wintypes.LPCWSTR, wintypes.LPVOID)
    CreateDirectoryW.restype = wintypes.BOOL

    CreateHardLinkW = kernel32.CreateHardLinkW
    CreateHardLinkW.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPVOID)
    CreateHardLinkW.restype = wintypes.BOOL
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
    handle = CreateFileW(
        str(path),
        desired_access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    value = _handle_value(handle)
    if value is None or value == INVALID_HANDLE_VALUE:
        raise Pc022WindowsRefreshError(
            "open",
            f"CreateFileW failed for {path}",
            winerror=ctypes.get_last_error(),
        )
    return value


def _close_once(handle: int, stage: str, aggregated: list[dict[str, Any]]) -> None:
    """Exactly one close attempt per successfully obtained handle."""
    ctypes.set_last_error(0)
    closed = bool(CloseHandle(handle))
    if not closed:
        aggregated.append(
            {"stage": stage, "winerror": ctypes.get_last_error(), "message": "CloseHandle returned zero"}
        )


def _query_attribute_tag(handle: int) -> FILE_ATTRIBUTE_TAG_INFO:
    info = FILE_ATTRIBUTE_TAG_INFO()
    ctypes.set_last_error(0)
    ok = bool(
        GetFileInformationByHandleEx(
            handle,
            FILE_INFO_BY_HANDLE_CLASS_FILE_ATTRIBUTE_TAG_INFO,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
    )
    if not ok:
        raise Pc022WindowsRefreshError(
            "attribute_tag",
            "GetFileInformationByHandleEx(FileAttributeTagInfo) failed",
            winerror=ctypes.get_last_error(),
        )
    return info


def _query_file_id(handle: int) -> tuple[int, int]:
    """Return (volume_serial_number, file_index) for an open handle.

    Identity source is ``GetFileInformationByHandle`` (BY_HANDLE_FILE_
    INFORMATION: VolumeSerialNumber plus the 64-bit FileIndex) because the
    audited target (Windows 10 build 19045) rejects ``GetFileInformationBy-
    HandleEx(FileIdInfo)`` with ERROR_INVALID_PARAMETER on directory
    handles; the compared semantics (same-volume, same-object identifier)
    are identical.  Recorded as a PC022 erratum candidate for the normative
    text that names the FileIdInfo class.
    """
    info = BY_HANDLE_FILE_INFORMATION()
    ctypes.set_last_error(0)
    ok = bool(GetFileInformationByHandle(handle, ctypes.byref(info)))
    if not ok:
        raise Pc022WindowsRefreshError(
            "file_id",
            "GetFileInformationByHandle failed",
            winerror=ctypes.get_last_error(),
        )
    file_index = (info.file_index_high << 32) | info.file_index_low
    return info.volume_serial_number, file_index


def _verify_directory_object(info: FILE_ATTRIBUTE_TAG_INFO) -> None:
    if not info.file_attributes & FILE_ATTRIBUTE_DIRECTORY:
        raise Pc022WindowsRefreshError(
            "type", "object opened via the directory path is not a directory"
        )
    if info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise Pc022WindowsRefreshError(
            "reparse", "object opened via the directory path is a reparse point"
        )


def handle_directory_identity(path: Path, *, desired_access: int = FILE_READ_ATTRIBUTES) -> tuple[int, int]:
    """Open, verify, and return (volume_serial_number, file_id) for ``path``.

    Lightweight identity probe used by hierarchy verification and same-volume
    checks; the refresh helper itself uses the GENERIC_WRITE main handle.
    """
    _require_nt()
    handle = _open_directory_handle(path, desired_access)
    aggregated: list[dict[str, Any]] = []
    try:
        _verify_directory_object(_query_attribute_tag(handle))
        return _query_file_id(handle)
    finally:
        _close_once(handle, "identity_probe_close", aggregated)
        if aggregated:
            raise Pc022WindowsRefreshError(
                "identity_probe_close", "CloseHandle failed during identity probe",
                aggregated=aggregated,
            )


def handle_file_identity(path: Path) -> tuple[int, int]:
    """Open, verify, and return (volume_serial_number, file_id) for a plain file."""
    _require_nt()
    handle = _open_directory_handle(path, FILE_READ_ATTRIBUTES)
    aggregated: list[dict[str, Any]] = []
    try:
        info = _query_attribute_tag(handle)
        if not info.file_attributes & FILE_ATTRIBUTE_DIRECTORY:
            pass  # plain file as required
        else:
            raise Pc022WindowsRefreshError(
                "type", "object opened via the file path is a directory"
            )
        if info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise Pc022WindowsRefreshError(
                "reparse", "object opened via the file path is a reparse point"
            )
        return _query_file_id(handle)
    finally:
        _close_once(handle, "identity_probe_close", aggregated)
        if aggregated:
            raise Pc022WindowsRefreshError(
                "identity_probe_close", "CloseHandle failed during identity probe",
                aggregated=aggregated,
            )


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
    aggregated: list[dict[str, Any]] = []
    h_main = _open_directory_handle(directory, GENERIC_WRITE)
    try:
        _verify_directory_object(_query_attribute_tag(h_main))
        main_identity = _query_file_id(h_main)
        h_pre = _open_directory_handle(directory, GENERIC_WRITE)
        try:
            if _query_file_id(h_pre) != main_identity:
                raise Pc022WindowsRefreshError(
                    "compare_pre", "path identity changed between H_main and H_pre"
                )
        finally:
            _close_once(h_pre, "close_pre", aggregated)
        ctypes.set_last_error(0)
        if not bool(FlushFileBuffers(h_main)):
            raise Pc022WindowsRefreshError(
                "flush_main",
                "FlushFileBuffers(H_main) returned zero",
                winerror=ctypes.get_last_error(),
            )
    finally:
        _close_once(h_main, "close_main", aggregated)
    h_post = _open_directory_handle(directory, GENERIC_WRITE)
    try:
        if _query_file_id(h_post) != main_identity:
            raise Pc022WindowsRefreshError(
                "compare_post",
                "path identity changed after CloseHandle(H_main)",
                aggregated=aggregated or None,
            )
    finally:
        _close_once(h_post, "close_post", aggregated)
    if aggregated:
        raise Pc022WindowsRefreshError(
            "close", "a close attempt failed during refresh", aggregated=aggregated
        )
    return {
        "directory": str(directory),
        "volume_serial_number": main_identity[0],
        "file_id": hex(main_identity[1]),
        "flush": "FlushFileBuffers(H_main) returned nonzero",
    }


def require_same_volume(
    first: tuple[int, bytes], second: tuple[int, bytes], *, label: str
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

    For every ``child`` the fixed order is: refresh ``parent``; CreateDirectoryW
    accepting only that this call actually created it; open and verify the
    child as a plain non-reparse directory on the same volume;
    ``windows_refresh_directory(child)``; ``windows_refresh_directory(parent)``;
    re-verify the child path-to-handle identity.  Any failure stops before the
    next level; no partial hierarchy is retried, isolated, or cleaned up here.
    """
    _require_nt()
    base_identity = handle_directory_identity(base, desired_access=FILE_READ_ATTRIBUTES)
    current = base
    for part in parts:
        if part in {"", ".", ".."}:
            raise Pc022WindowsRefreshError("component", f"invalid path component {part!r}")
        child = current / part
        windows_refresh_directory(current)
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
