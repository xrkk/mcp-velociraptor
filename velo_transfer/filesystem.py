"""Exclusive same-volume directory publication; caller owns durable intent/receipt."""

from __future__ import annotations

import ctypes
import errno
import os
import stat
from pathlib import Path
from typing import Callable

from .bundle import verify_tree
from .errors import TransferContentError as Error
from .manifest import Budget, _no_link, directory_identity, safe_chain


def _rename_noreplace(source: Path, destination: Path) -> None:
    if os.name == "posix":
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise Error("atomic_primitive_unavailable")
        renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                              ctypes.c_char_p, ctypes.c_uint]
        renameat2.restype = ctypes.c_int
        result = renameat2(-100, os.fsencode(source), -100,
                           os.fsencode(destination), 1)  # RENAME_NOREPLACE
        if result != 0:
            number = ctypes.get_errno()
            if number == errno.EEXIST:
                raise Error("destination_exists")
            if number in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
                raise Error("atomic_primitive_unavailable")
            if number == errno.EXDEV:
                raise Error("cross_volume")
            raise Error("atomic_publish_failed", errno=number)
    elif os.name == "nt":
        move = ctypes.windll.kernel32.MoveFileExW
        move.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
        move.restype = ctypes.c_int
        if not move(str(source), str(destination), 0):  # no REPLACE_EXISTING, no COPY_ALLOWED
            code = ctypes.windll.kernel32.GetLastError()
            if code in (80, 183):
                raise Error("destination_exists")
            if code == 17:
                raise Error("cross_volume")
            raise Error("atomic_publish_failed", winerror=code)
    else:
        raise Error("atomic_primitive_unavailable")


def _same_volume(source: Path, parent: Path) -> bool:
    return os.stat(source).st_dev == os.stat(parent).st_dev


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_tree(root: Path, budget: Budget) -> None:
    if os.name != "posix":
        return
    for current, dirs, files in os.walk(root, topdown=False, followlinks=False):
        budget.check()
        for name in files:
            path = Path(current) / name
            if not stat.S_ISREG(_no_link(path).st_mode):
                raise Error("tree_type_mismatch")
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        _fsync_directory(Path(current))


def publish_directory(staging_directory: str | Path, destination_directory: str | Path,
                      allowed_root: str | Path, manifest: dict, budget: Budget, *,
                      expected_staging_identity: dict[str, int],
                      expected_parent_identity: dict[str, int],
                      verify_windows_acl: Callable[[Path], bool] | None = None) -> dict:
    """Rename verified staging only after caller durably writes publish_intent.

    Never infers a receipt, reuse, or cleanup authorization. On post-rename failure
    the final path may exist; the caller must reconcile its persisted intent.
    """
    staging, destination, allowed_root = map(Path,
        (staging_directory, destination_directory, allowed_root))
    if staging.parent != destination.parent:
        raise Error("cross_parent")
    safe_chain(staging, allowed_root)
    safe_chain(destination, allowed_root, allow_missing_leaf=True)
    if destination.exists() or destination.is_symlink():
        raise Error("destination_exists")
    if directory_identity(staging) != expected_staging_identity:
        raise Error("staging_changed")
    if directory_identity(destination.parent) != expected_parent_identity:
        raise Error("destination_parent_changed")
    if not _same_volume(staging, destination.parent):
        raise Error("cross_volume")
    if os.name == "posix" and _no_link(staging).st_mode & 0o077:
        raise Error("staging_not_private")
    if os.name == "nt":
        if verify_windows_acl is None or not verify_windows_acl(staging) or not verify_windows_acl(destination.parent):
            raise Error("windows_acl_not_verified")
    verify_tree(staging, manifest, budget, expected_staging_identity)
    try:
        _fsync_tree(staging, budget)
    except OSError as exc:
        raise Error("staging_sync_failed") from exc
    if directory_identity(staging) != expected_staging_identity:
        raise Error("staging_changed")
    if directory_identity(destination.parent) != expected_parent_identity:
        raise Error("destination_parent_changed")
    _rename_noreplace(staging, destination)
    # From this point failure means published-but-unconfirmed, never absent.
    try:
        _fsync_directory(destination.parent)
        if directory_identity(destination.parent) != expected_parent_identity:
            raise Error("destination_parent_changed")
        if directory_identity(destination) != expected_staging_identity:
            raise Error("destination_changed")
        if os.name == "nt" and (verify_windows_acl is None or not verify_windows_acl(destination)):
            raise Error("windows_acl_not_verified")
        result = verify_tree(destination, manifest, budget, expected_staging_identity)
    except Error as exc:
        raise Error(exc.code, published=True) from exc
    except OSError as exc:
        raise Error("post_publish_io_failed", published=True) from exc
    return {"destination_directory": str(destination), "identity": result["identity"],
            "manifest_sha256": result["manifest_sha256"], "files": result["files"]}
