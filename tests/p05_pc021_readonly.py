"""Bounded POSIX package-content verification, never a preservation writer.

Walk with retained directory fds and openat/O_NOFOLLOW at every component.
Rewalk from the anchor after reading to bind the pathname to those objects.
Only ordinary files/directories are admitted; O_NONBLOCK prevents FIFO open
from hanging before its type can be refused. Unsupported platforms fail.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat


class ContentReadError(RuntimeError):
    pass


def _identity(info):
    return info.st_dev, info.st_ino, info.st_mode


def _metadata(info):
    return _identity(info) + (info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _walk(path, handles):
    """Every child is opened relative to the actual retained parent fd."""
    objects = []
    names = (path.anchor,) + path.parts[1:]
    parent = None
    for index, name in enumerate(names):
        directory = index < len(names) - 1
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        if directory:
            flags |= os.O_DIRECTORY
        fd = os.open(name, flags, dir_fd=parent)
        handles.append(fd)  # acquired ownership precedes every fallible check
        info = os.fstat(fd)
        if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            raise ContentReadError('package content is not an ordinary file/directory')
        objects.append((fd, directory, _identity(info), _metadata(info)))
        parent = fd
    return objects


def fingerprint(path: Path, limit: int):
    if (os.name != 'posix' or os.open not in os.supports_dir_fd
            or not all(hasattr(os, name) for name in
                       ('O_NOFOLLOW', 'O_DIRECTORY', 'O_NONBLOCK', 'O_CLOEXEC'))):
        raise ContentReadError('no supported no-follow package-content reader')
    if not path.is_absolute() or '..' in path.parts or len(path.parts) < 2:
        raise ContentReadError('package content requires an absolute plain file path')
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise ContentReadError('package-content chunk limit must be positive')
    handles, primary, closes = [], None, []
    try:
        bound = _walk(path, handles)
        count, digest = 0, hashlib.sha256()
        while True:
            chunk = os.read(bound[-1][0], min(limit, 65536))
            if not chunk:
                break
            count += len(chunk)
            if count > bound[-1][3][3]:
                raise ContentReadError('package content extra read')
            digest.update(chunk)
        # Retained fd metadata plus a fresh anchor-to-leaf no-follow walk.
        for fd, directory, identity, metadata in bound:
            info = os.fstat(fd)
            if (_identity(info) != identity
                    or (not directory and _metadata(info) != metadata)):
                raise ContentReadError('package content retained identity/metadata drift')
        if count != bound[-1][3][3]:
            raise ContentReadError('package content short read')
        fresh = _walk(path, handles)
        for original, current in zip(bound, fresh):
            if (original[2] != current[2]
                    or (not original[1] and original[3] != current[3])):
                raise ContentReadError('package content path binding drift')
    except BaseException as exc:
        primary = exc
    finally:
        for fd in reversed(handles):
            try:
                os.close(fd)
            except Exception as exc:
                closes.append(repr(exc))
    if primary is not None:
        if closes:
            primary.add_note('content reader close failures: ' + repr(closes))
        if isinstance(primary, OSError):
            raise ContentReadError('no-follow package content I/O failed: ' + str(primary)) from primary
        raise primary
    if closes:
        raise ContentReadError('package content close failed: ' + repr(closes))
    return count, digest.hexdigest()
