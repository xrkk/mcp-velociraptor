"""Protected references to the already deployed transfer endpoints."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


class ConnectionError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ConnectionError("duplicate_key")
        result[key] = value
    return result


def _secure_read(path: Path, limit: int) -> bytes:
    if not path.is_absolute() or ".." in path.parts:
        raise ConnectionError("invalid_reference_path")
    # A private leaf is insufficient when another user can replace an ancestor.
    for ancestor in reversed((path, *path.parents)):
        info = ancestor.lstat()
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if (stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, os.getuid()) or
                (info.st_mode & 0o022 and not sticky_root)):
            raise ConnectionError("insecure_reference")
        if ancestor != path and not stat.S_ISDIR(info.st_mode):
            raise ConnectionError("insecure_reference")
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
            before.st_nlink != 1 or before.st_mode & 0o077 or before.st_size > limit):
        raise ConnectionError("insecure_reference")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_mode, opened.st_nlink) != (
            before.st_dev, before.st_ino, before.st_uid, before.st_mode, before.st_nlink
        ):
            raise ConnectionError("reference_changed")
        raw = os.read(fd, limit + 1)
        after = path.lstat()
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
        ) or len(raw) > limit:
            raise ConnectionError("reference_changed")
        return raw
    finally:
        os.close(fd)


def _url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ConnectionError("invalid_endpoint")
    parts = urlsplit(value)
    if (parts.scheme not in ("http", "https") or not parts.hostname or parts.username or
            parts.password or parts.query or parts.fragment or parts.path != "/mcp" or
            any(ch.isspace() for ch in value)):
        raise ConnectionError("invalid_endpoint")
    try:
        if parts.port is not None and not 1 <= parts.port <= 65535:
            raise ValueError()
    except ValueError:
        raise ConnectionError("invalid_endpoint") from None
    return value


def _windows_path(value: str) -> str:
    if (not isinstance(value, str) or len(value) > 2048 or
            re.fullmatch(r"[A-Za-z]:\\[^\x00-\x1f]*", value) is None or
            any(part in ("", ".", "..") or ":" in part for part in value[3:].split("\\"))):
        raise ConnectionError("invalid_guest_path")
    return value


@dataclass(frozen=True, repr=False)
class TokenReference:
    path: Path

    def read(self) -> str:
        try:
            raw = _secure_read(self.path, 8192)
        except OSError:
            raise ConnectionError("invalid_token") from None
        if not raw or b"\n" in raw or b"\r" in raw or b"\x00" in raw:
            raise ConnectionError("invalid_token")
        try:
            value = raw.decode("ascii")
        except UnicodeDecodeError:
            raise ConnectionError("invalid_token") from None
        if not value or any(ch.isspace() for ch in value):
            raise ConnectionError("invalid_token")
        return value

    def __repr__(self):
        return "TokenReference(<protected>)"


@dataclass(frozen=True, repr=False)
class Endpoint:
    url: str
    token: TokenReference | None

    def __repr__(self):
        return "Endpoint(<protected>)"


@dataclass(frozen=True, repr=False)
class Deployment:
    python_path: str
    project_root: str
    policy_path: str
    guest_work_root: str

    def __repr__(self):
        return "Deployment(<protected>)"


@dataclass(frozen=True, repr=False)
class ConnectionProfile:
    velo: Endpoint
    windows: Endpoint | None
    deployment: Deployment

    def __repr__(self):
        return "ConnectionProfile(<protected>)"


def load_connection_profile(absolute_path: str | Path) -> ConnectionProfile:
    try:
        raw = _secure_read(Path(absolute_path), 65536)
        data = json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ConnectionError("invalid_profile")))
        if not isinstance(data, dict) or set(data) != {"version", "velo", "windows", "deployment"} or data["version"] != "velo.transfer.connection.v1":
            raise ConnectionError("invalid_profile")

        def endpoint(value, *, required_token):
            if (not isinstance(value, dict) or
                    (set(value) != {"endpoint", "token_file"} if required_token else
                     set(value) not in ({"endpoint"}, {"endpoint", "token_file"}))):
                raise ConnectionError("invalid_profile")
            token = TokenReference(Path(value["token_file"])) if "token_file" in value else None
            if token is not None:
                token.read()  # Validate now and again immediately before use.
            return Endpoint(_url(value["endpoint"]), token)

        deployed = data["deployment"]
        if not isinstance(deployed, dict) or set(deployed) != {"python_path", "project_root", "policy_path", "guest_work_root"}:
            raise ConnectionError("invalid_profile")
        return ConnectionProfile(endpoint(data["velo"], required_token=True),
                                 endpoint(data["windows"], required_token=False) if data["windows"] is not None else None,
                                 Deployment(*(_windows_path(deployed[key]) for key in (
                                     "python_path", "project_root", "policy_path", "guest_work_root"))))
    except ConnectionError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise ConnectionError("invalid_profile") from None
