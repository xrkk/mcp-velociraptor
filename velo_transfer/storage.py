"""Single-writer, bounded, durable task metadata for local transfer coordinators."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import stat
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .errors import TransferContentError as Error
from .manifest import _no_link, canonical_json, check_relative, safe_chain
from .policy import Policy, validate_deadline

STATE_SCHEMA = "velo.transfer.store.v1"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_BINDING_KEYS = frozenset(("request_digest", "policy_id", "vm_uuid",
                           "boot_identity", "vm_epoch"))


def _validate_json(value, *, max_bytes: int, max_nodes: int = 10000,
                   max_depth: int = 32) -> None:
    """Account canonical UTF-8 size before copying/encoding; traverse incrementally."""
    used = 0
    nodes = 0

    def charge(amount):
        nonlocal used
        used += amount
        if used > max_bytes:
            raise Error("state_budget_exceeded")

    def string_size(text):
        charge(2)
        # No giant UTF-8 or escaped temporary string is allocated here.
        for char in text:
            number = ord(char)
            if 0xD800 <= number <= 0xDFFF:
                raise Error("invalid_state")
            if char in ('"', "\\") or char in "\b\f\n\r\t":
                charge(2)
            elif number < 32:
                charge(6)
            else:
                charge(1 if number < 128 else 2 if number < 2048 else 3 if number < 65536 else 4)

    def visit(item, depth):
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise Error("state_budget_exceeded")
        kind = type(item)
        if kind in (dict, list):
            if len(item) > max_nodes - nodes:
                raise Error("state_budget_exceeded")
            charge(2 + max(0, len(item) - 1))
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise Error("invalid_state")
                    string_size(key)
                    charge(1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        elif kind is str:
            string_size(item)
        elif item is None:
            charge(4)
        elif kind is bool:
            charge(4 if item else 5)
        elif kind is int:
            if item.bit_length() > max_bytes * 4:
                raise Error("state_budget_exceeded")
            try:
                charge(len(str(item)))
            except ValueError as exc:
                raise Error("state_budget_exceeded") from exc
        elif kind is float and math.isfinite(item):
            charge(len(repr(item)))
        else:
            raise Error("invalid_state")

    visit(value, 0)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Error("duplicate_state_key")
        result[key] = value
    return result


def _bad_constant(_):
    raise Error("invalid_state")


def _binding(binding: dict, policy: Policy) -> dict:
    if not isinstance(binding, dict) or set(binding) != _BINDING_KEYS:
        raise Error("invalid_task_binding")
    if (not isinstance(binding["request_digest"], str) or
            not _HEX.fullmatch(binding["request_digest"]) or
            binding["policy_id"] != policy.policy_id):
        raise Error("invalid_task_binding")
    if binding["vm_uuid"] != policy.expected_vm_uuid:
        raise Error("vm_identity_mismatch")
    for key in ("vm_uuid", "boot_identity", "vm_epoch"):
        value = binding[key]
        if not isinstance(value, str) or not value or len(value) > 256 or "\x00" in value:
            raise Error("invalid_task_binding")
    return copy.deepcopy(binding)


def _transfer_id(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise Error("invalid_transfer_id")
    try:
        check_relative(value)
    except Error as exc:
        raise Error("invalid_transfer_id") from exc
    return value


def _replace(source: Path, destination: Path) -> None:
    if os.name == "nt":
        import ctypes
        move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
        move.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
        move.restype = ctypes.c_int
        if not move(str(source), str(destination), 0x1 | 0x8):
            raise OSError(ctypes.get_last_error(), "MoveFileExW failed")
    else:
        os.replace(source, destination)


def _sync_directory(directory: Path) -> None:
    if os.name == "posix":
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class TaskStore:
    """A caller explicitly holds writer() across each read/modify/write transaction."""

    def __init__(self, policy: Policy, *, deadline_monotonic: float | None = None):
        if not isinstance(policy, Policy):
            raise Error("invalid_policy")
        self.policy = policy
        self.root = policy.work_root
        self.deadline = (time.monotonic() + policy.limits["max_duration_seconds"]
                         if deadline_monotonic is None else deadline_monotonic)
        validate_deadline(self.deadline, policy.limits["max_duration_seconds"])
        self._lock_fd: int | None = None
        self._lock_identity: tuple[int, int] | None = None
        self._owner = {"owner_id": uuid.uuid4().hex, "pid": os.getpid(),
                       "opened_ns": time.time_ns()}
        self.policy.revalidate()

    def _check(self) -> None:
        validate_deadline(self.deadline, self.policy.limits["max_duration_seconds"])
        self.policy.revalidate()

    def _private(self, path: Path, kind: str) -> None:
        info = _no_link(path)
        if os.name == "nt":
            verifier = self.policy.acl_verifier
            if verifier is None or verifier(path, kind) is not True:
                raise Error("windows_acl_not_verified")
        elif info.st_mode & 0o077:
            raise Error("insecure_permissions")

    def _task_dir(self, transfer_id: str, *, create: bool = False) -> Path:
        name = _transfer_id(transfer_id)
        self._check()
        tasks = self.root / "tasks"
        if not os.path.lexists(tasks):
            if not create:
                raise Error("task_not_found")
            tasks.mkdir(mode=0o700)
            _sync_directory(self.root)
        safe_chain(tasks, self.root)
        self._private(tasks, "tasks")
        task = tasks / name
        if not os.path.lexists(task):
            if not create:
                raise Error("task_not_found")
            task.mkdir(mode=0o700)
            _sync_directory(tasks)
        safe_chain(task, self.root)
        self._private(task, "task")
        return task

    def _state_path(self, transfer_id: str, *, create: bool = False) -> Path:
        return self._task_dir(transfer_id, create=create) / "state.json"

    @contextmanager
    def writer(self):
        if self._lock_fd is not None:
            raise Error("writer_lock_held")
        self._check()
        path = self.root / ".transfer-writer.lock"
        safe_chain(path, self.root, allow_missing_leaf=True)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags, 0o600)
        except OSError as exc:
            raise Error("writer_lock_unavailable") from exc
        acquired = False
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise Error("writer_lock_unavailable")
            self._private(path, "lock")
            if os.name == "posix":
                import fcntl
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise Error("writer_busy") from exc
            elif os.name == "nt":
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                    os.fsync(fd)
                os.lseek(fd, 0, os.SEEK_SET)
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise Error("writer_busy") from exc
            else:
                raise Error("writer_lock_unavailable")
            acquired = True
            identity = os.fstat(fd)
            if os.stat(path, follow_symlinks=False).st_ino != identity.st_ino:
                raise Error("writer_lock_changed")
            self._lock_fd = fd
            self._lock_identity = (identity.st_dev, identity.st_ino)
            yield self
        finally:
            self._lock_fd = None
            self._lock_identity = None
            if acquired:
                if os.name == "posix":
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
                elif os.name == "nt":
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            os.close(fd)

    def _require_writer(self) -> None:
        if self._lock_fd is None or self._lock_identity is None:
            raise Error("writer_lock_required")
        self._check()
        path = self.root / ".transfer-writer.lock"
        info = _no_link(path)
        if (info.st_dev, info.st_ino) != self._lock_identity or info.st_nlink != 1:
            raise Error("writer_lock_changed")
        held = os.fstat(self._lock_fd)
        if (held.st_dev, held.st_ino) != self._lock_identity:
            raise Error("writer_lock_changed")

    def _read(self, path: Path) -> dict:
        self._check()
        safe_chain(path, self.root)
        self._private(path, "state")
        before = _no_link(path)
        if not stat.S_ISREG(before.st_mode):
            raise Error("invalid_state")
        maximum = self.policy.limits["max_state_bytes"]
        if before.st_size > maximum:
            raise Error("state_budget_exceeded")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            if os.fstat(fd).st_ino != before.st_ino:
                raise Error("state_changed")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(maximum + 1)
            if len(raw) > maximum or os.fstat(fd).st_size != len(raw):
                raise Error("state_budget_exceeded")
        finally:
            os.close(fd)
        if _no_link(path).st_ino != before.st_ino:
            raise Error("state_changed")
        try:
            envelope = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_bad_constant)
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise Error("invalid_state") from exc
        _validate_json(envelope, max_bytes=maximum)
        if (not isinstance(envelope, dict) or set(envelope) !=
                {"schema", "transfer_id", "binding", "revision", "state", "owner", "sha256"} or
                envelope["schema"] != STATE_SCHEMA or type(envelope["revision"]) is not int or
                envelope["revision"] < 0 or not isinstance(envelope["owner"], dict) or
                not isinstance(envelope["sha256"], str) or not _HEX.fullmatch(envelope["sha256"])):
            raise Error("invalid_state")
        digest = envelope["sha256"]
        content = {key: value for key, value in envelope.items() if key != "sha256"}
        if hashlib.sha256(canonical_json(content)).hexdigest() != digest:
            raise Error("state_hash_mismatch")
        if canonical_json(envelope) != raw:
            raise Error("invalid_state")
        return envelope

    def load(self, transfer_id: str, expected_binding: dict) -> dict:
        name = _transfer_id(transfer_id)
        binding = _binding(expected_binding, self.policy)
        path = self._state_path(name)
        if not os.path.lexists(path):
            raise Error("task_incomplete")
        envelope = self._read(path)
        if envelope["transfer_id"] != name or envelope["binding"] != binding:
            raise Error("task_binding_conflict")
        return copy.deepcopy(envelope)

    def _encode(self, transfer_id: str, binding: dict, revision: int, state) -> tuple[dict, bytes]:
        maximum = self.policy.limits["max_state_bytes"]
        # Account the full envelope including digest before deepcopy/json.dumps.
        content = {"schema": STATE_SCHEMA, "transfer_id": transfer_id,
                   "binding": binding, "revision": revision,
                   "state": state, "owner": self._owner}
        _validate_json({**content, "sha256": "0" * 64}, max_bytes=maximum)
        self._check()
        content = copy.deepcopy(content)
        envelope = {**content, "sha256": hashlib.sha256(canonical_json(content)).hexdigest()}
        raw = canonical_json(envelope)
        if len(raw) > maximum:
            raise Error("state_budget_exceeded")
        return envelope, raw

    def _commit(self, path: Path, raw: bytes, revision: int) -> None:
        self._require_writer()
        temporary = path.parent / (".state-" + uuid.uuid4().hex + ".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self._require_writer()
            _replace(temporary, path)
            _sync_directory(path.parent)
        except Exception as exc:
            try:
                observed = self._read(path) if path.exists() else None
            except Error:
                observed = None
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            if observed is None:
                raise Error("storage_reconcile_required") from exc
            if observed["revision"] == revision and canonical_json(observed) == raw:
                raise Error("storage_durability_unknown", observed_revision=revision) from exc
            if observed["revision"] < revision:
                raise Error("storage_write_failed", observed_revision=observed["revision"]) from exc
            raise Error("storage_reconcile_required") from exc

    def create(self, transfer_id: str, binding: dict, state) -> dict:
        self._require_writer()
        name = _transfer_id(transfer_id)
        bound = _binding(binding, self.policy)
        if os.path.lexists(self.root / "tasks" / name):
            # Existing valid task wins for the same binding; never reset a partial.
            return self.load(name, bound)
        envelope, raw = self._encode(name, bound, 0, state)
        path = self._state_path(name, create=True)
        self._commit(path, raw, 0)
        return copy.deepcopy(envelope)

    def save(self, transfer_id: str, binding: dict, expected_revision: int, state) -> dict:
        self._require_writer()
        if type(expected_revision) is not int or expected_revision < 0:
            raise Error("invalid_revision")
        existing = self.load(transfer_id, binding)
        if existing["revision"] != expected_revision:
            raise Error("stale_revision", actual_revision=existing["revision"])
        envelope, raw = self._encode(_transfer_id(transfer_id),
                                     _binding(binding, self.policy),
                                     expected_revision + 1, state)
        self._commit(self._state_path(transfer_id), raw, expected_revision + 1)
        return copy.deepcopy(envelope)
