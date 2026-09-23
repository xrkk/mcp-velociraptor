"""Private, bounded Linux host journal; physical transfer facts belong to its caller."""

from __future__ import annotations

import copy
import fcntl
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
from .filesystem import _rename_noreplace
from .manifest import canonical_json, digest_json
from .request import HostRequest, MAX_SPEC_BYTES
from .storage import _sync_directory, _validate_json

SCHEMA = "velo.transfer.host-journal.v1"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_PHASES = frozenset(("CREATED", "PREPARING", "READY", "TRANSFERRING", "VERIFYING",
                     "PUBLISHED", "CLEANING", "COMPLETE", "FAILED", "CONFLICT", "CANCELLED"))
_STICKY = stat.S_ISVTX
_IMMUTABLE = frozenset(("guest_request", "binding", "prepare_receipt", "source_validation_receipt",
                        "publication_receipt", "publish_intent"))


def observe_host_identity() -> dict[str, str]:
    """Read only the fixed Linux machine and boot identity files."""
    if os.name != "posix":
        raise Error("unsupported_host")
    try:
        def fixed(path):
            with Path(path).open("rb") as stream:
                raw = stream.read(129)
            if len(raw) > 128:
                raise ValueError()
            return raw.decode("ascii").removesuffix("\n")
        machine = fixed("/etc/machine-id")
        boot = fixed("/proc/sys/kernel/random/boot_id")
    except (OSError, UnicodeError, ValueError):
        raise Error("host_identity_unavailable") from None
    return _host_identity({"machine_id": machine, "boot_id": boot})


def _host_identity(value) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"machine_id", "boot_id"}:
        raise Error("invalid_host_identity")
    if (not isinstance(value["machine_id"], str) or
            re.fullmatch(r"[0-9a-f]{32}", value["machine_id"]) is None):
        raise Error("invalid_host_identity")
    try:
        parsed = uuid.UUID(value["boot_id"])
        if value["boot_id"] != str(parsed):
            raise ValueError()
    except (TypeError, ValueError, AttributeError):
        raise Error("invalid_host_identity") from None
    return dict(value)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _dir_id(info):
    return (info.st_dev, info.st_ino)


def _finite_deadline(value) -> bool:
    if type(value) is int:
        return value.bit_length() <= 53
    return type(value) is float and math.isfinite(value)


def _object(value, keys, code):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise Error(code)


def _decode(raw: bytes, maximum: int):
    if len(raw) > maximum:
        raise Error("state_budget_exceeded")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Error("duplicate_state_key")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Error("invalid_state")))
        _validate_json(value, max_bytes=maximum)
        if canonical_json(value) != raw:
            raise Error("invalid_state")
        return value
    except Error:
        raise
    except (UnicodeError, ValueError, OverflowError, RecursionError):
        raise Error("invalid_state") from None


def _check_parent_chain(parent: Path):
    uid = os.geteuid()
    chain = [Path("/")] + list(reversed(parent.parents[:-1])) + [parent]
    for path in chain:
        try:
            info = path.lstat()
        except OSError:
            raise Error("untrusted_ancestor") from None
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, uid):
            raise Error("untrusted_ancestor")
    for index, path in enumerate(chain[:-1]):
        info = path.lstat()
        if info.st_mode & 0o022:
            child = chain[index + 1].lstat()
            if not (info.st_uid == 0 and info.st_mode & _STICKY and
                    child.st_uid == uid and not child.st_mode & 0o077):
                raise Error("untrusted_ancestor")
    last = parent.lstat()
    if last.st_mode & 0o022:
        raise Error("untrusted_ancestor")


def _private(path: Path, kind: str):
    try:
        info = path.lstat()
    except OSError:
        raise Error(kind + "_missing") from None
    if stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise Error(kind + "_unsafe")
    if kind in ("root", "tasks", "task", "evidence"):
        if not stat.S_ISDIR(info.st_mode):
            raise Error(kind + "_unsafe")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Error(kind + "_unsafe")
    return info


def _read_file(path: Path, maximum: int, kind: str) -> tuple[bytes, os.stat_result]:
    before = _private(path, kind)
    if before.st_size > maximum:
        raise Error(kind + "_budget_exceeded")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            if _identity(opened) != _identity(before) or opened.st_nlink != 1:
                raise Error(kind + "_changed")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(maximum + 1)
            after = os.fstat(fd)
            final = _private(path, kind)
            if len(raw) > maximum or len(raw) != before.st_size:
                raise Error(kind + "_budget_exceeded")
            if _identity(after) != _identity(before) or _identity(final) != _identity(before):
                raise Error(kind + "_changed")
            return raw, before
        finally:
            os.close(fd)
    except Error:
        raise
    except OSError:
        raise Error(kind + "_unavailable") from None


def _checked_temporary(path: Path, fd: int, written, expected_size: int, kind: str):
    current = _private(path, kind)
    opened = os.fstat(fd)
    if (written.st_size != expected_size or written.st_nlink != 1 or
            _identity(current) != _identity(written) or
            _identity(opened) != _identity(written) or opened.st_nlink != 1):
        raise Error("temporary_changed")


def _phase_data(data, previous=None, *, initial=False):
    if not isinstance(data, dict) or type(data.get("phase")) is not str or data["phase"] not in _PHASES:
        raise Error("invalid_phase")
    for key in ("published_ever", "begin_attempted"):
        if type(data.get(key)) is not bool:
            raise Error("invalid_journal_data")
    if ("last_phase" in data and
            (type(data["last_phase"]) is not str or data["last_phase"] not in _PHASES)):
        raise Error("invalid_phase")
    channel = data.get("channel")
    if channel is not None and channel not in ("velo", "windows"):
        raise Error("invalid_channel")
    if data["begin_attempted"] and channel is None:
        raise Error("invalid_channel")
    if initial:
        if (data["phase"] != "CREATED" or data["published_ever"] or
                data["begin_attempted"] or channel is not None):
            raise Error("invalid_initial_state")
    elif previous is not None:
        if previous["published_ever"] and not data["published_ever"]:
            raise Error("published_fact_lost")
        if previous["begin_attempted"] and not data["begin_attempted"]:
            raise Error("begin_fact_lost")
        if previous["begin_attempted"] and previous["channel"] != channel:
            raise Error("channel_changed")
        for key in _IMMUTABLE:
            if key in previous and previous[key] is not None:
                if key not in data or canonical_json(previous[key]) != canonical_json(data[key]):
                    raise Error("immutable_fact_changed")
    if data["phase"] == "COMPLETE":
        completion = data.get("completion")
        if (not data["published_ever"] or data.get("publication_receipt") is None or
                not isinstance(completion, dict) or set(completion) !=
                {"destination_verified", "guest_cleanup_complete", "host_cleanup_complete"} or
                any(completion[key] is not True for key in completion)):
            raise Error("completion_unproven")


class HostJournal:
    def __init__(self, request: HostRequest, host_identity: dict):
        if (not isinstance(request, HostRequest) or not isinstance(request.spec_path, Path) or
                not request.spec_path.is_absolute() or not isinstance(request.work_root, Path) or
                not request.work_root.is_absolute() or type(request.resume) is not bool):
            raise Error("invalid_request")
        try:
            document = request.document
            if (not isinstance(document, dict) or canonical_json(document) != request._document_bytes or
                    not isinstance(document.get("budget"), dict) or
                    not isinstance(document.get("expected_vm_identity"), dict) or
                    type(document["budget"].get("max_metadata_bytes")) is not int or
                    document["budget"]["max_metadata_bytes"] <= 0 or
                    type(document["budget"].get("max_files")) is not int or
                    document["budget"]["max_files"] <= 0):
                raise Error("invalid_request")
        except (ValueError, UnicodeError, TypeError, RecursionError, KeyError):
            raise Error("invalid_request") from None
        if (request.work_root != request.spec_path.parent / ".velo-transfer" or
                request.transfer_id != document.get("transfer_id") or
                request.resume != document.get("resume") or
                not isinstance(request.transfer_id, str) or
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", request.transfer_id) is None or
                request.intent_digest != digest_json({k: v for k, v in document.items()
                                                     if k not in ("transfer_id", "resume")})):
            raise Error("invalid_request")
        self.request = request
        self.root = request.work_root
        self.tasks = self.root / "tasks"
        self.task_dir = self.tasks / request.transfer_id
        self.state_path = self.task_dir / "state.json"
        self.lock_path = self.root / ".host-writer.lock"
        self.limit = document["budget"]["max_metadata_bytes"] + 2 * MAX_SPEC_BYTES
        self.evidence_limit = document["budget"]["max_metadata_bytes"]
        self.max_evidence_files = min(document["budget"]["max_files"] + 32, self.evidence_limit)
        self.binding = {"intent_digest": request.intent_digest,
                        "spec_path": str(request.spec_path), "work_root": str(request.work_root),
                        "transfer_id": request.transfer_id,
                        "expected_vm_identity": copy.deepcopy(document["expected_vm_identity"]),
                        "host_identity": _host_identity(host_identity), "state_limit": self.limit}
        self._lock_fd = None
        self._ids = {}
        self._created = False
        self._state_id = None

    def _directory(self, path: Path, kind: str, *, create=False):
        if create and not os.path.lexists(path):
            try:
                path.mkdir(mode=0o700)
                _sync_directory(path.parent)
            except FileExistsError:
                # Another first initializer may have won creation; validate it.
                pass
            except OSError:
                raise Error(kind + "_unavailable") from None
        info = _private(path, kind)
        identity = _dir_id(info)
        old = self._ids.get(kind)
        if old is not None and old != identity:
            raise Error(kind + "_changed")
        self._ids[kind] = identity
        return path

    def _check_dirs(self, *, task=False, evidence=False):
        _check_parent_chain(self.root.parent)
        self._directory(self.root, "root")
        self._directory(self.tasks, "tasks")
        if task:
            self._directory(self.task_dir, "task")
        if evidence:
            self._directory(self.task_dir / "evidence", "evidence")

    @contextmanager
    def writer(self):
        if os.name != "posix":
            raise Error("unsupported_host")
        if self._lock_fd is not None:
            raise Error("writer_lock_held")
        _check_parent_chain(self.root.parent)
        if self.request.resume and (not os.path.lexists(self.root) or not os.path.lexists(self.tasks)):
            raise Error("task_not_found")
        tasks_existed = os.path.lexists(self.tasks)
        if tasks_existed and not os.path.lexists(self.lock_path):
            raise Error("writer_lock_changed")
        self._directory(self.root, "root", create=not self.request.resume)
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
        try:
            fd = os.open(self.lock_path, flags, 0o600)
        except OSError:
            raise Error("writer_lock_unavailable") from None
        locked = False
        try:
            opened = os.fstat(fd)
            current = _private(self.lock_path, "lock")
            if _identity(opened) != _identity(current):
                raise Error("writer_lock_changed")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Error("writer_busy") from None
            locked = True
            self._lock_fd = fd
            identity = _dir_id(opened)
            if "lock" in self._ids and self._ids["lock"] != identity:
                raise Error("writer_lock_changed")
            self._ids["lock"] = identity
            self._directory(self.root, "root")
            if not tasks_existed:
                try:
                    _sync_directory(self.root)
                except OSError:
                    raise Error("writer_lock_unavailable") from None
            self._directory(self.tasks, "tasks", create=not self.request.resume)
            self._check_dirs()
            yield self
        finally:
            self._lock_fd = None
            if locked:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _require_writer(self, *, task=False, evidence=False):
        if self._lock_fd is None:
            raise Error("writer_lock_required")
        self._check_dirs(task=task, evidence=evidence)
        opened = os.fstat(self._lock_fd)
        current = _private(self.lock_path, "lock")
        if _dir_id(opened) != self._ids["lock"] or _identity(opened) != _identity(current):
            raise Error("writer_lock_changed")

    def _encode(self, revision: int, deadline: float, data: dict):
        content = {"schema": SCHEMA, "transfer_id": self.request.transfer_id,
                   "binding": self.binding, "deadline_monotonic": deadline,
                   "revision": revision, "data": data}
        _validate_json({**content, "sha256": "0" * 64}, max_bytes=self.limit)
        content = copy.deepcopy(content)
        envelope = {**content, "sha256": digest_json(content)}
        raw = canonical_json(envelope)
        if len(raw) > self.limit:
            raise Error("state_budget_exceeded")
        return envelope, raw

    def _read_state(self):
        self._require_writer(task=True)
        if not os.path.lexists(self.state_path):
            raise Error("task_incomplete")
        raw, info = _read_file(self.state_path, self.limit, "state")
        value = _decode(raw, self.limit)
        if (not isinstance(value, dict) or set(value) !=
                {"schema", "transfer_id", "binding", "deadline_monotonic", "revision", "data", "sha256"} or
                value["schema"] != SCHEMA or type(value["revision"]) is not int or value["revision"] < 0 or
                not _finite_deadline(value["deadline_monotonic"]) or
                value["deadline_monotonic"] <= 0 or
                not isinstance(value["sha256"], str) or _HEX.fullmatch(value["sha256"]) is None):
            raise Error("invalid_state")
        content = {k: v for k, v in value.items() if k != "sha256"}
        if digest_json(content) != value["sha256"]:
            raise Error("state_hash_mismatch")
        if (value["transfer_id"] != self.request.transfer_id or
                canonical_json(value["binding"]) != canonical_json(self.binding)):
            if (isinstance(value["binding"], dict) and
                    value["binding"].get("host_identity") != self.binding["host_identity"]):
                raise Error("host_identity_mismatch")
            raise Error("task_binding_conflict")
        _phase_data(value["data"])
        identity = _dir_id(info)
        if self._state_id is not None and self._state_id != identity:
            raise Error("state_changed")
        self._state_id = identity
        return value

    def _commit(self, path: Path, raw: bytes, revision: int, *, initial=False):
        self._require_writer(task=True)
        previous = None
        if not initial:
            previous = _private(path, "state")
            if self._state_id is not None and _dir_id(previous) != self._state_id:
                raise Error("state_changed")
        elif os.path.lexists(path):
            raise Error("resume_required")
        temp = path.parent / (".state-" + uuid.uuid4().hex + ".tmp")
        fd = None
        temp_id = None
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            temp_id = _dir_id(os.fstat(fd))
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
                written = os.fstat(fd)
            self._require_writer(task=True)
            _checked_temporary(temp, fd, written, len(raw), "state")
            if initial:
                if os.path.lexists(path):
                    raise Error("resume_required")
                _rename_noreplace(temp, path)
            else:
                current = _private(path, "state")
                if _identity(current) != _identity(previous):
                    raise Error("state_changed")
                os.replace(temp, path)
            if _identity(_private(path, "state")) != _identity(written):
                raise Error("state_changed")
            _sync_directory(path.parent)
            self._state_id = _dir_id(_private(path, "state"))
        except BaseException as exc:
            self._state_id = None
            try:
                observed = self._read_state() if os.path.lexists(path) else None
            except (Error, OSError):
                observed = None
            try:
                if temp_id is not None and _dir_id(temp.lstat()) == temp_id:
                    temp.unlink()
            except OSError:
                pass
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            if observed is None:
                raise Error("storage_reconcile_required") from None
            if observed["revision"] == revision and canonical_json(observed) == raw:
                raise Error("storage_durability_unknown", observed_revision=revision) from None
            if observed["revision"] < revision:
                raise Error("storage_write_failed", observed_revision=observed["revision"]) from None
            raise Error("storage_reconcile_required") from None
        finally:
            if fd is not None:
                os.close(fd)

    def create(self, deadline_monotonic: float, data: dict) -> dict:
        self._require_writer()
        if self.request.resume:
            raise Error("resume_required")
        if (not _finite_deadline(deadline_monotonic) or
                deadline_monotonic <= time.monotonic() or
                deadline_monotonic > time.monotonic() + self.request.document["budget"]["max_duration_seconds"]):
            raise Error("invalid_deadline")
        _phase_data(data, initial=True)
        envelope, raw = self._encode(0, deadline_monotonic, data)
        if os.path.lexists(self.task_dir):
            raise Error("resume_required")
        self._directory(self.task_dir, "task", create=True)
        self._commit(self.state_path, raw, 0, initial=True)
        self._created = True
        return copy.deepcopy(envelope)

    def load(self) -> dict:
        self._require_writer()
        if not self.request.resume and not self._created:
            raise Error("resume_required")
        if not os.path.lexists(self.task_dir):
            raise Error("task_not_found")
        return copy.deepcopy(self._read_state())

    def save(self, expected_revision: int, data: dict) -> dict:
        self._require_writer()
        if type(expected_revision) is not int or expected_revision < 0:
            raise Error("invalid_revision")
        old = self.load()
        if old["revision"] != expected_revision:
            raise Error("stale_revision", actual_revision=old["revision"])
        _validate_json(data, max_bytes=self.limit)
        _phase_data(data, old["data"])
        envelope, raw = self._encode(expected_revision + 1, old["deadline_monotonic"], data)
        self._commit(self.state_path, raw, expected_revision + 1)
        return copy.deepcopy(envelope)

    def _evidence_path(self, name: str):
        if not isinstance(name, str) or _NAME.fullmatch(name) is None:
            raise Error("invalid_evidence_name")
        return self.task_dir / "evidence" / (name + ".json")

    def write_evidence(self, name: str, value) -> dict:
        self._require_writer(task=True)
        path = self._evidence_path(name)
        _validate_json(value, max_bytes=self.evidence_limit)
        raw = canonical_json(value)
        if len(raw) > self.evidence_limit:
            raise Error("state_budget_exceeded")
        self._directory(path.parent, "evidence", create=True)
        self._require_writer(task=True, evidence=True)
        if os.path.lexists(path):
            current, info = _read_file(path, self.evidence_limit, "evidence_file")
            if current != raw:
                raise Error("evidence_conflict")
            try:
                _sync_directory(path.parent)
            except OSError:
                raise Error("evidence_durability_unknown") from None
            repeated, after = _read_file(path, self.evidence_limit, "evidence_file")
            if repeated != raw or _identity(after) != _identity(info):
                raise Error("evidence_changed")
            return self._evidence_ref(name, raw, after)
        try:
            with os.scandir(path.parent) as entries:
                count = 0
                for _ in entries:
                    count += 1
                    if count >= self.max_evidence_files:
                        raise Error("evidence_collection_exceeded")
        except OSError:
            raise Error("evidence_unavailable") from None
        temp = path.parent / (".evidence-" + uuid.uuid4().hex + ".tmp")
        fd = None
        temp_id = None
        published = False
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            temp_id = _dir_id(os.fstat(fd))
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
                written = os.fstat(fd)
            self._require_writer(task=True, evidence=True)
            _checked_temporary(temp, fd, written, len(raw), "evidence_file")
            _rename_noreplace(temp, path)
            published = True
            if _identity(_private(path, "evidence_file")) != _identity(written):
                raise Error("evidence_reconcile_required")
            _sync_directory(path.parent)
        except OSError:
            if published:
                raise Error("evidence_durability_unknown") from None
            raise Error("evidence_write_failed") from None
        finally:
            if fd is not None:
                os.close(fd)
            try:
                if temp_id is not None and _dir_id(temp.lstat()) == temp_id:
                    temp.unlink()
            except OSError:
                pass
        stored, info = _read_file(path, self.evidence_limit, "evidence_file")
        if stored != raw:
            raise Error("evidence_reconcile_required")
        return self._evidence_ref(name, raw, info)

    @staticmethod
    def _evidence_ref(name, raw, info):
        return {"name": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                "device": info.st_dev, "inode": info.st_ino, "mtime_ns": info.st_mtime_ns}

    def read_evidence(self, ref: dict):
        self._require_writer(task=True, evidence=True)
        _object(ref, ("name", "size", "sha256", "device", "inode", "mtime_ns"), "invalid_evidence_ref")
        path = self._evidence_path(ref["name"])
        if (type(ref["size"]) is not int or not 0 <= ref["size"] <= self.evidence_limit or
                type(ref["device"]) is not int or type(ref["inode"]) is not int or
                type(ref["mtime_ns"]) is not int or
                not isinstance(ref["sha256"], str) or _HEX.fullmatch(ref["sha256"]) is None):
            raise Error("invalid_evidence_ref")
        raw, info = _read_file(path, self.evidence_limit, "evidence_file")
        if self._evidence_ref(ref["name"], raw, info) != ref:
            raise Error("evidence_changed")
        return copy.deepcopy(_decode(raw, self.evidence_limit))
