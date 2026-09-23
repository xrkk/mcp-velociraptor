"""Durable, bounded pull package reception inside an owned HostJournal writer."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from .errors import TransferContentError as Error
from .host_journal import HostJournal, _private
from .manifest import canonical_json
from .protocol import validate_binding
from .request import make_guest_request
from .storage import _sync_directory

SCHEMA = "velo.transfer.host-partial.v1"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_BLOCK = 1 << 20


def _id(info):
    return {"device": info.st_dev, "inode": info.st_ino, "size": info.st_size,
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}


def _node(path, kind):
    try:
        info = _private(path, "task" if kind == "receive" else "state")
    except Error:
        raise Error("partial_ownership_conflict") from None
    if stat.S_IMODE(info.st_mode) != (0o700 if kind == "receive" else 0o600):
        raise Error("partial_ownership_conflict")
    return info


def _open_pair(first_path, first_info, second_path, second_info, write=False):
    first = _open(first_path, first_info, write=write)
    try:
        second = _open(second_path, second_info, write=write)
    except BaseException:
        try:
            os.close(first)
        except OSError:
            pass
        raise
    return first, second


def _open(path, info, write=False):
    flags = (os.O_RDWR if write else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = None
    returned = False
    try:
        fd = os.open(path, flags)
        seen = os.fstat(fd)
        if _id(seen) != _id(info) or seen.st_nlink != 1:
            raise Error("partial_ownership_conflict")
        returned = True
        return fd
    except Error:
        raise
    except OSError:
        raise Error("partial_io_failed") from None
    finally:
        if fd is not None and not returned:
            try:
                os.close(fd)
            except OSError:
                pass


class HostPartial:
    def __init__(self, journal: HostJournal, binding: dict):
        if not isinstance(journal, HostJournal):
            raise Error("invalid_journal")
        self.journal = journal
        self.binding = validate_binding(binding)
        if self.binding["direction"] != "pull":
            raise Error("invalid_binding")
        self.directory = journal.task_dir / "receive"
        self.partial = self.directory / "received.part"
        self.ledger = self.directory / "chunks.jsonl"
        self._continuity = None

    def _load(self):
        self.journal._require_writer(task=True)
        envelope = self.journal.load()
        data = envelope["data"]
        guest = data.get("guest_request")
        if (canonical_json(data.get("binding")) != canonical_json(self.binding) or not isinstance(guest, dict) or
                guest.get("request_digest") != self.binding["request_digest"] or
                guest.get("transfer_id") != self.binding["transfer_id"] or
                guest.get("direction") != "pull" or
                guest.get("expected_vm_identity") != {key: self.binding[key] for key in
                    ("vm_uuid", "boot_identity", "vm_epoch")} or
                self.binding["transfer_id"] != self.journal.request.transfer_id):
            raise Error("partial_binding_conflict")
        try:
            expected = make_guest_request(self.journal.request, guest["expected_destination"])
        except (Error, KeyError, TypeError):
            raise Error("partial_binding_conflict") from None
        if guest != expected:
            raise Error("partial_binding_conflict")
        budget = self.journal.request.content_budget(envelope["deadline_monotonic"])
        budget.check()
        if self.binding["package_size"] > budget.max_package_bytes:
            raise Error("package_budget_exceeded")
        return envelope, budget

    def _save(self, envelope, state):
        fresh = self.journal.load()
        if fresh["revision"] != envelope["revision"] or fresh["data"].get("receive_partial") != envelope["data"].get("receive_partial"):
            raise Error("stale_revision")
        data = fresh["data"]
        data["receive_partial"] = copy.deepcopy(state)
        return self.journal.save(fresh["revision"], data)

    def _state(self, envelope):
        state = envelope["data"].get("receive_partial")
        if state is None:
            return None
        if (not isinstance(state, dict) or set(state) != {"schema", "binding", "phase", "directory",
                "partial", "ledger", "verified_offset", "chunk_count", "ledger_bytes"} or
                state["schema"] != SCHEMA or state["binding"] != self.binding or
                state["phase"] not in ("DIRECTORY", "PARTIAL", "READY") or
                type(state["verified_offset"]) is not int or state["verified_offset"] < 0 or
                type(state["chunk_count"]) is not int or state["chunk_count"] < 0 or
                type(state["ledger_bytes"]) is not int or state["ledger_bytes"] < 0 or
                state["verified_offset"] > self.binding["package_size"]):
            raise Error("partial_state_invalid")
        directory = state["directory"]
        if (not isinstance(directory, dict) or set(directory) != {"path", "device", "inode"} or
                directory["path"] != str(self.directory) or
                any(type(directory[key]) is not int or directory[key] < 0 for key in ("device", "inode"))):
            raise Error("partial_state_invalid")
        for key, path in (("partial", self.partial), ("ledger", self.ledger)):
            record = state[key]
            expected_present = (key == "partial" and state["phase"] != "DIRECTORY") or (
                key == "ledger" and state["phase"] == "READY")
            if expected_present:
                if (not isinstance(record, dict) or set(record) !=
                        {"path", "device", "inode", "size", "mtime_ns", "ctime_ns"} or
                        record["path"] != str(path) or
                        any(type(record[field]) is not int or record[field] < 0 for field in
                            ("device", "inode", "size", "mtime_ns", "ctime_ns"))):
                    raise Error("partial_state_invalid")
            elif record is not None:
                raise Error("partial_state_invalid")
        if state["phase"] != "READY" and any(state[key] != 0 for key in
                ("verified_offset", "chunk_count", "ledger_bytes")):
            raise Error("partial_state_invalid")
        return copy.deepcopy(state)

    def _ownership(self, state):
        result = {"directory": copy.deepcopy(state["directory"]),
                  "received.part": copy.deepcopy(state["partial"]),
                  "chunks.jsonl": copy.deepcopy(state["ledger"])}
        return result

    def _response(self, state):
        return copy.deepcopy({"path": str(self.partial), "verified_offset": state["verified_offset"],
                              "chunk_count": state["chunk_count"], "ownership": self._ownership(state)})

    def _check_owned(self, state):
        directory = _node(self.directory, "receive")
        if state["directory"] != {"path": str(self.directory), "device": directory.st_dev,
                                   "inode": directory.st_ino}:
            raise Error("partial_ownership_conflict")
        observed = {}
        for key, path in (("partial", self.partial), ("ledger", self.ledger)):
            recorded = state[key]
            if recorded is None:
                observed[key] = None
                continue
            info = _node(path, "partial_file")
            if (not isinstance(recorded, dict) or recorded.get("path") != str(path) or
                    (recorded.get("device"), recorded.get("inode")) != (info.st_dev, info.st_ino)):
                raise Error("partial_ownership_conflict")
            observed[key] = info
        return observed

    def _created_file(self, path, fd, directory):
        # The original open descriptor, not a later pathname lookup, anchors
        # registration. A replaced parent or same-name object is not ours.
        parent = _node(self.directory, "receive")
        if (directory != {"path": str(self.directory), "device": parent.st_dev,
                          "inode": parent.st_ino}):
            raise Error("partial_ownership_conflict")
        try:
            opened = os.fstat(fd)
        except OSError:
            raise Error("partial_io_failed") from None
        current = _node(path, "partial_file")
        if (_id(opened) != _id(current) or not stat.S_ISREG(opened.st_mode) or
                opened.st_nlink != 1 or opened.st_uid != os.geteuid() or
                stat.S_IMODE(opened.st_mode) != 0o600):
            raise Error("partial_ownership_conflict")
        return {"path": str(path), **_id(opened)}

    def _new_file(self, path, directory):
        if os.path.lexists(path):
            raise Error("partial_reconcile_required")
        fd = None
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.fsync(fd)
            _sync_directory(path.parent)
            return self._created_file(path, fd, directory), fd
        except BaseException as exc:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if isinstance(exc, OSError):
                raise Error("partial_io_failed") from None
            raise

    def initialize(self):
        envelope, budget = self._load()
        state = self._state(envelope)
        if state is None:
            if os.path.lexists(self.directory):
                raise Error("partial_reconcile_required")
            budget.space(self.journal.task_dir, 0)
            directory_fd = None
            try:
                self.directory.mkdir(mode=0o700)
                directory_fd = os.open(self.directory,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                created = os.fstat(directory_fd)
                _sync_directory(self.journal.task_dir)
                self.journal._require_writer(task=True)
                observed = _node(self.directory, "receive")
                if ((created.st_dev, created.st_ino) != (observed.st_dev, observed.st_ino) or
                        created.st_uid != os.geteuid() or stat.S_IMODE(created.st_mode) != 0o700):
                    raise Error("partial_ownership_conflict")
                state = {"schema": SCHEMA, "binding": copy.deepcopy(self.binding),
                         "phase": "DIRECTORY", "directory": {"path": str(self.directory),
                         "device": created.st_dev, "inode": created.st_ino}, "partial": None,
                         "ledger": None, "verified_offset": 0, "chunk_count": 0, "ledger_bytes": 0}
                envelope = self._save(envelope, state)
                self._check_owned(state)
            except OSError:
                raise Error("partial_io_failed") from None
            finally:
                if directory_fd is not None:
                    os.close(directory_fd)
        if state["phase"] == "DIRECTORY":
            self._check_owned(state)
            record, fd = self._new_file(self.partial, state["directory"])
            try:
                state["partial"] = record
                state["phase"] = "PARTIAL"
                envelope = self._save(envelope, state)
                self._created_file(self.partial, fd, state["directory"])
            finally:
                os.close(fd)
        if state["phase"] == "PARTIAL":
            self._check_owned(state)
            record, fd = self._new_file(self.ledger, state["directory"])
            try:
                state["ledger"] = record
                state["phase"] = "READY"
                envelope = self._save(envelope, state)
                self._created_file(self.ledger, fd, state["directory"])
            finally:
                os.close(fd)
        return self.resume()

    def _ready(self, envelope):
        state = self._state(envelope)
        if state is None or state["phase"] != "READY":
            raise Error("partial_not_initialized")
        return state

    def resume(self):
        envelope, budget = self._load()
        state = self._ready(envelope)
        info = self._check_owned(state)
        pinfo, linfo = info["partial"], info["ledger"]
        if pinfo.st_size < state["verified_offset"] or linfo.st_size < state["ledger_bytes"]:
            raise Error("partial_corrupt")
        if state["ledger_bytes"] > budget.max_metadata_bytes:
            raise Error("metadata_budget_exceeded")
        pfd, lfd = _open_pair(self.partial, pinfo, self.ledger, linfo)
        try:
            position = 0
            ledger_position = 0
            with os.fdopen(os.dup(lfd), "rb") as records:
                for _ in range(state["chunk_count"]):
                    budget.check()
                    line = records.readline(257)
                    ledger_position += len(line)
                    if len(line) > 256 or not line.endswith(b"\n") or ledger_position > state["ledger_bytes"]:
                        raise Error("partial_corrupt")
                    try:
                        record = json.loads(line)
                    except (ValueError, UnicodeError):
                        raise Error("partial_corrupt") from None
                    if (not isinstance(record, dict) or set(record) != {"offset", "size", "sha256"} or
                            type(record["offset"]) is not int or record["offset"] != position or
                            type(record["size"]) is not int or not 0 < record["size"] <=
                            self.journal.request.guest_budget["max_chunk_bytes"] or
                            not isinstance(record["sha256"], str) or _HEX.fullmatch(record["sha256"]) is None or
                            canonical_json(record) + b"\n" != line):
                        raise Error("partial_corrupt")
                    digest = hashlib.sha256()
                    left = record["size"]
                    while left:
                        budget.check()
                        piece = os.read(pfd, min(left, _BLOCK))
                        if not piece:
                            raise Error("partial_corrupt")
                        digest.update(piece)
                        left -= len(piece)
                    if digest.hexdigest() != record["sha256"]:
                        raise Error("partial_corrupt")
                    position += record["size"]
            if position != state["verified_offset"] or ledger_position != state["ledger_bytes"]:
                raise Error("partial_corrupt")
            if (_id(os.fstat(pfd)) != _id(pinfo) or _id(os.fstat(lfd)) != _id(linfo) or
                    _id(_node(self.partial, "partial_file")) != _id(pinfo) or
                    _id(_node(self.ledger, "partial_file")) != _id(linfo)):
                raise Error("partial_changed")
        except OSError:
            raise Error("partial_io_failed") from None
        finally:
            os.close(pfd)
            os.close(lfd)
        budget.check()
        if pinfo.st_size > position or linfo.st_size > ledger_position:
            pfd, lfd = _open_pair(self.partial, pinfo, self.ledger, linfo, write=True)
            try:
                if pinfo.st_size > position:
                    os.ftruncate(pfd, position)
                    os.fsync(pfd)
                if linfo.st_size > ledger_position:
                    os.ftruncate(lfd, ledger_position)
                    os.fsync(lfd)
            except OSError:
                raise Error("partial_io_failed") from None
            finally:
                os.close(pfd)
                os.close(lfd)
        current = self._check_owned(state)
        state["partial"] = {"path": str(self.partial), **_id(current["partial"])}
        state["ledger"] = {"path": str(self.ledger), **_id(current["ledger"])}
        if state != envelope["data"]["receive_partial"]:
            budget.check()
        self._save(envelope, state)
        self._continuity = (state["verified_offset"], state["chunk_count"],
                            state["ledger_bytes"], _id(current["partial"]), _id(current["ledger"]))
        return self._response(state)

    def append(self, offset: int, data: bytes, chunk_sha256: str):
        if type(offset) is not int or offset < 0 or type(data) is not bytes or not data or not isinstance(chunk_sha256, str) or _HEX.fullmatch(chunk_sha256) is None:
            raise Error("invalid_chunk")
        envelope, budget = self._load()
        state = self._ready(envelope)
        if len(data) > self.journal.request.guest_budget["max_chunk_bytes"] or offset + len(data) > self.binding["package_size"]:
            raise Error("chunk_budget_exceeded")
        if hashlib.sha256(data).hexdigest() != chunk_sha256:
            raise Error("chunk_hash_mismatch")
        if self._continuity is None:
            self.resume()
            envelope, budget = self._load()
            state = self._ready(envelope)
        info = self._check_owned(state)
        fingerprint = (state["verified_offset"], state["chunk_count"], state["ledger_bytes"],
                       _id(info["partial"]), _id(info["ledger"]))
        if fingerprint != self._continuity:
            self.resume()
            envelope, budget = self._load()
            state = self._ready(envelope)
            info = self._check_owned(state)
        if offset < state["verified_offset"]:
            return self._replay(state, offset, data, chunk_sha256, budget)
        if offset != state["verified_offset"]:
            raise Error("chunk_offset_conflict")
        line = canonical_json({"offset": offset, "size": len(data), "sha256": chunk_sha256}) + b"\n"
        if state["ledger_bytes"] + len(line) > budget.max_metadata_bytes:
            raise Error("metadata_budget_exceeded")
        budget.space(self.directory, len(data) + len(line))
        pfd, lfd = _open_pair(self.partial, info["partial"], self.ledger, info["ledger"], write=True)
        try:
            if os.fstat(pfd).st_size != offset or os.fstat(lfd).st_size != state["ledger_bytes"]:
                raise Error("partial_changed")
            os.lseek(pfd, offset, os.SEEK_SET)
            if os.write(pfd, data) != len(data):
                raise Error("partial_io_failed")
            os.fsync(pfd)
            os.lseek(lfd, state["ledger_bytes"], os.SEEK_SET)
            if os.write(lfd, line) != len(line):
                raise Error("partial_io_failed")
            os.fsync(lfd)
            pinfo, linfo = os.fstat(pfd), os.fstat(lfd)
            if (_id(_node(self.partial, "partial_file")) != _id(pinfo) or
                    _id(_node(self.ledger, "partial_file")) != _id(linfo)):
                raise Error("partial_changed")
        except OSError:
            raise Error("partial_io_failed") from None
        finally:
            os.close(pfd)
            os.close(lfd)
        state["verified_offset"] += len(data)
        state["chunk_count"] += 1
        state["ledger_bytes"] += len(line)
        state["partial"] = {"path": str(self.partial), **_id(pinfo)}
        state["ledger"] = {"path": str(self.ledger), **_id(linfo)}
        budget.check()
        self._save(envelope, state)
        self._continuity = (state["verified_offset"], state["chunk_count"],
                            state["ledger_bytes"], _id(pinfo), _id(linfo))
        return self._response(state)

    def _replay(self, state, offset, data, digest, budget):
        # Re-anchor at the durable owner and this append's continuity check.
        owned = self._check_owned(state)
        pinfo, linfo = owned["partial"], owned["ledger"]
        observed = (state["verified_offset"], state["chunk_count"], state["ledger_bytes"],
                    _id(pinfo), _id(linfo))
        if observed != self._continuity:
            raise Error("partial_changed")
        pfd, lfd = _open_pair(self.partial, pinfo, self.ledger, linfo)
        try:
            with os.fdopen(os.dup(lfd), "rb") as records:
                for _ in range(state["chunk_count"]):
                    budget.check()
                    line = records.readline(257)
                    if len(line) > 256:
                        raise Error("partial_corrupt")
                    record = json.loads(line)
                    if record["offset"] == offset:
                        if record != {"offset": offset, "size": len(data), "sha256": digest}:
                            raise Error("chunk_replay_conflict")
                        if os.pread(pfd, len(data), offset) != data:
                            raise Error("chunk_replay_conflict")
                        if (_id(os.fstat(pfd)) != _id(pinfo) or _id(os.fstat(lfd)) != _id(linfo) or
                                _id(_node(self.partial, "partial_file")) != _id(pinfo) or
                                _id(_node(self.ledger, "partial_file")) != _id(linfo)):
                            raise Error("partial_changed")
                        return self._response(state)
        except (ValueError, KeyError, TypeError, OSError):
            raise Error("partial_corrupt") from None
        finally:
            os.close(pfd)
            os.close(lfd)
        raise Error("chunk_offset_conflict")

    def verify(self):
        self.resume()
        envelope, budget = self._load()
        state = self._ready(envelope)
        if state["verified_offset"] != self.binding["package_size"]:
            raise Error("package_incomplete")
        info = self._check_owned(state)["partial"]
        fd = _open(self.partial, info)
        digest = hashlib.sha256()
        byte_count = 0
        try:
            while True:
                budget.check()
                piece = os.read(fd, _BLOCK)
                if not piece:
                    break
                byte_count += len(piece)
                digest.update(piece)
            if (_id(os.fstat(fd)) != _id(info) or _id(_node(self.partial, "partial_file")) != _id(info)):
                raise Error("partial_changed")
        except OSError:
            raise Error("partial_io_failed") from None
        finally:
            os.close(fd)
        budget.check()
        if (info.st_size != self.binding["package_size"] or
                byte_count != info.st_size or byte_count != self.binding["package_size"]):
            raise Error("package_size_mismatch")
        if digest.hexdigest() != self.binding["package_sha256"]:
            raise Error("package_hash_mismatch")
        return copy.deepcopy({"path": str(self.partial), "size": info.st_size,
                              "sha256": digest.hexdigest(),
                              "expected_manifest_sha256": self.binding["manifest_sha256"],
                              "ownership": self._ownership(state)})
