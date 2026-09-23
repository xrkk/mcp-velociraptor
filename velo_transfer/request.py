"""Pure, bounded host request parsing and guest begin conversion."""

from __future__ import annotations

import copy
import json
import math
import os
import re
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .errors import TransferContentError as Error
from .guest_service import _BUDGET_KEYS, request_digest
from .manifest import Budget, canonical_json, check_relative, digest_json
from .protocol import PROTOCOL_VERSION, validate_destination

SCHEMA = "velo.transfer.request.v1"
MAX_SPEC_BYTES = 1 << 20
_REQUIRED = frozenset(("schema", "direction", "sources", "destination_directory",
                       "connection_profile", "expected_vm_identity", "evidence_context", "budget"))
_OPTIONAL = frozenset(("transfer_id", "resume"))
_BUDGET = _BUDGET_KEYS | {"request_timeout_seconds"}
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_DRIVE = re.compile(r"[A-Za-z]:\\")


def _object(value, keys, code):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise Error(code)


def _text(value, limit, code):
    if not isinstance(value, str) or not value or len(value) > limit or "\x00" in value:
        raise Error(code)
    return value


def _posix(value, code):
    _text(value, 32767, code)
    if not value.startswith("/") or value.startswith("//") or value == "/" or value.endswith("/"):
        raise Error(code)
    try:
        for part in value[1:].split("/"):
            check_relative(part)
    except Error:
        raise Error(code) from None
    return value


def _windows(value, code):
    _text(value, 32767, code)
    if _DRIVE.match(value) is None or value.endswith("\\") or "/" in value:
        raise Error(code)
    try:
        for part in value[3:].split("\\"):
            check_relative(part)
    except Error:
        raise Error(code) from None
    return value


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _read_spec(path: Path) -> bytes:
    try:
        for parent in reversed(path.parents):
            if stat.S_ISLNK(parent.lstat().st_mode):
                raise Error("invalid_spec_file")
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_SPEC_BYTES:
            raise Error("invalid_spec_file" if before.st_size <= MAX_SPEC_BYTES else "spec_too_large")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or _identity(opened) != _identity(before):
                raise Error("spec_changed")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_SPEC_BYTES + 1)
            if len(raw) > MAX_SPEC_BYTES:
                raise Error("spec_too_large")
            final_opened = os.fstat(fd)
            final_path = path.lstat()
            if (final_opened.st_nlink != 1 or final_path.st_nlink != 1 or
                    _identity(final_opened) != _identity(before) or
                    _identity(final_path) != _identity(before)):
                raise Error("spec_changed")
            return raw
        finally:
            os.close(fd)
    except Error:
        raise
    except OSError:
        raise Error("spec_unavailable") from None


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Error("duplicate_json_key")
        result[key] = value
    return result


def _parse(raw):
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Error("invalid_json")))
        # json.loads accepts exponent overflow and escaped lone surrogates.
        # Validate their canonical UTF-8 representation before any field logic.
        canonical_json(value)
        return value
    except Error:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise Error("invalid_json") from None


def _validate_budget(value):
    _object(value, _BUDGET, "invalid_budget")
    for key in _BUDGET_KEYS:
        number = value[key]
        if type(number) is not int or number < (0 if key in ("max_logical_bytes", "min_free_bytes") else 1):
            raise Error("invalid_budget")
    timeout = value["request_timeout_seconds"]
    if (type(timeout) not in (int, float) or timeout <= 0 or timeout > 300 or
            not math.isfinite(timeout) or timeout > value["max_duration_seconds"]):
        raise Error("invalid_budget")


def _validate_document(value):
    if (not isinstance(value, dict) or not _REQUIRED <= set(value) or
            not set(value) <= _REQUIRED | _OPTIONAL or value["schema"] != SCHEMA):
        raise Error("invalid_request")
    direction = value["direction"]
    if direction not in ("push", "pull"):
        raise Error("invalid_direction")
    _validate_budget(value["budget"])
    sources = value["sources"]
    if not isinstance(sources, list) or not sources:
        raise Error("sources_required")
    if len(sources) > value["budget"]["max_files"]:
        raise Error("file_count_exceeded")
    evidence = value["evidence_context"]
    _object(evidence, ("producer_complete", "producer_quiescent", "references"), "producer_evidence_missing")
    refs = evidence["references"]
    if (evidence["producer_complete"] is not True or evidence["producer_quiescent"] is not True or
            not isinstance(refs, list) or not refs or len(refs) > 4096 or
            any(not isinstance(ref, str) or not 1 <= len(ref) <= 512 or "\x00" in ref for ref in refs)):
        raise Error("producer_evidence_missing")
    if len(canonical_json({"sources": sources, "evidence_context": evidence})) > value["budget"]["max_metadata_bytes"]:
        raise Error("metadata_budget_exceeded")
    names = set()
    parents = set()
    for source in sources:
        _object(source, ("absolute_path", "relative_path"), "invalid_source_spec")
        (_posix if direction == "push" else _windows)(source["absolute_path"], "invalid_source_path")
        relative = check_relative(source["relative_path"])
        folded = relative.casefold()
        parts = folded.split("/")
        prefixes = {"/".join(parts[:i]) for i in range(1, len(parts))}
        if folded in names or folded in parents or prefixes & names:
            raise Error("path_collision")
        names.add(folded)
        parents.update(prefixes)
    (_windows if direction == "push" else _posix)(value["destination_directory"], "invalid_destination_path")
    _posix(value["connection_profile"], "invalid_connection_profile")
    expected = value["expected_vm_identity"]
    _object(expected, ("vm_uuid", "boot_identity", "vm_epoch"), "invalid_vm_identity")
    for key in expected:
        _text(expected[key], 256, "invalid_vm_identity")
    try:
        parsed = uuid.UUID(expected["vm_uuid"])
        if expected["vm_uuid"].lower() != str(parsed):
            raise ValueError()
    except (ValueError, AttributeError):
        raise Error("invalid_vm_identity") from None
    expected["vm_uuid"] = str(parsed)
    if "transfer_id" in value:
        transfer_id = value["transfer_id"]
        if (not isinstance(transfer_id, str) or _ID.fullmatch(transfer_id) is None or
                transfer_id.startswith("guest-internal-")):
            raise Error("invalid_transfer_id")
        check_relative(transfer_id)
    elif value.get("resume") is True:
        raise Error("resume_requires_transfer_id")
    else:
        value["transfer_id"] = uuid.uuid4().hex
    if type(value.get("resume", False)) is not bool:
        raise Error("invalid_resume")
    value.setdefault("resume", False)


@dataclass(frozen=True)
class HostRequest:
    spec_path: Path
    work_root: Path
    transfer_id: str
    resume: bool
    intent_digest: str
    request_timeout_seconds: float
    _document_bytes: bytes

    @property
    def document(self) -> dict:
        return json.loads(self._document_bytes)

    @property
    def guest_budget(self) -> dict:
        return {key: self.document["budget"][key] for key in _BUDGET_KEYS}

    def content_budget(self, deadline_monotonic: float) -> Budget:
        try:
            valid = (type(deadline_monotonic) in (int, float) and
                     math.isfinite(deadline_monotonic) and deadline_monotonic > time.monotonic())
        except OverflowError:
            valid = False
        if not valid:
            raise Error("invalid_deadline")
        values = self.guest_budget
        return Budget(values["max_files"], values["max_metadata_bytes"],
                      values["max_logical_bytes"], values["max_package_bytes"],
                      values["min_free_bytes"], deadline_monotonic)


def load_request(absolute_path) -> HostRequest:
    if not isinstance(absolute_path, (str, Path)):
        raise Error("invalid_spec_path")
    spelling = str(absolute_path)
    _posix(spelling, "invalid_spec_path")
    path = Path(spelling)
    value = _parse(_read_spec(path))
    _validate_document(value)
    intent = digest_json({key: item for key, item in value.items() if key not in ("transfer_id", "resume")})
    return HostRequest(path, path.parent / ".velo-transfer", value["transfer_id"], value["resume"],
                       intent, float(value["budget"]["request_timeout_seconds"]), canonical_json(value))


def make_guest_request(request: HostRequest, expected_destination: dict, package: dict | None = None) -> dict:
    if not isinstance(request, HostRequest):
        raise Error("invalid_request")
    document = request.document
    destination = validate_destination(expected_destination, document["direction"])
    try:
        canonical_json(destination)
    except (ValueError, UnicodeError, RecursionError):
        raise Error("invalid_destination") from None
    if destination["canonical_path"] != document["destination_directory"]:
        raise Error("invalid_destination")
    result = {"protocol_version": PROTOCOL_VERSION, "transfer_id": request.transfer_id,
              "direction": document["direction"], "sources": copy.deepcopy(document["sources"]),
              "expected_destination": destination,
              "expected_vm_identity": copy.deepcopy(document["expected_vm_identity"]),
              "evidence_context": copy.deepcopy(document["evidence_context"]),
              "budget": request.guest_budget}
    if document["direction"] == "push":
        _object(package, ("size", "sha256", "manifest_sha256"), "invalid_package_identity")
        if (type(package["size"]) is not int or package["size"] < 0 or
                package["size"] > result["budget"]["max_package_bytes"] or
                any(not isinstance(package[key], str) or _HEX.fullmatch(package[key]) is None
                    for key in ("sha256", "manifest_sha256"))):
            raise Error("invalid_package_identity")
        result["package"] = copy.deepcopy(package)
    elif package is not None:
        raise Error("invalid_package_identity")
    result["request_digest"] = request_digest(result)
    return result
