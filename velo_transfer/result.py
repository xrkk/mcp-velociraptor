"""Pure, bounded host result contract. Physical transfer facts belong to the caller."""

from __future__ import annotations

import copy
import json
import re
import uuid
from pathlib import PurePosixPath

from .errors import TransferContentError as Error
from .manifest import _check_collisions, canonical_json, check_relative
from .protocol import validate_destination
from .storage import _validate_json

SCHEMA = "velo.transfer.result.v1"
_FIELDS = frozenset((
    "schema", "outcome", "transfer_id", "request_digest", "direction", "channel",
    "fallback_reason", "source_vm_identity", "destination_identity", "package_sha256",
    "package_size", "manifest_sha256", "resumed_bytes", "files", "source_stability",
    "phase", "last_phase", "published_ever", "destination_verified", "cleanup",
    "publication_receipt_sha256", "warnings", "evidence_index",
))
_PHASES = frozenset(("CREATED", "PREPARING", "READY", "TRANSFERRING", "VERIFYING",
                     "PUBLISHED", "CLEANING", "COMPLETE", "FAILED", "CONFLICT", "CANCELLED"))
_OUTCOMES = {"complete": 0, "rejected": 2, "incomplete": 3, "conflict": 4,
             "cleanup_pending": 5}
_STABILITY = frozenset(("stable_at_required_check", "changed_after_authorized_release",
                        "changed_before_required_check", "unknown"))
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_EVIDENCE_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_REQUIRED_EVIDENCE = frozenset(("publication_receipt", "destination_verification",
                                "host_cleanup", "guest_cleanup"))


def _object(value: object, fields: frozenset[str] | set[str], code: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise Error(code)
    return value


def _digest(value: object, *, optional: bool = True) -> None:
    if value is None and optional:
        return
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise Error("invalid_result_digest")


def _number(value: object) -> None:
    if type(value) is not int or value < 0:
        raise Error("invalid_result_number")


def _path_text(value: object) -> None:
    if (type(value) is not str or not value or len(value) > 32767 or
            any(ord(ch) < 32 or 0x7f <= ord(ch) <= 0x9f or
                0xd800 <= ord(ch) <= 0xdfff for ch in value)):
        raise Error("invalid_result_path")


def _identity(value: object) -> None:
    _object(value, {"vm_uuid", "boot_identity", "vm_epoch"}, "invalid_result_vm_identity")
    try:
        parsed = uuid.UUID(value["vm_uuid"])
        if value["vm_uuid"] != str(parsed):
            raise ValueError()
    except (TypeError, ValueError, AttributeError):
        raise Error("invalid_result_vm_identity") from None
    for key in ("boot_identity", "vm_epoch"):
        item = value[key]
        if type(item) is not str or not item or len(item) > 256 or "\x00" in item:
            raise Error("invalid_result_vm_identity")


def _reference(value: object, max_metadata_bytes: int) -> None:
    _object(value, {"name", "size", "sha256", "device", "inode", "mtime_ns"},
            "invalid_result_evidence")
    if type(value["name"]) is not str or _EVIDENCE_NAME.fullmatch(value["name"]) is None:
        raise Error("invalid_result_evidence")
    _digest(value["sha256"], optional=False)
    for key in ("size", "device", "inode", "mtime_ns"):
        _number(value[key])
    if value["size"] > max_metadata_bytes:
        raise Error("invalid_result_evidence")


def _result_path(value: object) -> None:
    _path_text(value)
    if (not value.startswith("/") or value == "/" or value.startswith("//") or
            "\\" in value or value.endswith("/") or
            any(part in ("", ".", "..") for part in value[1:].split("/")) or
            not PurePosixPath(value).is_absolute()):
        raise Error("invalid_result_path")


def _budget(max_files: object, max_metadata_bytes: object) -> None:
    if (type(max_files) is not int or max_files <= 0 or
            type(max_metadata_bytes) is not int or max_metadata_bytes <= 0):
        raise Error("invalid_result_budget")


def validate_result(document: object, *, max_files: int, max_metadata_bytes: int) -> dict:
    """Validate declared facts only; return an independent JSON value."""
    _budget(max_files, max_metadata_bytes)
    try:
        _validate_json(document, max_bytes=max_metadata_bytes)
        encoded = canonical_json(document)
    except Error as exc:
        raise Error("result_budget_exceeded" if exc.code == "state_budget_exceeded"
                    else "invalid_result_json") from None
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        raise Error("invalid_result_json") from None
    if len(encoded) > max_metadata_bytes:
        raise Error("result_budget_exceeded")
    value = _object(document, _FIELDS, "invalid_result_fields")
    if value["schema"] != SCHEMA or type(value["outcome"]) is not str or value["outcome"] not in _OUTCOMES:
        raise Error("invalid_result_status")
    transfer_id = value["transfer_id"]
    if transfer_id is not None:
        if (type(transfer_id) is not str or _ID.fullmatch(transfer_id) is None or
                transfer_id.startswith("guest-internal-")):
            raise Error("invalid_result_transfer_id")
        check_relative(transfer_id)
    _digest(value["request_digest"])
    direction = value["direction"]
    if direction not in ("push", "pull", None) or (direction is None and value["outcome"] != "rejected"):
        raise Error("invalid_result_direction")
    channel = value["channel"]
    if channel not in ("velo", "windows", None):
        raise Error("invalid_result_channel")
    fallback = value["fallback_reason"]
    if channel == "windows":
        if type(fallback) is not str or _CODE.fullmatch(fallback) is None:
            raise Error("invalid_result_channel")
    elif fallback is not None:
        raise Error("invalid_result_channel")
    source_vm = value["source_vm_identity"]
    if source_vm is not None:
        if direction != "pull":
            raise Error("invalid_result_vm_identity")
        _identity(source_vm)
    destination = value["destination_identity"]
    if destination is not None:
        if direction is None:
            raise Error("invalid_result_destination")
        try:
            validate_destination(destination, direction)
        except Error:
            raise Error("invalid_result_destination") from None
    package = (value["package_sha256"], value["package_size"], value["manifest_sha256"])
    if any(item is None for item in package):
        if not all(item is None for item in package):
            raise Error("invalid_result_package")
        known_package = False
    else:
        _digest(value["package_sha256"], optional=False)
        _digest(value["manifest_sha256"], optional=False)
        _number(value["package_size"])
        known_package = True
    _number(value["resumed_bytes"])
    if (not known_package and value["resumed_bytes"] != 0 or
            known_package and value["resumed_bytes"] > value["package_size"]):
        raise Error("invalid_result_resumed_bytes")
    files = value["files"]
    if type(files) is not list or len(files) > max_files:
        raise Error("result_file_count_exceeded")
    names = []
    for file in files:
        _object(file, {"source", "relative_path", "destination", "size", "sha256"},
                "invalid_result_file")
        _path_text(file["source"])
        _path_text(file["destination"])
        try:
            names.append(check_relative(file["relative_path"]))
        except Error:
            raise Error("invalid_result_file") from None
        _number(file["size"])
        _digest(file["sha256"], optional=False)
    try:
        _check_collisions(names)
    except Error:
        raise Error("result_path_collision") from None
    if type(value["source_stability"]) is not str or value["source_stability"] not in _STABILITY:
        raise Error("invalid_result_stability")
    if (type(value["phase"]) is not str or value["phase"] not in _PHASES or
            value["last_phase"] is not None and
            (type(value["last_phase"]) is not str or value["last_phase"] not in _PHASES)):
        raise Error("invalid_result_phase")
    for key in ("published_ever", "destination_verified"):
        if value[key] is not None and type(value[key]) is not bool:
            raise Error("invalid_result_fact")
    cleanup = _object(value["cleanup"], {"host", "guest"}, "invalid_result_cleanup")
    if any(item is not None and type(item) is not bool for item in cleanup.values()):
        raise Error("invalid_result_cleanup")
    _digest(value["publication_receipt_sha256"])
    warnings = value["warnings"]
    if (type(warnings) is not list or any(type(item) is not str or _CODE.fullmatch(item) is None
                                          for item in warnings) or len(warnings) != len(set(warnings))):
        raise Error("invalid_result_warnings")
    evidence = value["evidence_index"]
    if type(evidence) is not list:
        raise Error("invalid_result_evidence")
    roles = {}
    for item in evidence:
        _object(item, {"role", "reference"}, "invalid_result_evidence")
        role = item["role"]
        if type(role) is not str or _CODE.fullmatch(role) is None or role in roles:
            raise Error("invalid_result_evidence")
        _reference(item["reference"], max_metadata_bytes)
        roles[role] = item["reference"]
    receipt = roles.get("publication_receipt")
    if receipt is not None and receipt["sha256"] != value["publication_receipt_sha256"]:
        raise Error("result_receipt_mismatch")
    # A persisted receipt or a published phase is an affirmative publication
    # fact, including when a later failure changes the current phase.
    published_phases = {"PUBLISHED", "CLEANING", "COMPLETE"}
    publication_known = (value["phase"] in published_phases or
                         value["last_phase"] in published_phases or
                         value["publication_receipt_sha256"] is not None or
                         receipt is not None)
    if publication_known and value["published_ever"] is not True:
        raise Error("result_publication_contradiction")
    if value["published_ever"] is True and any(value[key] is None for key in (
            "transfer_id", "request_digest", "direction", "channel",
            "destination_identity", "package_sha256", "package_size", "manifest_sha256")):
        raise Error("result_publication_binding_missing")
    outcome = value["outcome"]
    if value["phase"] == "COMPLETE" and outcome != "complete":
        raise Error("result_outcome_conflict")
    if outcome == "complete":
        if (value["phase"] != "COMPLETE" or value["published_ever"] is not True or
                value["destination_verified"] is not True or
                cleanup["host"] is not True or cleanup["guest"] is not True or
                value["source_stability"] not in
                ("stable_at_required_check", "changed_after_authorized_release") or
                any(value[key] is None for key in ("transfer_id", "request_digest", "direction",
                                                     "channel", "destination_identity", "package_sha256",
                                                     "package_size", "manifest_sha256",
                                                     "publication_receipt_sha256")) or
                direction == "pull" and source_vm is None or
                not _REQUIRED_EVIDENCE <= roles.keys()):
            raise Error("result_completion_unproven")
    elif outcome == "rejected":
        if (value["phase"] != "FAILED" or value["published_ever"] is not False or
                value["publication_receipt_sha256"] is not None or receipt is not None):
            raise Error("result_outcome_conflict")
    elif outcome == "incomplete":
        pass
    elif outcome == "conflict":
        if value["phase"] not in ("CONFLICT", "FAILED"):
            raise Error("result_outcome_conflict")
    elif outcome == "cleanup_pending":
        if (value["phase"] not in ("PUBLISHED", "CLEANING") or
                value["published_ever"] is not True or
                value["publication_receipt_sha256"] is None or
                cleanup["host"] is True and cleanup["guest"] is True or
                value["destination_verified"] is False):
            raise Error("result_outcome_conflict")
    return copy.deepcopy(value)


def encode_result(document: object, *, max_files: int, max_metadata_bytes: int) -> bytes:
    value = validate_result(document, max_files=max_files, max_metadata_bytes=max_metadata_bytes)
    return canonical_json(value)


def decode_result(raw: bytes, *, max_files: int, max_metadata_bytes: int) -> dict:
    _budget(max_files, max_metadata_bytes)
    if type(raw) is not bytes or len(raw) > max_metadata_bytes:
        raise Error("result_budget_exceeded" if type(raw) is bytes else "invalid_result_json")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Error("duplicate_result_key")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Error("invalid_result_json")))
    except Error:
        raise
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        raise Error("invalid_result_json") from None
    return validate_result(value, max_files=max_files, max_metadata_bytes=max_metadata_bytes)


def result_exit_code(document: object, *, max_files: int, max_metadata_bytes: int) -> int:
    return _OUTCOMES[validate_result(document, max_files=max_files,
                                      max_metadata_bytes=max_metadata_bytes)["outcome"]]


def result_summary(document: object, result_path: str, *, max_files: int,
                   max_metadata_bytes: int) -> dict:
    value = validate_result(document, max_files=max_files, max_metadata_bytes=max_metadata_bytes)
    _result_path(result_path)
    return {"schema": SCHEMA, "transfer_id": value["transfer_id"], "phase": value["phase"],
            "outcome": value["outcome"], "exit_code": _OUTCOMES[value["outcome"]],
            "published_ever": value["published_ever"], "result_path": result_path,
            "file_count": len(value["files"])}
