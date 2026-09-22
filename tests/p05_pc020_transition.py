"""Single-use PC020 schema5/epoch6 to schema6/epoch7 transition writer.

This module is a callable writer, not a selector or an arbitrary state editor.
It consumes already-signed preparation and migration bundles through the
reviewed read-only validators.  It never operates a VM or selects a snapshot.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from tests import p05_pc020_evidence as evidence
from tests import pc022_windows_refresh


INTENT_KEYS = {
    "schema_version", "kind", "workflow_id", "transition_id",
    "from_sha256", "next_sha256", "created_at",
}
RECEIPT_KEYS = {
    "schema_version", "kind", "workflow_id", "transition_id",
    "from_sha256", "to_sha256", "next_sha256", "started_at",
    "replaced_at", "directory_fsynced_at", "readback_at", "status", "error",
}
FAILED_BEFORE_REPLACE = "FAILED_BEFORE_REPLACE"
TRANSITION_INDETERMINATE = "TRANSITION_INDETERMINATE"
COMMITTED = "COMMITTED"


class Pc020TransitionError(RuntimeError):
    """The one migration did not produce a fully receipted commit."""

    def __init__(self, message: str, outcome: "TransitionOutcome"):
        super().__init__(message)
        self.outcome = outcome


@dataclass(frozen=True)
class TransitionOutcome:
    status: str
    transition_id: str
    canonical_path: Path
    next_path: Path
    intent_path: Path
    receipt_path: Path
    isolation_path: Path | None
    from_sha256: str
    to_sha256: str | None
    next_sha256: str | None
    receipt_written: bool


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _read_bytes(path: Path) -> bytes:
    return path.read_bytes()


def _open_exclusive(path: Path) -> BinaryIO:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(path, flags, 0o600)
    return os.fdopen(descriptor, "wb")


def _write_all(handle: BinaryIO, payload: bytes, path: Path) -> None:
    view = memoryview(payload)
    written = 0
    while written < len(payload):
        count = handle.write(view[written:])
        if count is None or count <= 0:
            raise OSError(f"short write for {path.name}")
        written += count


def _flush_file(handle: BinaryIO, path: Path) -> None:
    handle.flush()


def _fsync_file(handle: BinaryIO, path: Path) -> None:
    os.fsync(handle.fileno())


def _close_file(handle: BinaryIO, path: Path) -> None:
    handle.close()


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        pc022_windows_refresh.windows_refresh_directory(path)
        return
    # PC022: the audited Windows path rejected os.open(directory, O_RDONLY)
    # (errno 13); no POSIX directory sync may be presented as a production
    # fallback, so the writer fails closed off Windows.
    raise pc022_windows_refresh.Pc022WindowsRefreshError(
        "platform",
        "directory refresh is only implemented for the Windows production path",
    )


def _replace(source: Path, target: Path) -> None:
    if os.name == "nt":
        pc022_windows_refresh.windows_replace_file(source, target)
        return
    raise pc022_windows_refresh.Pc022WindowsRefreshError(
        "platform",
        "atomic replace is only implemented for the Windows production path",
    )


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _canonical_uuid(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise evidence.Pc020EvidenceError(f"{label} is not a canonical UUID")
    try:
        canonical = str(uuid.UUID(value))
    except ValueError as exc:
        raise evidence.Pc020EvidenceError(f"{label} is not a canonical UUID") from exc
    if canonical != value:
        raise evidence.Pc020EvidenceError(f"{label} is not a canonical UUID")
    return value


def _plain_directory(path: Path, label: str) -> None:
    current = path
    while True:
        try:
            info = current.lstat()
        except OSError as exc:
            raise evidence.Pc020EvidenceError(f"{label} is unavailable") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise evidence.Pc020EvidenceError(f"{label} traverses a link/reparse or non-directory")
        if current.parent == current:
            return
        current = current.parent


def _plain_file(path: Path, label: str) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        raise evidence.Pc020EvidenceError(f"{label} must be an absolute path")
    _plain_directory(path.parent, f"{label} parent")
    try:
        info = path.lstat()
    except OSError as exc:
        raise evidence.Pc020EvidenceError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & 0x400
    ):
        raise evidence.Pc020EvidenceError(f"{label} is not a plain file")


def _output_paths(canonical_path: Path, transition_id: str) -> tuple[Path, Path, Path, Path]:
    parent = canonical_path.parent
    base = canonical_path.name
    return (
        Path(str(canonical_path) + ".next"),
        parent / f"{base}.{transition_id}.pc020-intent.json",
        parent / f"{base}.{transition_id}.pc020-receipt.json",
        parent / f"{base}.next.{transition_id}.failed-before-replace",
    )


def _create_durable(path: Path, payload: bytes) -> None:
    handle: BinaryIO | None = None
    try:
        handle = _open_exclusive(path)
        _write_all(handle, payload, path)
        _flush_file(handle, path)
        _fsync_file(handle, path)
        _close_file(handle, path)
        handle = None
        _fsync_directory(path.parent)
    finally:
        if handle is not None and not handle.closed:
            try:
                handle.close()
            except OSError:
                pass


def _persist_exact(path: Path, document: dict[str, Any]) -> bytes:
    payload = evidence.canonical_json(document)
    _create_durable(path, payload)
    if _read_bytes(path) != payload:
        raise evidence.Pc020EvidenceError(f"{path.name} durable readback differs")
    return payload


def _validate_predecessor_shape(document: Any) -> dict[str, Any]:
    keys = {
        "schema_version", "workflow_id", "epoch", "phase", "active_snapshot",
        "automatic_restore_allowlist", "retired_snapshots", "baseline_evidence",
        "activation_evidence",
    }
    if not isinstance(document, dict) or set(document) != keys:
        raise evidence.Pc020EvidenceError("predecessor root keys differ")
    if type(document.get("schema_version")) is not int or document["schema_version"] != 5:
        raise evidence.Pc020EvidenceError("predecessor schema is not 5")
    if type(document.get("epoch")) is not int or document["epoch"] != 6:
        raise evidence.Pc020EvidenceError("predecessor epoch is not 6")
    if document.get("workflow_id") != evidence.WORKFLOW_ID or document.get("phase") != "NETWORK_ACTIVE":
        raise evidence.Pc020EvidenceError("predecessor workflow or phase differs")
    active = document.get("active_snapshot")
    if (
        not isinstance(active, dict)
        or set(active) != evidence.SNAPSHOT_KEYS
        or active.get("name") != evidence.SNAPSHOT_188
        or document.get("automatic_restore_allowlist") != [evidence.SNAPSHOT_188]
    ):
        raise evidence.Pc020EvidenceError("predecessor active/allowlist is not Snapshot188")
    return document


def _fixed_predecessor(data: bytes) -> dict[str, Any]:
    if _sha(data) != evidence.PREDECESSOR_SHA256:
        raise evidence.Pc020EvidenceError("canonical bytes are not the fixed predecessor")
    document = json.loads(data.decode("utf-8"))
    _validate_predecessor_shape(document)
    evidence._predecessor(data)
    return document


def _fixed_ref(path: Path, namespace: str, filename: str) -> str:
    if path.name != filename or path.parent.parent.name != namespace:
        raise evidence.Pc020EvidenceError(f"{filename} is outside the fixed {namespace} layout")
    identity = _canonical_uuid(path.parent.name, f"{namespace} directory")
    return f"{namespace}/{identity}/{filename}"


def _derive_epoch7(
    predecessor: dict[str, Any],
    preparation_path: Path,
    preparation: dict[str, Any],
    migration_path: Path,
    migration: dict[str, Any],
) -> dict[str, Any]:
    admission = json.loads(_read_bytes(preparation_path).decode("utf-8"))
    retired = list(predecessor["retired_snapshots"])
    names = [row.get("name") if isinstance(row, dict) else None for row in retired]
    if names.count(evidence.SNAPSHOT_187) != 1 or evidence.SNAPSHOT_188 in names:
        raise evidence.Pc020EvidenceError("predecessor retired transition set differs")
    retired = [row for row in retired if row["name"] != evidence.SNAPSHOT_187]
    retired.append({"name": evidence.SNAPSHOT_188, "status": evidence.MANUAL_ONLY})
    target = {
        "schema_version": 6,
        "workflow_id": evidence.WORKFLOW_ID,
        "epoch": 7,
        "phase": "PREPARATION_BASELINE",
        "active_snapshot": {
            "name": evidence.SNAPSHOT_187,
            "checkpoint_marker": admission["checkpoint_marker"],
            "purpose": "P05 preparation only; not product readiness or P06 authorization",
        },
        "automatic_restore_allowlist": [evidence.SNAPSHOT_187],
        "retired_snapshots": retired,
        "migration_evidence": {
            "kind": "pc020-requalification-migration-v1",
            "source": "pc020-migration",
            "evidence_path": _fixed_ref(migration_path, "pc020-migration", "migration.json"),
            "evidence_sha256": _sha(_read_bytes(migration_path)),
            "predecessor_sha256": evidence.PREDECESSOR_SHA256,
            "migrated_at": migration["migrated_at"],
        },
        "preparation_evidence": {
            "kind": "pc020-snapshot187-preparation-v1",
            "source": "pc020-preparation-admission",
            "evidence_path": _fixed_ref(preparation_path, "pc020-preparation", "admission.json"),
            "evidence_sha256": _sha(_read_bytes(preparation_path)),
            "qualified_at": preparation["qualified_at"],
        },
        "activation_evidence": None,
    }
    payload = evidence.canonical_json(target)
    evidence.verify_schema6_shape(payload, expected_epoch=7)
    return target


def _intent(transition_id: str, next_sha256: str, created_at: str) -> dict[str, Any]:
    value = {
        "schema_version": 1,
        "kind": "pc020-canonical-transition-intent-v1",
        "workflow_id": evidence.WORKFLOW_ID,
        "transition_id": transition_id,
        "from_sha256": evidence.PREDECESSOR_SHA256,
        "next_sha256": next_sha256,
        "created_at": created_at,
    }
    if set(value) != INTENT_KEYS:
        raise AssertionError("intent key construction differs")
    return value


def _receipt(
    transition_id: str,
    *,
    to_sha256: str | None,
    next_sha256: str | None,
    started_at: str,
    replaced_at: str | None,
    directory_fsynced_at: str | None,
    readback_at: str | None,
    status: str,
    error: str | None,
) -> dict[str, Any]:
    value = {
        "schema_version": 1,
        "kind": "pc020-canonical-transition-receipt-v1",
        "workflow_id": evidence.WORKFLOW_ID,
        "transition_id": transition_id,
        "from_sha256": evidence.PREDECESSOR_SHA256,
        "to_sha256": to_sha256,
        "next_sha256": next_sha256,
        "started_at": started_at,
        "replaced_at": replaced_at,
        "directory_fsynced_at": directory_fsynced_at,
        "readback_at": readback_at,
        "status": status,
        "error": error,
    }
    if set(value) != RECEIPT_KEYS:
        raise AssertionError("receipt key construction differs")
    return value


def transition_to_epoch7(
    canonical_path: Path,
    preparation_admission: Path,
    migration_record: Path,
    *,
    policy: evidence.FrozenSourcePolicy,
    transition_id: str | None = None,
) -> TransitionOutcome:
    """Perform the one reviewed PC020 predecessor-to-epoch7 transition.

    Failures raise :class:`Pc020TransitionError`; its ``outcome`` records only
    observed state.  A returned outcome is always fully receipted COMMITTED.
    """
    transition_id = _canonical_uuid(transition_id or str(uuid.uuid4()), "transition_id")
    if not isinstance(canonical_path, Path) or not canonical_path.is_absolute():
        raise evidence.Pc020EvidenceError("canonical path must be absolute")
    if ".." in canonical_path.parts:
        raise evidence.Pc020EvidenceError("canonical path must not contain dotdot")
    next_path, intent_path, receipt_path, isolation_path = _output_paths(canonical_path, transition_id)
    started_at = _utc_now()
    target_sha: str | None = None
    replace_attempted = False
    replaced_at: str | None = None
    directory_fsynced_at: str | None = None
    readback_at: str | None = None
    output_parent_safe = False

    def outcome(status: str, *, receipt_written: bool = False) -> TransitionOutcome:
        return TransitionOutcome(
            status=status,
            transition_id=transition_id,
            canonical_path=canonical_path,
            next_path=next_path,
            intent_path=intent_path,
            receipt_path=receipt_path,
            isolation_path=None,
            from_sha256=evidence.PREDECESSOR_SHA256,
            to_sha256=target_sha,
            next_sha256=target_sha,
            receipt_written=receipt_written,
        )

    try:
        _plain_directory(canonical_path.parent, "canonical parent")
        output_parent_safe = True
        _plain_file(canonical_path, "canonical")
        for label, path in (("preparation admission", preparation_admission), ("migration record", migration_record)):
            _plain_file(path, label)
        predecessor_bytes = _read_bytes(canonical_path)
        predecessor = _fixed_predecessor(predecessor_bytes)
        if _lexists(next_path):
            raise evidence.Pc020EvidenceError("unknown existing .next blocks transition")
        if _lexists(intent_path):
            raise evidence.Pc020EvidenceError("existing transition intent blocks transition")
        if _lexists(receipt_path):
            raise evidence.Pc020EvidenceError("existing transition receipt blocks transition")
        if _lexists(isolation_path):
            raise evidence.Pc020EvidenceError("existing isolation target blocks transition")

        preparation = evidence.verify_preparation(preparation_admission, policy=policy)
        migration = evidence.verify_migration(
            migration_record,
            original_preparation=preparation_admission,
            policy=policy,
        )
        target = _derive_epoch7(
            predecessor, preparation_admission, preparation, migration_record, migration
        )
        target_bytes = evidence.canonical_json(target)
        target_sha = _sha(target_bytes)

        _create_durable(next_path, target_bytes)
        candidate_bytes = _read_bytes(next_path)
        if candidate_bytes != target_bytes:
            raise evidence.Pc020EvidenceError("candidate .next byte readback differs")
        evidence.verify_schema6_shape(candidate_bytes, expected_epoch=7)

        intent_document = _intent(transition_id, target_sha, _utc_now())
        _persist_exact(intent_path, intent_document)

        adjacent = _read_bytes(canonical_path)
        if adjacent != predecessor_bytes:
            raise evidence.Pc020EvidenceError("canonical drifted before atomic replace")

        replace_attempted = True
        _replace(next_path, canonical_path)
        replaced_at = _utc_now()
        _fsync_directory(canonical_path.parent)
        directory_fsynced_at = _utc_now()
        committed_bytes = _read_bytes(canonical_path)
        if committed_bytes != target_bytes:
            raise evidence.Pc020EvidenceError("canonical readback bytes differ after replace")
        evidence.verify_schema6_shape(committed_bytes, expected_epoch=7)
        readback_at = _utc_now()
    except Exception as exc:
        status = TRANSITION_INDETERMINATE if replace_attempted else FAILED_BEFORE_REPLACE
        error = f"{type(exc).__name__}: {exc}"
        receipt_document = _receipt(
            transition_id,
            to_sha256=target_sha,
            next_sha256=target_sha,
            started_at=started_at,
            replaced_at=replaced_at,
            directory_fsynced_at=directory_fsynced_at,
            readback_at=readback_at,
            status=status,
            error=error,
        )
        receipt_written = False
        if output_parent_safe:
            try:
                _persist_exact(receipt_path, receipt_document)
                receipt_written = True
            except Exception as receipt_exc:
                error += f"; receipt failed: {type(receipt_exc).__name__}: {receipt_exc}"
        else:
            error += "; receipt not attempted because output parent is untrusted"
        final = outcome(status, receipt_written=receipt_written)
        raise Pc020TransitionError(error, final) from exc

    committed_receipt = _receipt(
        transition_id,
        to_sha256=target_sha,
        next_sha256=target_sha,
        started_at=started_at,
        replaced_at=replaced_at,
        directory_fsynced_at=directory_fsynced_at,
        readback_at=readback_at,
        status=COMMITTED,
        error=None,
    )
    try:
        _persist_exact(receipt_path, committed_receipt)
    except Exception as exc:
        final = outcome(TRANSITION_INDETERMINATE, receipt_written=False)
        raise Pc020TransitionError(
            f"receipt failed after verified replace: {type(exc).__name__}: {exc}", final
        ) from exc
    return outcome(COMMITTED, receipt_written=True)
