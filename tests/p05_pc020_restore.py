"""Read-only verification of PC020 schema6/epoch7 P05 restore originals.

This module accepts only the initial Snapshot187 and candidate Snapshot189 P05
rows.  It validates carried immutable bytes and never executes a restore,
writes canonical state, or authorizes activation/P06.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from tests import p05_pc020_creation as creation
from tests import p05_pc020_evidence as evidence
from tests import p05_snapshot_raw as snapshot_raw
from tests import p06_evidence as legacy


RESTORE_KEYS = {
    "workflow_id", "run_id", "restore_attempt_id", "snapshot_stage",
    "snapshot_name", "checkpoint_marker", "canonical_schema_version",
    "canonical_epoch", "canonical_phase", "canonical_sha256", "restore_records",
}
RESTORE_KINDS = {
    "snapshot_metadata", "revert_operation", "pre_start_marker",
    "post_restore_hostname", "canonical_readback", "pc020_migration",
    "pc020_preparation",
}
STAGES = {
    "P05_REPAIR_INITIAL": evidence.SNAPSHOT_187,
    "P05_REPAIR_CANDIDATE": evidence.SNAPSHOT_189,
}
OBSERVATIONS = {
    "snapshot_metadata": "snapshot-tree-readonly",
    "revert_operation": "single-revert",
    "pre_start_marker": "vmx-checkpoint-marker-before-start",
    "post_restore_hostname": "guest-identity-via-control-plane",
}


class Epoch7RestoreError(evidence.Pc020EvidenceError):
    """The supplied bytes do not prove one reviewed epoch7 P05 restore."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise Epoch7RestoreError(f"{label} must be a non-empty string")
    return value


def _sha_value(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise Epoch7RestoreError(f"{label} must be a lowercase SHA-256")
    return value


def _records(restore: dict[str, Any], root: Path) -> tuple[dict[str, Path], dict[str, dict[str, str]]]:
    values = restore.get("restore_records")
    if not isinstance(values, list) or len(values) != len(RESTORE_KINDS):
        raise Epoch7RestoreError("epoch7 restore must contain exactly seven original record kinds")
    paths: dict[str, Path] = {}
    declarations: dict[str, dict[str, str]] = {}
    relative_paths: set[str] = set()
    for value in values:
        if not isinstance(value, dict) or set(value) != {"kind", "path", "sha256"}:
            raise Epoch7RestoreError("epoch7 restore record shape differs")
        kind = value.get("kind")
        relative = value.get("path")
        checksum = _sha_value(value.get("sha256"), "restore record sha256")
        if kind not in RESTORE_KINDS or kind in paths or relative in relative_paths:
            raise Epoch7RestoreError("epoch7 restore record kind or path is unknown or duplicated")
        if not isinstance(relative, str):
            raise Epoch7RestoreError("epoch7 restore record path is not text")
        path = legacy.plain_file(root, relative)
        if legacy.digest(path) != checksum:
            raise Epoch7RestoreError(f"epoch7 restore record bytes differ: {kind}")
        paths[kind] = path
        declarations[kind] = value
        relative_paths.add(relative)
    if set(paths) != RESTORE_KINDS:
        raise Epoch7RestoreError("epoch7 restore record kind set differs")
    return paths, declarations


def _bind_epoch7_packages(
    canonical: dict[str, Any],
    paths: dict[str, Path],
    declarations: dict[str, dict[str, str]],
    policy: evidence.FrozenSourcePolicy,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    preparation_path = paths["pc020_preparation"]
    migration_path = paths["pc020_migration"]
    preparation_result = evidence.verify_preparation(preparation_path, policy=policy)
    migration_result = evidence.verify_migration(
        migration_path, original_preparation=preparation_path, policy=policy,
    )
    preparation = evidence._json_bytes(preparation_path.read_bytes(), "epoch7 preparation admission")
    migration = evidence._json_bytes(migration_path.read_bytes(), "epoch7 migration")
    preparation_ref = canonical["preparation_evidence"]
    migration_ref = canonical["migration_evidence"]
    if (
        preparation_ref["evidence_path"] != declarations["pc020_preparation"]["path"]
        or preparation_ref["evidence_sha256"] != declarations["pc020_preparation"]["sha256"]
        or preparation_ref["qualified_at"] != preparation["qualified_at"]
    ):
        raise Epoch7RestoreError("epoch7 canonical preparation Ref/path/hash/time differs")
    if (
        migration_ref["evidence_path"] != declarations["pc020_migration"]["path"]
        or migration_ref["evidence_sha256"] != declarations["pc020_migration"]["sha256"]
        or migration_ref["migrated_at"] != migration["migrated_at"]
        or migration_ref["predecessor_sha256"] != migration["predecessor_sha256"]
    ):
        raise Epoch7RestoreError("epoch7 canonical migration Ref/path/hash/time differs")
    if canonical["active_snapshot"]["checkpoint_marker"] != preparation["checkpoint_marker"]:
        raise Epoch7RestoreError("epoch7 active Snapshot187 marker differs from preparation original")
    return preparation_result, migration_result, preparation, migration


def _verify_raw(
    restore: dict[str, Any],
    paths: dict[str, Path],
    expected_snapshot: str,
) -> None:
    try:
        legacy._verify_restore_action_originals(
            restore["restore_attempt_id"], expected_snapshot,
            restore["checkpoint_marker"], paths,
        )
    except legacy.EvidenceError as exc:
        raise Epoch7RestoreError(str(exc)) from exc
    originals: dict[str, dict[str, Any]] = {}
    for kind, observation in OBSERVATIONS.items():
        document = evidence._json_bytes(paths[kind].read_bytes(), f"restore original {kind}")
        if document.get("observation") != observation:
            raise Epoch7RestoreError(f"{kind} observation differs")
        response = document.get("response")
        if not isinstance(response, dict) or response.get("stderr") != "":
            raise Epoch7RestoreError(f"{kind} stderr is not the successful empty stream")
        originals[kind] = document
    if originals["revert_operation"]["response"]["stdout"] != "":
        raise Epoch7RestoreError("revert_operation stdout is not the successful empty stream")
    try:
        names = snapshot_raw.snapshot_names(
            originals["snapshot_metadata"]["response"]["stdout"]
        )
    except snapshot_raw.SnapshotRawError as exc:
        raise Epoch7RestoreError(str(exc)) from exc
    expected_names = {evidence.SNAPSHOT_187, evidence.SNAPSHOT_188}
    if expected_snapshot == evidence.SNAPSHOT_189:
        expected_names.add(evidence.SNAPSHOT_189)
    if (
        len(names) != len(expected_names)
        or len(set(names)) != len(names)
        or set(names) != expected_names
    ):
        raise Epoch7RestoreError("restore snapshot tree differs from the exact stage inventory")


def _verify(
    restore: dict[str, Any],
    root: Path,
    *,
    policy: evidence.FrozenSourcePolicy,
    creation_path: Path | None,
) -> dict[str, Any]:
    if not isinstance(root, Path) or not root.is_absolute():
        raise Epoch7RestoreError("controlled package root must be absolute")
    if not isinstance(restore, dict) or set(restore) != RESTORE_KEYS:
        raise Epoch7RestoreError("epoch7 restore root keys differ")
    stage = restore.get("snapshot_stage")
    expected_snapshot = STAGES.get(stage)
    if expected_snapshot is None:
        raise Epoch7RestoreError("restore stage is not an epoch7 P05 stage")
    _nonempty(restore.get("run_id"), "restore run_id")
    _nonempty(restore.get("restore_attempt_id"), "restore attempt_id")
    marker = _nonempty(restore.get("checkpoint_marker"), "restore checkpoint_marker")
    if (
        restore.get("workflow_id") != evidence.WORKFLOW_ID
        or restore.get("snapshot_name") != expected_snapshot
        or type(restore.get("canonical_schema_version")) is not int
        or restore["canonical_schema_version"] != 6
        or type(restore.get("canonical_epoch")) is not int
        or restore["canonical_epoch"] != 7
        or restore.get("canonical_phase") != "PREPARATION_BASELINE"
    ):
        raise Epoch7RestoreError("restore stage/snapshot/schema6 epoch7 pairing differs")
    _sha_value(restore.get("canonical_sha256"), "canonical_sha256")
    paths, declarations = _records(restore, root)
    canonical_bytes = paths["canonical_readback"].read_bytes()
    if _sha(canonical_bytes) != restore["canonical_sha256"]:
        raise Epoch7RestoreError("canonical SHA differs from current readback bytes")
    evidence.verify_schema6_shape(canonical_bytes, expected_epoch=7)
    canonical = evidence._json_bytes(canonical_bytes, "epoch7 canonical readback")
    if (
        canonical["schema_version"] != restore["canonical_schema_version"]
        or canonical["epoch"] != restore["canonical_epoch"]
        or canonical["phase"] != restore["canonical_phase"]
        or canonical["workflow_id"] != restore["workflow_id"]
    ):
        raise Epoch7RestoreError("restore declaration differs from canonical readback identity")
    preparation_result, migration_result, _, _ = _bind_epoch7_packages(
        canonical, paths, declarations, policy,
    )
    if stage == "P05_REPAIR_INITIAL":
        if creation_path is not None:
            raise Epoch7RestoreError("initial restore must not consume future creation evidence")
        if marker != canonical["active_snapshot"]["checkpoint_marker"]:
            raise Epoch7RestoreError("initial restore marker differs from epoch7 Snapshot187")
        creation_result = None
    else:
        if not isinstance(creation_path, Path) or not creation_path.is_absolute():
            raise Epoch7RestoreError("candidate restore requires an absolute creation original")
        creation_result = creation.verify_snapshot189_creation(
            creation_path,
            preparation_admission=paths["pc020_preparation"],
            policy=policy,
            expected_marker=marker,
        )
        if creation_result["checkpoint_marker"] != marker:
            raise Epoch7RestoreError("candidate restore marker differs from verified creation")
    _verify_raw(restore, paths, expected_snapshot)
    return {
        "scope": "single_epoch7_p05_restore_evidence",
        "stage": stage,
        "run_id": restore["run_id"],
        "restore_attempt_id": restore["restore_attempt_id"],
        "snapshot_name": expected_snapshot,
        "checkpoint_marker": marker,
        "canonical_schema_version": 6,
        "canonical_epoch": 7,
        "canonical_phase": "PREPARATION_BASELINE",
        "canonical_active_snapshot": canonical["active_snapshot"]["name"],
        "preparation_id": preparation_result["admission_id"],
        "migration_id": migration_result["migration_id"],
        "creation_operation_id": None if creation_result is None else creation_result["operation_id"],
        "synthetic_fixture": policy.synthetic_fixture,
        "operational_ready": False,
        "authorizes_activation": False,
        "authorizes_p06": False,
    }


def verify_epoch7_restore(
    restore: dict[str, Any],
    root: Path,
    *,
    policy: evidence.FrozenSourcePolicy,
    creation_path: Path | None = None,
) -> dict[str, Any]:
    """Verify one INITIAL/187 or CANDIDATE/189 epoch7 restore record."""
    try:
        return _verify(restore, root, policy=policy, creation_path=creation_path)
    except Epoch7RestoreError:
        raise
    except (
        evidence.Pc020EvidenceError, legacy.EvidenceError,
        snapshot_raw.SnapshotRawError, OSError, UnicodeError,
        json.JSONDecodeError, KeyError, TypeError, ValueError,
    ) as exc:
        raise Epoch7RestoreError(str(exc)) from exc
