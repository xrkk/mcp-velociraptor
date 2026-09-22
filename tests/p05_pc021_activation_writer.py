"""PC021/PC022 epoch7-to-epoch8 activation transition writer.

Implements P05 v19 0.PC021.4: the writer admits only through the G07
private one-shot capability, verifies it against the actual C7/R/S bytes in
a single critical section, atomically marks it SPENT before any file side
effect, then runs the fixed order ``.next`` -> durable v2 intent ->
canonical re-comparison with no-reparse/same-volume re-verification ->
same-volume ``MoveFileExW`` flags 9 replace -> canonical parent native
refresh -> canonical readback H8 -> 15-key v3 receipt persistence.

The receipt uses the distinct ``pc021-epoch8-activation-transition-
receipt-v3`` kind; it is never interchangeable with the epoch6->7
migration receipt shapes.  ``FAILED_BEFORE_REPLACE`` is determined solely
by this invocation not having attempted the replace, and the read-only
canonical observation (predecessor / external drift with preserved bytes
and hash / unreadable) is recorded independently.  After the replace is
attempted, any uncertainty is ``TRANSITION_INDETERMINATE`` with everything
preserved in place; nothing is isolated, deleted, rolled back, or used to
revive the old state, and a fully written receipt whose final refresh
failed still does not report success.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat as stat_module
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tests import p05_pc020_activation as graph
from tests import p05_pc020_evidence as evidence
from tests import p05_pc021_issuer as issuer
from tests import pc022_windows_refresh as refresh


INTENT_V2_KEYS = {
    "schema_version", "kind", "workflow_id", "transition_id",
    "from_sha256", "to_sha256", "next_sha256",
    "activation_root_sha256", "issuance_receipt_sha256", "created_at",
}
RECEIPT_V3_KEYS = {
    "schema_version", "kind", "workflow_id", "transition_id",
    "from_sha256", "to_sha256", "next_sha256",
    "activation_root_sha256", "issuance_receipt_sha256",
    "started_at", "replaced_at", "directory_fsynced_at", "readback_at",
    "status", "error",
}
INTENT_V2_KIND = "pc020-canonical-transition-intent-v2"
RECEIPT_V3_KIND = "pc021-epoch8-activation-transition-receipt-v3"
FAILED_BEFORE_REPLACE = "FAILED_BEFORE_REPLACE"
TRANSITION_INDETERMINATE = "TRANSITION_INDETERMINATE"
COMMITTED = "COMMITTED"


class Epoch8TransitionError(RuntimeError):
    def __init__(self, message: str, outcome: "Epoch8Outcome"):
        super().__init__(message)
        self.outcome = outcome


@dataclass(frozen=True)
class Epoch8Outcome:
    status: str
    transition_id: str
    canonical_path: Path
    next_path: Path
    intent_path: Path
    receipt_path: Path
    from_sha256: str
    to_sha256: str | None
    next_sha256: str | None
    receipt_written: bool
    canonical_observation: str | None


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _create_durable(path: Path, payload: bytes) -> None:
    with path.open("xb") as stream:
        view = memoryview(payload)
        written = 0
        while written < len(payload):
            count = stream.write(view[written:])
            if count is None or count <= 0:
                raise OSError(f"short write for {path.name}")
            written += count
        stream.flush()
        os.fsync(stream.fileno())
    refresh.windows_refresh_directory(path.parent)


def _canonical_uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise evidence.Pc020EvidenceError("transition_id is not a canonical UUID")
    canonical = str(uuid.UUID(value))
    if canonical != value:
        raise evidence.Pc020EvidenceError("transition_id is not a canonical UUID")
    return value


def _derive_epoch8(
    epoch7: dict[str, Any],
    *,
    activation_ref: dict[str, Any],
    checkpoint_marker: str,
) -> dict[str, Any]:
    retired = [dict(row) for row in epoch7["retired_snapshots"]]
    if any(row["name"] == evidence.SNAPSHOT_189 for row in retired):
        raise evidence.Pc020EvidenceError("epoch7 retired set already contains 189")
    retired.append({"name": evidence.SNAPSHOT_187, "status": evidence.MANUAL_ONLY})
    target = {
        "schema_version": 6,
        "workflow_id": epoch7["workflow_id"],
        "epoch": 8,
        "phase": "NETWORK_ACTIVE",
        "active_snapshot": {
            "name": evidence.SNAPSHOT_189,
            "checkpoint_marker": checkpoint_marker,
            "purpose": "P06_ACTIVE production baseline",
        },
        "automatic_restore_allowlist": [evidence.SNAPSHOT_189],
        "retired_snapshots": retired,
        "migration_evidence": dict(epoch7["migration_evidence"]),
        "preparation_evidence": dict(epoch7["preparation_evidence"]),
        "activation_evidence": activation_ref,
    }
    payload = evidence.canonical_json(target)
    evidence.verify_schema6_shape(payload, expected_epoch=8)
    return target


def transition_to_epoch8(
    canonical_path: Path,
    activation_dir: Path,
    capability: issuer.IssuanceCapability,
    *,
    policy: evidence.FrozenSourcePolicy,
    root_policy: evidence.FrozenSourcePolicy,
    transition_id: str | None = None,
) -> Epoch8Outcome:
    """Run the one reviewed epoch7-to-epoch8 activation transition."""
    transition_id = _canonical_uuid(transition_id or str(uuid.uuid4()))
    if not isinstance(canonical_path, Path) or not canonical_path.is_absolute():
        raise evidence.Pc020EvidenceError("canonical path must be absolute")
    if ".." in canonical_path.parts:
        raise evidence.Pc020EvidenceError("canonical path must not contain dotdot")
    root_path = activation_dir / "activation-evidence.json"
    receipt_binding = activation_dir / "issuance-receipt.json"
    next_path = Path(str(canonical_path) + ".next")
    intent_path = canonical_path.parent / f"{canonical_path.name}.{transition_id}.epoch8-intent.json"
    receipt_path = canonical_path.parent / f"{canonical_path.name}.{transition_id}.epoch8-receipt.json"
    started_at = _utc_now()
    target_sha: str | None = None
    replace_attempted = False
    replaced_at: str | None = None
    directory_fsynced_at: str | None = None
    readback_at: str | None = None
    observation: str | None = None

    def outcome(status: str, *, receipt_written: bool = False) -> Epoch8Outcome:
        return Epoch8Outcome(
            status=status, transition_id=transition_id,
            canonical_path=canonical_path, next_path=next_path,
            intent_path=intent_path, receipt_path=receipt_path,
            from_sha256=capability.epoch7_sha256, to_sha256=target_sha,
            next_sha256=target_sha, receipt_written=receipt_written,
            canonical_observation=observation,
        )

    try:
        # Step 1-3: capability admission, byte re-verification, atomic SPENT
        # strictly before any writer file side effect.
        if not isinstance(capability, issuer.IssuanceCapability):
            raise evidence.Pc020EvidenceError("writer admits only the private issuance capability")
        if capability.operation != issuer.ISSUANCE_OPERATION:
            raise evidence.Pc020EvidenceError("capability operation differs")
        if capability.issuance_id != activation_dir.name:
            raise evidence.Pc020EvidenceError("capability is not bound to this activation directory")
        graph.verify_snapshot189_activation(
            root_path, policy=policy, epoch7_canonical=_read(canonical_path), root_policy=root_policy,
        )
        c7 = _read(canonical_path)
        hr = _read(root_path)
        hs = _read(receipt_binding)
        if (
            _sha(c7) != capability.epoch7_sha256
            or _sha(hr) != capability.activation_root_sha256
            or _sha(hs) != capability.issuance_receipt_sha256
        ):
            raise evidence.Pc020EvidenceError("capability hashes differ from the actual C7/R/S bytes")
        epoch7 = json.loads(c7.decode("utf-8"))
        capability.spend()

        # Step 4-5: derive N8, exclusive .next with durability and readback.
        if _lexists(next_path):
            raise evidence.Pc020EvidenceError("unknown existing .next blocks transition")
        if _lexists(intent_path):
            raise evidence.Pc020EvidenceError("existing epoch8 intent blocks transition")
        if _lexists(receipt_path):
            raise evidence.Pc020EvidenceError("existing epoch8 receipt blocks transition")
        root_document = json.loads(hr.decode("utf-8"))
        activation_ref = {
            "source": "snapshot189-activation",
            "evidence_path": f"activation-189/{activation_dir.name}/activation-evidence.json",
            "evidence_sha256": _sha(hr),
            "activated_at": root_document["issued_at"],
        }
        target = _derive_epoch8(epoch7, activation_ref=activation_ref, checkpoint_marker=root_document["checkpoint_marker"])
        target_bytes = evidence.canonical_json(target)
        target_sha = _sha(target_bytes)
        _create_durable(next_path, target_bytes)
        if _read(next_path) != target_bytes:
            raise evidence.Pc020EvidenceError("candidate .next byte readback differs")

        # Step 6: durable v2 intent (10 keys; declares no refresh outcome).
        intent = {
            "schema_version": 2, "kind": INTENT_V2_KIND,
            "workflow_id": evidence.WORKFLOW_ID, "transition_id": transition_id,
            "from_sha256": capability.epoch7_sha256, "to_sha256": target_sha,
            "next_sha256": target_sha,
            "activation_root_sha256": capability.activation_root_sha256,
            "issuance_receipt_sha256": capability.issuance_receipt_sha256,
            "created_at": _utc_now(),
        }
        if set(intent) != INTENT_V2_KEYS:
            raise AssertionError("intent key construction differs")
        _create_durable(intent_path, evidence.canonical_json(intent))
        if _read(intent_path) != evidence.canonical_json(intent):
            raise evidence.Pc020EvidenceError("intent readback differs")

        # Step 7: immediate canonical re-comparison with identity re-checks.
        adjacent = _read(canonical_path)
        if adjacent != c7:
            raise evidence.Pc020EvidenceError("canonical drifted before atomic replace")
        _plain_file_recheck(canonical_path)
        _plain_file_recheck(next_path)
        refresh.require_same_volume(
            refresh.handle_directory_identity(next_path.parent),
            refresh.handle_directory_identity(canonical_path.parent),
            label="replace",
        )

        # Step 8-9: same-volume atomic replace, native refresh, readback.
        replace_attempted = True
        refresh.windows_replace_file(next_path, canonical_path)
        replaced_at = _utc_now()
        refresh.windows_refresh_directory(canonical_path.parent)
        directory_fsynced_at = _utc_now()
        committed = _read(canonical_path)
        if committed != target_bytes:
            raise evidence.Pc020EvidenceError("canonical readback bytes differ after replace")
        readback_at = _utc_now()
    except Exception as exc:
        status = TRANSITION_INDETERMINATE if replace_attempted else FAILED_BEFORE_REPLACE
        error = f"{type(exc).__name__}: {exc}"
        if status == FAILED_BEFORE_REPLACE:
            # PC022 W4 three-way observation; external bytes are preserved,
            # never compared-against-predecessor forcibly nor rolled back.
            try:
                observed = _read(canonical_path)
                observation = (
                    "predecessor" if _sha(observed) == capability.epoch7_sha256
                    else f"external_drift:{_sha(observed)}"
                )
            except Exception as observe_exc:
                observation = f"unreadable:{type(observe_exc).__name__}"
            error += f"; canonical_observation={observation}"
        receipt_written = False
        try:
            failure = _receipt(
                transition_id, capability=capability,
                to_sha256=target_sha, next_sha256=target_sha,
                started_at=started_at, replaced_at=replaced_at,
                directory_fsynced_at=directory_fsynced_at, readback_at=readback_at,
                status=status, error=error,
            )
            _create_durable(receipt_path, evidence.canonical_json(failure))
            receipt_written = True
        except Exception as receipt_exc:
            error += f"; receipt failed: {type(receipt_exc).__name__}: {receipt_exc}"
        raise Epoch8TransitionError(error, outcome(status, receipt_written=receipt_written)) from exc

    committed_receipt = _receipt(
        transition_id, capability=capability,
        to_sha256=target_sha, next_sha256=target_sha,
        started_at=started_at, replaced_at=replaced_at,
        directory_fsynced_at=directory_fsynced_at, readback_at=readback_at,
        status=COMMITTED, error=None,
    )
    try:
        _create_durable(receipt_path, evidence.canonical_json(committed_receipt))
    except Exception as exc:
        # A complete receipt whose final persistence/refresh failed does not
        # report success: the state stays TRANSITION_INDETERMINATE.
        raise Epoch8TransitionError(
            f"receipt failed after verified replace: {type(exc).__name__}: {exc}",
            outcome(TRANSITION_INDETERMINATE),
        ) from exc
    return outcome(COMMITTED, receipt_written=True)


def _receipt(
    transition_id: str, *, capability: issuer.IssuanceCapability,
    to_sha256: str | None, next_sha256: str | None, started_at: str,
    replaced_at: str | None, directory_fsynced_at: str | None,
    readback_at: str | None, status: str, error: str | None,
) -> dict[str, Any]:
    value = {
        "schema_version": 3, "kind": RECEIPT_V3_KIND,
        "workflow_id": evidence.WORKFLOW_ID, "transition_id": transition_id,
        "from_sha256": capability.epoch7_sha256,
        "to_sha256": to_sha256, "next_sha256": next_sha256,
        "activation_root_sha256": capability.activation_root_sha256,
        "issuance_receipt_sha256": capability.issuance_receipt_sha256,
        "started_at": started_at, "replaced_at": replaced_at,
        "directory_fsynced_at": directory_fsynced_at, "readback_at": readback_at,
        "status": status, "error": error,
    }
    if set(value) != RECEIPT_V3_KEYS:
        raise AssertionError("receipt key construction differs")
    return value


def _read(path: Path) -> bytes:
    return path.read_bytes()


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _plain_file_recheck(path: Path) -> None:
    info = path.lstat()
    if (
        not stat_module.S_ISREG(info.st_mode)
        or stat_module.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & 0x400
    ):
        raise evidence.Pc020EvidenceError(f"{path.name} is not a plain non-reparse file")

