"""Read-only selector predicates; trust bindings belong to the controller.

Production bindings come from the fixed PC026 governance reader. Explicit
bindings below remain an internal integration seam, never a CLI override.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import uuid

from tests import p05_pc020_evidence as evidence
from tests import p05_pc020_creation as creation
from tests import p05_pc020_restore as restore
from tests import p05_pc020_transition as migration_writer
from tests import p05_pc021_activation_writer as activation_writer
from tests import p05_pc021_stage_rules as stages
from tests import p06_pc021_consumer as consumer


@dataclass(frozen=True)
class ControllerBindings:
    evidence_root: Path
    policy: evidence.FrozenSourcePolicy
    epoch7_canonical: bytes
    epoch7_receipt: Path
    root_policy: evidence.FrozenSourcePolicy | None = None
    profile_id: str | None = None
    governed_group: object | None = None


def read_schema6(data: bytes, expected_workflow: str, *, profile_id: str | None = None) -> dict:
    state = evidence._json_bytes(data, "selector canonical")
    evidence.verify_schema6_shape(data, expected_epoch=state.get("epoch"), profile_id=profile_id)
    if expected_workflow != evidence.WORKFLOW_ID:
        raise evidence.Pc020EvidenceError("workflow_id mismatch")
    marker = state["active_snapshot"]["checkpoint_marker"]
    if (state["epoch"] == 7 and marker != evidence.MARKER_187) or (
        state["epoch"] == 8 and (
            creation.MARKER_PATTERN.fullmatch(marker) is None
            or int(marker.removeprefix("Win10MalBox-Velo-Snapshot").removesuffix(".vmsn")) <= 3
        )
    ):
        raise evidence.Pc020EvidenceError("schema6 checkpoint marker differs")
    return state


def plain(root: Path, relative: str) -> Path:
    if not root.is_absolute() or ".." in root.parts:
        raise evidence.Pc020EvidenceError("selector evidence root must be absolute")
    # Reject ancestor aliases as well as the package-relative components.
    for parent in (root, *root.parents):
        evidence._plain_directory(parent, "selector evidence root ancestor")
    return evidence._plain_file(root, relative, "formal selector evidence")


def resolve_refs(state: dict, root: Path) -> dict[str, Path]:
    paths = {}
    for key in ("preparation_evidence", "migration_evidence", "activation_evidence"):
        reference = state[key]
        if reference is None:
            continue
        path = plain(root, reference["evidence_path"])
        if evidence._sha(path.read_bytes()) != reference["evidence_sha256"]:
            raise evidence.Pc020EvidenceError(f"{key} hash mismatch")
        paths[key] = path
    return paths


def _receipt(root: Path, path: Path, keys: set, generation: int, kind: str,
             hashes: dict[str, str]) -> dict:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise evidence.Pc020EvidenceError("transition receipt outside approved root") from exc
    value = evidence._json_bytes(plain(root, relative).read_bytes(), "transition receipt")
    if (set(value) != keys or type(value.get("schema_version")) is not int
            or value["schema_version"] != generation or value.get("kind") != kind
            or value.get("workflow_id") != evidence.WORKFLOW_ID
            or value.get("status") != "COMMITTED" or value.get("error") is not None):
        raise evidence.Pc020EvidenceError("current COMMITTED transition receipt required")
    identity = value.get("transition_id")
    if not isinstance(identity, str) or str(uuid.UUID(identity)) != identity:
        raise evidence.Pc020EvidenceError("transition UUID differs")
    for key, digest in hashes.items():
        if value[key] != digest:
            raise evidence.Pc020EvidenceError(f"transition {key} binding differs")
    for key in ("started_at", "replaced_at", "directory_fsynced_at", "readback_at"):
        evidence._utc(value[key], f"transition {key}")
    return value


def qualify(data: bytes, *, bindings: ControllerBindings, stage: str) -> dict:
    """Verify current selection content, without executing recovery or a writer."""
    state = read_schema6(data, evidence.WORKFLOW_ID, profile_id=bindings.profile_id)
    rule = stages.STAGE_RULES.get(stage)
    if bindings.profile_id == "pc026-snapshot191-v1" and rule is not None:
        from tests.p05_pc026_profile import CURRENT
        rule = dict(rule)
        rule["canonical"] = dict(rule["canonical"])
        if stage == "P06_ACTIVE":
            rule["canonical"]["active_snapshot"] = CURRENT.snapshot
        if stage != "P05_REPAIR_INITIAL":
            rule["restored_snapshot"] = CURRENT.snapshot
    actual = {"schema_version": state["schema_version"], "epoch": state["epoch"],
              "phase": state["phase"], "active_snapshot": state["active_snapshot"]["name"]}
    if rule is None or rule["canonical"] != actual or rule["restored_snapshot"] != actual["active_snapshot"]:
        raise evidence.Pc020EvidenceError("stage cannot select this canonical active snapshot")
    c7 = read_schema6(bindings.epoch7_canonical, evidence.WORKFLOW_ID)
    if c7["epoch"] != 7 or (state["epoch"] == 7 and data != bindings.epoch7_canonical):
        raise evidence.Pc020EvidenceError("trusted C7 binding differs")
    for key in ("migration_evidence", "preparation_evidence"):
        if state[key] != c7[key]:
            raise evidence.Pc020EvidenceError("epoch8 changed immutable C7 references")
    paths = resolve_refs(state, bindings.evidence_root)
    declarations = {kind: {"path": state[key]["evidence_path"],
                           "sha256": state[key]["evidence_sha256"]}
                    for kind, key in (("pc020_preparation", "preparation_evidence"),
                                      ("pc020_migration", "migration_evidence"))}
    restore._bind_epoch7_packages(c7,
        {kind: paths[key] for kind, key in (("pc020_preparation", "preparation_evidence"),
                                           ("pc020_migration", "migration_evidence"))},
        declarations, bindings.policy)
    h7 = evidence._sha(bindings.epoch7_canonical)
    _receipt(bindings.evidence_root, bindings.epoch7_receipt, migration_writer.RECEIPT_KEYS,
             2, "pc020-epoch7-migration-transition-receipt-v2",
             {"from_sha256": evidence.PREDECESSOR_SHA256, "to_sha256": h7, "next_sha256": h7})
    if state["epoch"] == 8:
        if bindings.root_policy is None:
            raise evidence.Pc020EvidenceError("current activation frozen policy binding missing")
        activation = paths["activation_evidence"]
        root_doc = evidence._json_bytes(activation.read_bytes(), "activation root")
        if state["active_snapshot"]["checkpoint_marker"] != root_doc["checkpoint_marker"]:
            raise evidence.Pc020EvidenceError("active marker differs from activation metadata")
        receipt_path = plain(bindings.evidence_root,
            (activation.parent / "epoch8-transition-receipt.json").relative_to(bindings.evidence_root).as_posix())
        hashes = {"from_sha256": h7, "to_sha256": evidence._sha(data), "next_sha256": evidence._sha(data),
                  "activation_root_sha256": evidence._sha(activation.read_bytes()),
                  "issuance_receipt_sha256": evidence._sha(plain(bindings.evidence_root,
                      (activation.parent / "issuance-receipt.json").relative_to(bindings.evidence_root).as_posix()).read_bytes())}
        receipt = _receipt(bindings.evidence_root, receipt_path, activation_writer.RECEIPT_V3_KEYS,
                           3, activation_writer.RECEIPT_V3_KIND, hashes)
        intent_path = plain(bindings.evidence_root,
            (activation.parent / "epoch8-transition-intent.json").relative_to(bindings.evidence_root).as_posix())
        intent = evidence._json_bytes(intent_path.read_bytes(), "epoch8 intent")
        if (set(intent) != activation_writer.INTENT_V2_KEYS or type(intent.get("schema_version")) is not int
                or intent["schema_version"] != 2 or intent.get("kind") != "pc020-canonical-transition-intent-v2"
                or intent.get("workflow_id") != evidence.WORKFLOW_ID
                or intent.get("transition_id") != receipt["transition_id"]
                or any(intent[key] != value for key, value in hashes.items())):
            raise evidence.Pc020EvidenceError("epoch8 intent/receipt binding differs")
        evidence._utc(intent["created_at"], "epoch8 intent created_at")
        consumer.verify_p06_admission(activation.parent, epoch7_canonical=bindings.epoch7_canonical,
            epoch8_canonical=data, epoch8_receipt_path=receipt_path,
            policy=bindings.policy, root_policy=bindings.root_policy,
            profile_id=bindings.profile_id)
    if bindings.governed_group is not None:
        bindings.governed_group.recheck()
    return {"stage": stage, "content_graph_validated": True,
            "canonical_sha256": evidence._sha(data), "synthetic_fixture": bindings.policy.synthetic_fixture}
