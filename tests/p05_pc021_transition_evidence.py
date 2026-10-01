"""Shared read-only PC021 fixed transition output and completion predicates."""
from __future__ import annotations

from pathlib import Path
import uuid

from tests import p05_pc020_evidence as evidence


INTENT_NAME = "epoch8-transition-intent.json"
RECEIPT_NAME = "epoch8-transition-receipt.json"
INTENT_KIND = "pc020-canonical-transition-intent-v2"
RECEIPT_KIND = "pc021-epoch8-activation-transition-receipt-v3"
INTENT_KEYS = {
    "schema_version", "kind", "workflow_id", "transition_id", "from_sha256",
    "to_sha256", "next_sha256", "activation_root_sha256", "issuance_receipt_sha256", "created_at",
}
RECEIPT_KEYS = {
    "schema_version", "kind", "workflow_id", "transition_id", "from_sha256",
    "to_sha256", "next_sha256", "activation_root_sha256", "issuance_receipt_sha256",
    "started_at", "replaced_at", "directory_fsynced_at", "readback_at", "status", "error",
}


def verify_committed_bytes(intent_bytes: bytes, receipt_bytes: bytes, *,
                           epoch7: bytes, epoch8: bytes, root: bytes, issuance: bytes) -> dict:
    """Content only; does not reconstruct a capability or attest past API calls."""
    intent = evidence._json_bytes(intent_bytes, "epoch8 intent")
    receipt = evidence._json_bytes(receipt_bytes, "epoch8 receipt")
    if set(intent) != INTENT_KEYS or type(intent.get("schema_version")) is not int or intent["schema_version"] != 2 or intent.get("kind") != INTENT_KIND:
        raise evidence.Pc020EvidenceError("epoch8 intent keys or generation differ")
    if set(receipt) != RECEIPT_KEYS:
        raise evidence.Pc020EvidenceError("epoch8 transition receipt keys differ")
    if receipt.get("kind") != RECEIPT_KIND:
        raise evidence.Pc020EvidenceError("transition receipt is not the current v3 kind")
    if type(receipt.get("schema_version")) is not int or receipt["schema_version"] != 3:
        raise evidence.Pc020EvidenceError("transition receipt schema generation differs")
    if receipt.get("status") != "COMMITTED" or receipt.get("error") is not None:
        raise evidence.Pc020EvidenceError("epoch8 transition receipt is not COMMITTED")
    for document in (intent, receipt):
        identity = document.get("transition_id")
        if (document.get("workflow_id") != evidence.WORKFLOW_ID or not isinstance(identity, str)
                or str(uuid.UUID(identity)) != identity):
            raise evidence.Pc020EvidenceError("transition workflow/UUID identity differs")
    if intent["transition_id"] != receipt["transition_id"]:
        raise evidence.Pc020EvidenceError("epoch8 intent/receipt transition ID binding differs")
    hashes = {"from_sha256": evidence._sha(epoch7), "to_sha256": evidence._sha(epoch8),
              "next_sha256": evidence._sha(epoch8), "activation_root_sha256": evidence._sha(root),
              "issuance_receipt_sha256": evidence._sha(issuance)}
    if any(document[key] != digest for document in (intent, receipt) for key, digest in hashes.items()):
        raise evidence.Pc020EvidenceError("intent/v3 COMMITTED receipt hashes do not bind C7/R/S/H8")
    evidence.verify_schema6_shape(epoch7, expected_epoch=7)
    evidence.verify_schema6_shape(epoch8, expected_epoch=8)
    c7, c8 = evidence._json_bytes(epoch7, "C7"), evidence._json_bytes(epoch8, "C8")
    root_document = evidence._json_bytes(root, "activation root")
    if (any(c8[key] != c7[key] for key in ("migration_evidence", "preparation_evidence"))
            or c8["active_snapshot"]["checkpoint_marker"] != root_document["checkpoint_marker"]):
        raise evidence.Pc020EvidenceError("C8 immutable references or activation marker binding differs")
    evidence._utc(intent["created_at"], "intent created_at")
    for key in ("started_at", "replaced_at", "directory_fsynced_at", "readback_at"):
        evidence._utc(receipt[key], f"receipt {key}")
    return receipt


def read_fixed(activation_dir: Path, receipt_path: Path) -> tuple[bytes, bytes]:
    """Read only the two normative plain files; never accept an old UUID path."""
    if not activation_dir.is_absolute() or ".." in activation_dir.parts:
        raise evidence.Pc020EvidenceError("activation directory must be an absolute plain path")
    if receipt_path != activation_dir / RECEIPT_NAME:
        raise evidence.Pc020EvidenceError("epoch8 receipt must use the fixed activation directory path")
    for parent in (activation_dir, *activation_dir.parents):
        evidence._plain_directory(parent, "activation ancestor")
    return tuple(evidence._plain_file(activation_dir, name, "fixed transition output").read_bytes()
                 for name in (INTENT_NAME, RECEIPT_NAME))
