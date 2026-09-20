"""Read-only verification of the one live PC020 Snapshot189 creation record.

This module validates caller-supplied immutable originals.  It does not run
VMware, select or restore a snapshot, write canonical state, or authorize P06.
"""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from tests import p05_pc020_evidence as evidence
from tests import p05_snapshot_raw as raw


CREATION_KEYS = {
    "schema_version", "workflow_id", "candidate", "checkpoint_marker", "vmx",
    "tree_before", "create_operation", "tree_after", "metadata_readback",
}
ORIGINAL_NAMES = ("tree_before", "create_operation", "tree_after", "metadata_readback")
MARKER_PATTERN = re.compile(r"Win10MalBox-Velo-Snapshot[0-9]+\.vmsn")


class Creation189Error(evidence.Pc020EvidenceError):
    """The supplied bytes do not prove the one reviewed live 189 creation."""


def _snapshot_identity(fields: dict[str, str], name: str) -> dict[str, Any]:
    prefixes = [key[:-12] for key, value in fields.items() if key.endswith(".displayName") and value == name]
    if len(prefixes) != 1:
        raise Creation189Error(f"metadata does not uniquely identify {name}")
    prefix = prefixes[0]
    uid = fields.get(prefix + ".uid")
    marker = fields.get(prefix + ".filename")
    if not isinstance(uid, str) or not uid.isdigit() or not isinstance(marker, str) or MARKER_PATTERN.fullmatch(marker) is None:
        raise Creation189Error(f"metadata UID or marker differs for {name}")
    parent_key = prefix + ".parent"
    parent_present = parent_key in fields
    parent = fields.get(parent_key)
    if parent_present and (not isinstance(parent, str) or not parent.isdigit()):
        raise Creation189Error(f"metadata parent differs for {name}")
    return {
        "uid": uid,
        "marker": marker,
        "parent_present": parent_present,
        "parent": parent,
    }


def _trusted_preparation_identity(
    preparation_admission: Path,
    policy: evidence.FrozenSourcePolicy,
) -> dict[str, dict[str, Any]]:
    evidence.verify_preparation(preparation_admission, policy=policy)
    root = preparation_admission.parent
    admission = evidence._json_bytes(preparation_admission.read_bytes(), "preparation admission")
    seen: dict[str, tuple[int, str]] = {}
    metadata_path = evidence._ref(root, admission["snapshot_metadata"], "snapshot_metadata", seen)
    metadata = evidence._raw_command(
        metadata_path,
        operation_id=admission["admission_id"],
        observation="snapshot_metadata",
        vmx=evidence.VMX,
        argv=["/usr/bin/cat", str(PurePosixPath(evidence.VMX).with_suffix(".vmsd"))],
    )
    fields = raw.vmsd_fields(metadata["response"]["stdout"])
    identities = {
        name: _snapshot_identity(fields, name)
        for name in (evidence.SNAPSHOT_187, evidence.SNAPSHOT_188)
    }
    if identities[evidence.SNAPSHOT_187]["marker"] != evidence.MARKER_187:
        raise Creation189Error("trusted preparation 187 marker differs")
    return identities


def _verify(
    creation_path: Path,
    *,
    preparation_admission: Path,
    policy: evidence.FrozenSourcePolicy,
    expected_marker: str,
) -> dict[str, Any]:
    if (
        not isinstance(creation_path, Path)
        or not creation_path.is_absolute()
        or creation_path.name != "creation.json"
        or ".." in creation_path.parts
    ):
        raise Creation189Error("creation path must be an absolute creation.json without dotdot")
    if not isinstance(preparation_admission, Path) or not preparation_admission.is_absolute():
        raise Creation189Error("preparation admission path must be absolute")
    if not isinstance(expected_marker, str) or MARKER_PATTERN.fullmatch(expected_marker) is None:
        raise Creation189Error("expected Snapshot189 marker is invalid")

    root = creation_path.parent
    evidence._plain_directory(root, "creation root")
    evidence._plain_file(root, creation_path.name, "creation root record")
    document = evidence._json_bytes(creation_path.read_bytes(), "Snapshot189 creation")
    if (
        set(document) != CREATION_KEYS
        or not evidence._exact_int(document.get("schema_version"), 1)
        or document.get("workflow_id") != evidence.WORKFLOW_ID
        or document.get("candidate") != evidence.SNAPSHOT_189
        or document.get("checkpoint_marker") != expected_marker
        or document.get("vmx") != evidence.VMX
    ):
        raise Creation189Error("Snapshot189 creation wrapper identity differs")

    preparation = _trusted_preparation_identity(preparation_admission, policy)
    seen: dict[str, tuple[int, str]] = {}
    originals: dict[str, dict[str, Any]] = {}
    for name in ORIGINAL_NAMES:
        path = evidence._ref(root, document[name], f"creation_metadata.{name}", seen)
        originals[name] = evidence._json_bytes(path.read_bytes(), f"creation_metadata.{name}")

    create = originals["create_operation"]
    operation_id = create.get("operation_id") if isinstance(create, dict) else None
    if not isinstance(operation_id, str) or not operation_id:
        raise Creation189Error("Snapshot189 creation operation_id is empty")
    argv = {
        "tree_before": ["/usr/bin/vmrun", "-T", "ws", "listSnapshots", evidence.VMX, "showTree"],
        "create_operation": ["/usr/bin/vmrun", "-T", "ws", "snapshot", evidence.VMX, evidence.SNAPSHOT_189],
        "tree_after": ["/usr/bin/vmrun", "-T", "ws", "listSnapshots", evidence.VMX, "showTree"],
        "metadata_readback": ["/usr/bin/cat", str(PurePosixPath(evidence.VMX).with_suffix(".vmsd"))],
    }
    previous_end = None
    for name in ORIGINAL_NAMES:
        original = originals[name]
        raw.command(
            original,
            workflow_id=evidence.WORKFLOW_ID,
            operation_id=operation_id,
            observation=name,
            vmx=evidence.VMX,
            expected_argv=argv[name],
        )
        if original["request"]["command_line"] != " ".join(argv[name]):
            raise Creation189Error(f"{name} command_line differs from its exact argv")
        if original["response"]["stderr"] != "":
            raise Creation189Error(f"{name} stderr is not empty")
        if name == "create_operation" and original["response"]["stdout"] != "":
            raise Creation189Error("create_operation stdout is not the successful empty stream")
        started = raw.utc(original["started_at"])
        ended = raw.utc(original["ended_at"])
        if previous_end is not None and started < previous_end:
            raise Creation189Error("Snapshot189 command sequence overlaps or runs backwards")
        previous_end = ended

    before = raw.snapshot_names(originals["tree_before"]["response"]["stdout"])
    after = raw.snapshot_names(originals["tree_after"]["response"]["stdout"])
    if len(before) != 2 or set(before) != {evidence.SNAPSHOT_187, evidence.SNAPSHOT_188}:
        raise Creation189Error("tree_before is not exactly retained 187/188 with zero 189")
    if len(after) != 3 or set(after) != {
        evidence.SNAPSHOT_187,
        evidence.SNAPSHOT_188,
        evidence.SNAPSHOT_189,
    }:
        raise Creation189Error("tree_after is not exactly retained 187/188 plus one 189")

    metadata_stdout = originals["metadata_readback"]["response"]["stdout"]
    fields = raw.vmsd_fields(metadata_stdout)
    display_names = [value for key, value in fields.items() if key.endswith(".displayName")]
    if (
        fields.get("snapshot.numSnapshots") != "3"
        or len(display_names) != 3
        or set(display_names) != {evidence.SNAPSHOT_187, evidence.SNAPSHOT_188, evidence.SNAPSHOT_189}
    ):
        raise Creation189Error("post-creation metadata snapshot set or count differs")
    post = {
        name: _snapshot_identity(fields, name)
        for name in (evidence.SNAPSHOT_187, evidence.SNAPSHOT_188, evidence.SNAPSHOT_189)
    }
    for name in (evidence.SNAPSHOT_187, evidence.SNAPSHOT_188):
        if post[name] != preparation[name]:
            raise Creation189Error(f"retained snapshot identity changed for {name}")
    marker, candidate_uid = raw.snapshot_marker(metadata_stdout, evidence.SNAPSHOT_189)
    if (
        marker != document["checkpoint_marker"]
        or marker != expected_marker
        or candidate_uid in {post[evidence.SNAPSHOT_187]["uid"], post[evidence.SNAPSHOT_188]["uid"]}
        or fields.get("snapshot.lastUID") != candidate_uid
        or not post[evidence.SNAPSHOT_189]["parent_present"]
        or post[evidence.SNAPSHOT_189]["parent"] != preparation[evidence.SNAPSHOT_187]["uid"]
    ):
        raise Creation189Error("Snapshot189 marker, UID, current/lastUID, or parent binding differs")

    return {
        "scope": "single_snapshot189_creation_evidence",
        "operation_id": operation_id,
        "candidate": evidence.SNAPSHOT_189,
        "candidate_uid": candidate_uid,
        "vmx": evidence.VMX,
        "checkpoint_marker": marker,
        "started_at": originals["tree_before"]["started_at"],
        "create_started_at": create["started_at"],
        "create_ended_at": create["ended_at"],
        "observed_at": originals["metadata_readback"]["ended_at"],
        "synthetic_fixture": policy.synthetic_fixture,
        "operational_ready": False,
        "authorizes_activation": False,
    }


def verify_snapshot189_creation(
    creation_path: Path,
    *,
    preparation_admission: Path,
    policy: evidence.FrozenSourcePolicy,
    expected_marker: str,
) -> dict[str, Any]:
    """Verify one immutable live 187/188→187/188/189 creation sequence."""
    try:
        return _verify(
            creation_path,
            preparation_admission=preparation_admission,
            policy=policy,
            expected_marker=expected_marker,
        )
    except Creation189Error:
        raise
    except (evidence.Pc020EvidenceError, raw.SnapshotRawError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Creation189Error(str(exc)) from exc
