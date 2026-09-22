"""PC021/PC022 unified P06/P07 consumer predicates.

One admission rule for everything downstream of the activation (P05 v19
0.PC021.4.4 plus the PC022 version gates):

- ``verify_p06_admission`` consumes the complete activation content graph
  through the G06 verifier (13-key root, v2 issuance receipt with the six
  ordered events), the current epoch8 canonical bytes (schema6 / epoch8 /
  NETWORK_ACTIVE / Snapshot189 with the activation Ref byte-bound to the
  root), and the 15-key v3 transition receipt in COMMITTED state whose
  hashes bind C7/R/S.  A legacy 188 bundle whose bytes and hashes are all
  correct stays historical: it simply does not have this shape and is
  refused, never "upgraded by hash".
- ``verify_selection`` and ``verify_aggregate_binding`` enforce one
  explicit successful attempt per scenario, rejected alternates with
  reasons, no failed attempt inside the success coverage, and the strict
  129 x 5 = 645 tool-scenario relation recomputation with empty difference
  sets in both directions.
- ``verify_p07_handoff`` states the consumption direction: the handoff is
  built only from the admitted current graph and never becomes a P05
  prerequisite.  Transport ZIP hashes are never compared to manifest
  hashes, and no member resolves the frozen source-time ``local_path``
  outside the package.
"""

from __future__ import annotations

import hashlib
import json
import stat as stat_module
from pathlib import Path
from typing import Any

from tests import p05_pc020_activation as graph
from tests import p05_pc020_evidence as evidence
from tests import p05_pc021_stage_rules as stage_rules


class ConsumerError(ValueError):
    """A downstream consumption rule refused the input."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_p06_admission(
    activation_dir: Path,
    *,
    epoch7_canonical: bytes,
    epoch8_canonical: bytes,
    epoch8_receipt_path: Path,
    policy: evidence.FrozenSourcePolicy,
    root_policy: evidence.FrozenSourcePolicy,
) -> dict[str, Any]:
    """Admit one activation bundle plus its committed epoch8 transition."""
    root_path = activation_dir / "activation-evidence.json"
    facts = graph.verify_snapshot189_activation(
        root_path, policy=policy, epoch7_canonical=epoch7_canonical,
        root_policy=root_policy,
    )
    if activation_dir.parent.name != "activation-189":
        raise ConsumerError("activation bundle is outside the fixed activation-189 layout")
    epoch8 = evidence._json_bytes(epoch8_canonical, "epoch8 canonical")
    evidence.verify_schema6_shape(epoch8_canonical, expected_epoch=8)
    if (
        epoch8.get("phase") != "NETWORK_ACTIVE"
        or epoch8.get("active_snapshot", {}).get("name") != evidence.SNAPSHOT_189
        or epoch8.get("automatic_restore_allowlist") != [evidence.SNAPSHOT_189]
    ):
        raise ConsumerError("epoch8 canonical is not the active Snapshot189 state")
    activation_ref = epoch8.get("activation_evidence")
    root_document = json.loads(root_path.read_bytes())
    root_bytes = root_path.read_bytes()
    if (
        not isinstance(activation_ref, dict)
        or activation_ref.get("source") != "snapshot189-activation"
        or activation_ref.get("evidence_path")
        != f"activation-189/{activation_dir.name}/activation-evidence.json"
        or activation_ref.get("evidence_sha256") != _sha(root_bytes)
        or activation_ref.get("activated_at") != root_document.get("issued_at")
    ):
        raise ConsumerError("epoch8 canonical activation Ref is not bound to this root")

    receipt_bytes = epoch8_receipt_path.read_bytes()
    committed = json.loads(receipt_bytes)
    if not isinstance(committed, dict) or set(committed) != {
        "schema_version", "kind", "workflow_id", "transition_id",
        "from_sha256", "to_sha256", "next_sha256",
        "activation_root_sha256", "issuance_receipt_sha256",
        "started_at", "replaced_at", "directory_fsynced_at", "readback_at",
        "status", "error",
    }:
        raise ConsumerError("epoch8 transition receipt keys differ")
    if committed.get("kind") != "pc021-epoch8-activation-transition-receipt-v3":
        # legacy shapes stay readable as history only and never upgrade
        raise ConsumerError("transition receipt is not the current v3 kind")
    if committed.get("schema_version") != 3:
        raise ConsumerError("transition receipt schema generation differs")
    if committed.get("status") != "COMMITTED" or committed.get("error") is not None:
        raise ConsumerError("epoch8 transition receipt is not COMMITTED")
    if (
        committed.get("to_sha256") != _sha(epoch8_canonical)
        or committed.get("from_sha256") != _sha(epoch7_canonical)
        or committed.get("activation_root_sha256") != _sha(root_bytes)
        or committed.get("issuance_receipt_sha256")
        != _sha((activation_dir / "issuance-receipt.json").read_bytes())
    ):
        raise ConsumerError("v3 COMMITTED receipt hashes do not bind C7/R/S/H8")
    return {
        "activation_root_sha256": _sha(root_bytes),
        "epoch8_sha256": _sha(epoch8_canonical),
        "transition_id": committed.get("transition_id"),
        "phase_count": facts["phase_count"],
        "authorizes_p06": True,
        "historical_only": False,
    }


def verify_selection(
    ledger_rows: list[dict[str, Any]], selection_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """One explicit successful attempt per scenario; alternates carry reasons."""
    if not isinstance(selection_rows, list) or not selection_rows:
        raise ConsumerError("final selection is empty")
    scenarios: set[str] = set()
    for row in selection_rows:
        if not isinstance(row, dict) or set(row) != {
            "scenario", "run_id", "restore_attempt_id", "report_relative_path",
            "status", "rejected_alternates",
        }:
            raise ConsumerError("selection row shape differs")
        if row["status"] != "success":
            raise ConsumerError("selected attempt is not a success")
        scenario = row["scenario"]
        if scenario in scenarios:
            raise ConsumerError(f"scenario selected more than once: {scenario}")
        scenarios.add(scenario)
        matched = [
            ledger for ledger in ledger_rows
            if ledger.get("scenario") == scenario
            and ledger.get("run_id") == row["run_id"]
        ]
        if len(matched) != 1 or matched[0].get("status") != "success":
            raise ConsumerError(f"selected run is not the one received success: {scenario}")
        alternates = row["rejected_alternates"]
        if not isinstance(alternates, list):
            raise ConsumerError("rejected alternates must be a list with reasons")
        for alternate in alternates:
            if not isinstance(alternate, dict) or not alternate.get("run_id") or not alternate.get("reason"):
                raise ConsumerError("rejected alternate lacks run id or reason")
    received_scenarios = {ledger.get("scenario") for ledger in ledger_rows}
    unselected = received_scenarios - scenarios
    if unselected:
        raise ConsumerError(f"scenarios received but never selected: {sorted(unselected)}")
    return selection_rows


def verify_aggregate_binding(
    *,
    selection_rows: list[dict[str, Any]],
    coverage: list[dict[str, Any]],
    expected_tools: set[str],
    expected_scenarios: set[str],
    expected_relations: int,
) -> dict[str, Any]:
    """Strictly recompute the tool-scenario coverage from the selection."""
    selected_runs = {(row["scenario"], row["run_id"]) for row in selection_rows}
    observed: set[tuple[str, str]] = set()
    for relation in coverage:
        if not isinstance(relation, dict) or set(relation) != {"tool", "scenario", "run_id"}:
            raise ConsumerError("coverage relation shape differs")
        key = (relation["scenario"], relation["run_id"])
        if key not in selected_runs:
            raise ConsumerError("coverage relation belongs to an unselected or failed attempt")
        observed.add((relation["tool"], relation["scenario"]))
    tools = {tool for tool, _ in observed}
    scenarios = {scenario for _, scenario in observed}
    if tools != expected_tools:
        missing = sorted(expected_tools - tools)
        extra = sorted(tools - expected_tools)
        raise ConsumerError(f"tool difference set is not empty (missing={missing[:4]}..., extra={extra[:4]}...)")
    if scenarios != expected_scenarios:
        raise ConsumerError("scenario difference set is not empty")
    expected_pairs = {(tool, scenario) for tool in expected_tools for scenario in expected_scenarios}
    if observed != expected_pairs or len(observed) != expected_relations:
        raise ConsumerError(
            f"coverage relations differ from the exact {expected_relations} set"
        )
    return {
        "tools": len(tools),
        "scenarios": len(scenarios),
        "relations": len(observed),
        "difference_sets_empty": True,
    }


def verify_p07_handoff(
    handoff: dict[str, Any],
    *,
    admission: dict[str, Any],
    selection_rows: list[dict[str, Any]],
) -> None:
    """The handoff consumes only the admitted current graph, in one direction."""
    if not isinstance(handoff, dict):
        raise ConsumerError("handoff is not an object")
    if handoff.get("epoch8_sha256") != admission["epoch8_sha256"]:
        raise ConsumerError("handoff does not bind the admitted epoch8 canonical")
    if handoff.get("activation_root_sha256") != admission["activation_root_sha256"]:
        raise ConsumerError("handoff does not bind the admitted activation root")
    selected = {(row["scenario"], row["run_id"]) for row in selection_rows}
    consumed = {
        (row.get("scenario"), row.get("run_id"))
        for row in handoff.get("consumed_selection", [])
    }
    if consumed != selected:
        raise ConsumerError("handoff does not consume exactly the final selection")
    for key in ("p05_prerequisite", "reissue_instruction"):
        if key in handoff:
            raise ConsumerError(
                "handoff must not become a P05 prerequisite or instruct reissue"
            )


def member_paths_stay_in_package(manifest_members: list[dict[str, Any]], package_root: Path) -> list[Path]:
    """Resolve members only inside the package; reject escapes and reparse."""
    resolved: list[Path] = []
    for member in manifest_members:
        relative = member.get("path")
        if not isinstance(relative, str) or relative.startswith(("/", "\\")) or ".." in Path(relative).parts:
            raise ConsumerError(f"manifest member escapes the package: {relative!r}")
        path = package_root / relative
        info = path.lstat()
        if (
            not stat_module.S_ISREG(info.st_mode)
            or stat_module.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise ConsumerError(f"manifest member is not a plain file: {relative}")
        resolved.append(path)
    return resolved


def transport_zip_hash_is_not_manifest_hash(zip_sha: str, manifest_sha: str) -> None:
    """Transport ZIP hashes and manifest hashes are different domains."""
    if zip_sha == manifest_sha:
        raise ConsumerError("transport ZIP hash must not be conflated with the manifest hash")
