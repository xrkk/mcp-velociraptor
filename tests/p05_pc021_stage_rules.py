"""PC021/PC022 unified stage rules binding index, restore, and runner reports.

Single normative table for the three stages (P05 v19 0.PC021.4.2/0.PC021.5
and the requirement v10 stage table): which snapshot is actually restored,
which canonical state must be read back, which exact restore record kinds
apply (seven for the two P05 stages, eight with ``activation_evidence`` for
``P06_ACTIVE``), and which inputs each stage may consume.  The verifiers
below bind the scenario index, the scenario files, restore declarations,
and runner reports to this one rule set; no CLI flag, environment override,
or alternate root may bypass them.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from tests import p05_pc020_evidence as evidence


SNAPSHOT_187 = evidence.SNAPSHOT_187
SNAPSHOT_189 = evidence.SNAPSHOT_189
SEVEN_KINDS = {
    "snapshot_metadata", "revert_operation", "pre_start_marker",
    "post_restore_hostname", "canonical_readback",
    "pc020_migration", "pc020_preparation",
}
STAGE_RULES: dict[str, dict[str, Any]] = {
    "P05_REPAIR_INITIAL": {
        "restored_snapshot": SNAPSHOT_187,
        "canonical": {"schema_version": 6, "epoch": 7, "phase": "PREPARATION_BASELINE", "active_snapshot": SNAPSHOT_187},
        "record_kinds": set(SEVEN_KINDS),
        "consumes_creation": False,
        "requires_activation_graph": False,
    },
    "P05_REPAIR_CANDIDATE": {
        "restored_snapshot": SNAPSHOT_189,
        "canonical": {"schema_version": 6, "epoch": 7, "phase": "PREPARATION_BASELINE", "active_snapshot": SNAPSHOT_187},
        "record_kinds": set(SEVEN_KINDS),
        "consumes_creation": True,
        "requires_activation_graph": False,
    },
    "P06_ACTIVE": {
        "restored_snapshot": SNAPSHOT_189,
        "canonical": {"schema_version": 6, "epoch": 8, "phase": "NETWORK_ACTIVE", "active_snapshot": SNAPSHOT_189},
        "record_kinds": set(SEVEN_KINDS) | {"activation_evidence"},
        "consumes_creation": True,
        "requires_activation_graph": True,
    },
}


class StageRuleError(ValueError):
    """A stage binding deviates from the single normative rule table."""


def _sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_index_binding(index_path: Path, *, repo_root: Path) -> list[dict[str, Any]]:
    """Verify the scenario index against its scenario files and the rules.

    Every row must bind its exact scenario bytes (sha256), one fixture spec
    digest shared by all rows, an approved (stage, snapshot) pair, and the
    scenario document must restate the same stage/snapshot/fixture binding.
    Returns the parsed rows for further consumers.
    """
    rows = json.loads(index_path.read_bytes().decode("utf-8"))
    if not isinstance(rows, dict) or set(rows) != {"schema_version", "scenarios"} or rows.get("schema_version") != 1:
        raise StageRuleError("scenario index shape differs")
    scenarios = rows["scenarios"]
    if not isinstance(scenarios, list) or not scenarios:
        raise StageRuleError("scenario index has no rows")
    fixture_hashes: set[str] = set()
    seen: set[str] = set()
    for row in scenarios:
        if not isinstance(row, dict) or set(row) != {
            "fixture_spec_sha256", "path", "required_snapshot",
            "scenario_id", "sha256", "snapshot_stage",
        }:
            raise StageRuleError("index row shape differs")
        scenario_id = row["scenario_id"]
        if scenario_id in seen:
            raise StageRuleError(f"duplicate scenario id: {scenario_id}")
        seen.add(scenario_id)
        rule = STAGE_RULES.get(row["snapshot_stage"])
        if rule is None or rule["restored_snapshot"] != row["required_snapshot"]:
            raise StageRuleError(
                f"index row {scenario_id} stage/snapshot pair is not approved"
            )
        scenario_path = repo_root / "tests/scenarios" / row["path"]
        try:
            scenario_path.resolve().relative_to((repo_root / "tests/scenarios").resolve())
        except ValueError as exc:
            raise StageRuleError(f"scenario path escapes the scenario root: {row['path']}") from exc
        if not scenario_path.is_file():
            raise StageRuleError(f"scenario file missing: {row['path']}")
        if _sha_file(scenario_path) != row["sha256"]:
            raise StageRuleError(f"index row sha256 does not bind the scenario bytes: {scenario_id}")
        fixture_hashes.add(row["fixture_spec_sha256"])
        scenario = json.loads(scenario_path.read_bytes().decode("utf-8"))
        if (
            scenario.get("scenario_id") != scenario_id
            or scenario.get("required_snapshot") != row["required_snapshot"]
            or scenario.get("fixture_spec_sha256") != row["fixture_spec_sha256"]
            or scenario.get("schema_version") != 1
        ):
            raise StageRuleError(f"scenario does not restate its index binding: {scenario_id}")
    if len(fixture_hashes) != 1:
        raise StageRuleError("index rows do not share one frozen fixture spec digest")
    return scenarios


def verify_restore_stage_binding(document: Any) -> dict[str, Any]:
    """Bind one restore declaration to the single stage rule table.

    The declaration must carry the exact approved (stage, restored snapshot,
    canonical four-tuple, record kind set); a manifest of the wrong
    generation, a stage/snapshot cross-use, an extra or missing record kind,
    or a canonical that jumped ahead is refused.
    """
    if not isinstance(document, dict):
        raise StageRuleError("restore declaration is not an object")
    required_keys = {
        "workflow_id", "run_id", "restore_attempt_id", "snapshot_stage",
        "snapshot_name", "checkpoint_marker", "canonical_schema_version",
        "canonical_epoch", "canonical_phase", "canonical_sha256",
        "restore_records",
    }
    if set(document) != required_keys:
        raise StageRuleError("restore declaration keys differ")
    if document["workflow_id"] != evidence.WORKFLOW_ID:
        raise StageRuleError("restore declaration belongs to another workflow")
    stage = document["snapshot_stage"]
    rule = STAGE_RULES.get(stage)
    if rule is None:
        raise StageRuleError("restore stage is not approved")
    if document["snapshot_name"] != rule["restored_snapshot"]:
        raise StageRuleError(
            f"stage {stage} must restore {rule['restored_snapshot']}, "
            f"not {document['snapshot_name']}"
        )
    canonical = rule["canonical"]
    if (
        document["canonical_schema_version"] != canonical["schema_version"]
        or document["canonical_epoch"] != canonical["epoch"]
        or document["canonical_phase"] != canonical["phase"]
    ):
        raise StageRuleError(
            f"stage {stage} canonical state does not match the rule table"
        )
    records = document["restore_records"]
    if not isinstance(records, list):
        raise StageRuleError("restore records are not a list")
    kinds: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {"kind", "path", "sha256"}:
            raise StageRuleError("restore record shape differs")
        kind = record["kind"]
        if kind in kinds:
            raise StageRuleError(f"restore record kind duplicated: {kind}")
        relative = record["path"]
        if not isinstance(relative, str) or not relative or "\\" in relative or relative.startswith("/"):
            raise StageRuleError(f"restore record path escapes the package root: {relative!r}")
        if ".." in Path(relative).parts:
            raise StageRuleError(f"restore record path traverses dotdot: {relative!r}")
        kinds.add(kind)
    if kinds != rule["record_kinds"]:
        missing = sorted(rule["record_kinds"] - kinds)
        extra = sorted(kinds - rule["record_kinds"])
        raise StageRuleError(
            f"stage {stage} record kind set differs (missing={missing}, extra={extra})"
        )
    if stage == "P05_REPAIR_CANDIDATE" and not rule["consumes_creation"]:
        raise StageRuleError("candidate stage must consume the creation original")
    return {"stage": stage, "rule": {key: value for key, value in rule.items() if key != "record_kinds"}, "kinds": sorted(kinds)}


def verify_runner_report_binding(report: Any, index_row: dict[str, Any]) -> None:
    """Bind a runner report to its index row under the same rules."""
    if not isinstance(report, dict):
        raise StageRuleError("runner report is not an object")
    if report.get("schema_version") != 2:
        raise StageRuleError("runner report schema generation differs")
    if report.get("scenario") != index_row["scenario_id"]:
        raise StageRuleError("runner report scenario differs from its index row")
    if report.get("source_sha256") != index_row["sha256"] or report.get("fixture_spec_sha256") != index_row["fixture_spec_sha256"]:
        raise StageRuleError("runner report does not bind the frozen scenario/fixture digests")
    if report.get("transport") != "streamable-http" or report.get("status") != "success" or report.get("failure") is not None:
        raise StageRuleError("formal runner report must be a complete streamable-http success")
    if report.get("unexecuted_step_ids") != []:
        raise StageRuleError("formal runner report has unexecuted steps")
