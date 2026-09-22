"""Read-only verifier for the PC020 Snapshot189 three-phase activation graph."""

from __future__ import annotations

import json
import hashlib
import re
import stat
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tests import p05_pc020_creation as creation
from tests import p05_pc020_evidence as evidence
from tests import p05_pc020_restore as restore7
from tests import p05_pc021_package as pkg
from tests import p06_evidence as legacy


ROOT_KEYS = {
    "schema_version", "kind", "workflow_id", "candidate", "checkpoint_marker",
    "migration_evidence", "preparation_evidence", "creation_metadata", "initial",
    "candidate_cycles", "source_inputs", "implementation_sources", "issued_at",
}
RECEIPT_NAME = "issuance-receipt.json"
RECEIPT_KEYS = {
    "schema_version", "kind", "workflow_id", "issuance_id", "operation", "source",
    "epoch7", "cycle2", "activation_root", "issued_at", "events", "status", "error",
}
RECEIPT_KIND = "snapshot189-activation-issuance-receipt-v2"
RECEIPT_SOURCE_KEYS = {"source_inputs_sha256", "implementation_sources_sha256"}
RECEIPT_EPOCH7_KEYS = {"canonical_sha256", "schema_version", "epoch", "phase", "active_snapshot"}
RECEIPT_CYCLE2_KEYS = {"restore_attempt_id", "run_id", "report", "package_manifest"}
EVENT_KEYS = {"sequence", "event", "at"}
EVENT_ORDER = (
    "PRE_ISSUE_GRAPH_VALIDATED", "ISSUED_AT_SAMPLED", "ROOT_WRITTEN",
    "ROOT_FILE_FSYNCED", "ROOT_DIRECTORY_FSYNCED", "ROOT_READBACK_VALIDATED",
)
PHASE_KEYS = legacy.PHASE_KEYS
SCENARIOS = {
    "p05-flow-triage-repair-initial": (
        "tests/scenarios/representative/p05-flow-triage-repair-initial.json",
        "P05_REPAIR_INITIAL", evidence.SNAPSHOT_187,
    ),
    "p05-flow-triage-repair-candidate": (
        "tests/scenarios/representative/p05-flow-triage-repair-candidate.json",
        "P05_REPAIR_CANDIDATE", evidence.SNAPSHOT_189,
    ),
}
INDEX = "tests/data/p05_scenario_index.json"
FIXTURE = "tests/data/p05_fixture_spec.json"
SCHEMA = "tests/scenarios/schema-v1.json"
RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


class Activation189Error(evidence.Pc020EvidenceError):
    """The supplied bytes do not prove one complete Snapshot189 activation."""


def _json(path: Path, label: str) -> dict[str, Any]:
    # P05 carried originals predate PC020's canonical-json encoding rule.
    # Their frozen byte identity is checked by the Ref/policy; parse them with
    # the existing duplicate-key/non-finite-safe legacy reader.
    value = legacy._read_json(path, label)
    if not isinstance(value, dict):
        raise Activation189Error(f"{label} must be an object")
    return value


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not RFC3339_Z.fullmatch(value):
        raise Activation189Error(f"{label} must be exact RFC3339 UTC Z")
    try:
        instant = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise Activation189Error(f"{label} is invalid") from exc
    return instant.astimezone(UTC)


def _source_graph(
    sources: dict[str, Path], implementations: dict[str, Path]
) -> dict[str, tuple[dict[str, Any], str, str, str]]:
    required = {INDEX, FIXTURE, SCHEMA, *(row[0] for row in SCENARIOS.values())}
    mixed = required & set(implementations)
    if mixed:
        raise Activation189Error(
            "normative sources must live in source_inputs, not implementation_sources"
        )
    source = sources
    if not required.issubset(source):
        raise Activation189Error("frozen source set omits the complete P05 representative graph")
    index = _json(source[INDEX], "scenario index")
    fixture = _json(source[FIXTURE], "fixture specification")
    schema = _json(source[SCHEMA], "scenario schema")
    if (
        set(index) != {"schema_version", "scenarios"} or index.get("schema_version") != 1
        or not isinstance(index.get("scenarios"), list) or len(index["scenarios"]) != 2
        or fixture.get("schema_version") != 1
        or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or not isinstance(schema.get("$defs"), dict)
    ):
        raise Activation189Error("P05 source index, fixture, or schema shape differs")
    fixture_sha = legacy.digest(source[FIXTURE])
    index_sha = legacy.digest(source[INDEX])
    result: dict[str, tuple[dict[str, Any], str, str, str]] = {}
    expected_order = list(SCENARIOS)
    for position, row in enumerate(index["scenarios"]):
        scenario_id = expected_order[position]
        path, stage, snapshot = SCENARIOS[scenario_id]
        if not isinstance(row, dict) or set(row) != {
            "fixture_spec_sha256", "path", "required_snapshot", "scenario_id",
            "sha256", "snapshot_stage",
        }:
            raise Activation189Error("scenario index row shape differs")
        scenario = _json(source[path], f"scenario {scenario_id}")
        scenario_sha = legacy.digest(source[path])
        if (
            row.get("scenario_id") != scenario_id
            or row.get("path") != path.removeprefix("tests/scenarios/")
            or row.get("snapshot_stage") != stage
            or row.get("required_snapshot") != snapshot
            or row.get("sha256") != scenario_sha
            or row.get("fixture_spec_sha256") != fixture_sha
            or set(scenario) != {
                "business_purpose", "cleanup", "fixture_spec_sha256", "required_snapshot",
                "scenario_id", "schema_version", "steps",
            }
            or scenario.get("schema_version") != 1
            or scenario.get("scenario_id") != scenario_id
            or scenario.get("required_snapshot") != snapshot
            or scenario.get("fixture_spec_sha256") != fixture_sha
            or not isinstance(scenario.get("steps"), list)
            or not isinstance(scenario.get("cleanup"), list)
        ):
            raise Activation189Error("scenario source does not bind its exact index row")
        result[scenario_id] = (scenario, scenario_sha, index_sha, fixture_sha)
    return result


def _phase_manifest(
    root: Path, phase: dict[str, Any], report: dict[str, Any], seen: dict[str, tuple[int, str]]
) -> None:
    manifest_path = evidence._ref(root, phase["package_manifest"], "phase manifest", seen)
    document = _json(manifest_path, "phase manifest")
    report_ref = phase["report"]["path"]
    try:
        pkg.verify_phase_package(
            phase_root=manifest_path.parent,
            manifest=document,
            report=report,
            report_ref_path=report_ref,
        )
    except pkg.PackagePreservationError as exc:
        raise Activation189Error(f"phase manifest content graph differs: {exc}") from exc
    actual = sorted(
        path.relative_to(manifest_path.parent).as_posix()
        for path in evidence._walk(manifest_path.parent).values()
        if path != manifest_path
    )
    declared = sorted(member["path"] for member in document["members"])
    if declared != actual:
        raise Activation189Error("phase manifest is not the exact recursive ordinary-file set")


def _flow_ids(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"flow_id", "flowId", "FlowId"} and isinstance(item, str) and item:
                found.add(item)
            found.update(_flow_ids(item))
    elif isinstance(value, list):
        for item in value:
            found.update(_flow_ids(item))
    return found


def _successful(call: dict[str, Any], tool: str) -> dict[str, Any]:
    structured = call.get("structured")
    if (
        call.get("tool") != tool or call.get("is_error") is not False
        or not isinstance(structured, dict)
        or structured.get("operation") != tool
        or structured.get("status") != "success"
        or not isinstance(structured.get("warnings"), list)
    ):
        raise Activation189Error(f"phase {tool} call is not one decoded success")
    return structured


def _package_downloads(report: dict[str, Any], phase_root: Path) -> None:
    """Every download chain's member is read only inside the package.

    The product ``local_path`` stays an immutable source-time assertion in
    the report; it is never resolved or opened here (P05 v19 0.PC021.3.4).
    Exactly two fixture chains exist and no other download call does.
    """
    try:
        chains = pkg.locate_download_chains(report)
    except pkg.PackagePreservationError as exc:
        raise Activation189Error(f"phase download chains differ: {exc}") from exc
    download_calls = [
        call for call in report["calls"]
        if isinstance(call, dict) and call.get("tool") == "download_flow_file"
    ]
    if len(chains) != 2 or len(download_calls) != len(chains):
        raise Activation189Error(
            "phase must contain exactly the two fixture download chains"
        )
    for chain in chains:
        member = (
            phase_root / pkg.DOWNLOADS_DIR / pkg.flow_key(chain.flow_id)
            / chain.file_id / "content.bin"
        )
        if not member.exists():
            raise Activation189Error("phase package lacks a downloaded member")
        info = member.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise Activation189Error("phase downloaded member is not one plain file")
        data = member.read_bytes()
        if (
            len(data) != chain.logical_size
            or hashlib.sha256(data).hexdigest() != chain.sha256
        ):
            raise Activation189Error("phase downloaded member size or sha256 differs")


def _business_chain(report: dict[str, Any], phase_root: Path) -> set[str]:
    calls = report.get("calls")
    if not isinstance(calls, list):
        raise Activation189Error("phase report calls are absent")
    by_step = {call.get("step_id"): [] for call in calls if isinstance(call, dict)}
    for call in calls:
        if not isinstance(call, dict) or not isinstance(call.get("step_id"), str):
            raise Activation189Error("phase business call is not an object with a step identity")
        by_step.setdefault(call["step_id"], []).append(call)

    chains = (
        ("collect_ascii", "wait_ascii", "ascii_metadata", "ascii_files", "ascii_download", "collect_file"),
        ("collect_utf8", "wait_utf8", "utf8_metadata", "utf8_files", "utf8_download", "collect_file"),
        ("start_triage", "wait_triage", "triage_results", "triage_files", None, "collect_forensic_triage"),
    )
    flow_ids: set[str] = set()
    for start_id, wait_id, results_id, files_id, download_id, start_tool in chains:
        starts = by_step.get(start_id, [])
        waits = by_step.get(wait_id, [])
        results = by_step.get(results_id, [])
        files = by_step.get(files_id, [])
        if len(starts) != 1 or not waits or len(results) != 1 or len(files) != 1:
            raise Activation189Error("phase omits one complete Triage/file lifecycle chain")
        start = _successful(starts[0], start_tool)
        flow_id = start.get("flow_id")
        start_state = start.get("state")
        if (
            not isinstance(flow_id, str) or not flow_id or flow_id in flow_ids
            or not isinstance(start_state, str) or not start_state or start_state == "ERROR"
        ):
            raise Activation189Error("phase startup Flow identity or initial state differs")
        flow_ids.add(flow_id)
        for wait in waits:
            state = _successful(wait, "get_flow_status")
            if (
                wait.get("arguments") != {"flow_id": flow_id}
                or state.get("flow_id") != flow_id
                or wait.get("sequence", 0) <= starts[0].get("sequence", 0)
                or not isinstance(state.get("state"), str) or not state["state"]
                or state["state"] == "ERROR"
            ):
                raise Activation189Error("phase Flow status identity or state differs")
        if waits[-1]["structured"]["state"] != "FINISHED":
            raise Activation189Error("phase Flow has no later terminal FINISHED fact")
        result = _successful(results[0], "get_flow_results")
        listing = _successful(files[0], "list_flow_files")
        if (
            results[0].get("arguments", {}).get("flow_id") != flow_id
            or files[0].get("arguments") != {"flow_id": flow_id}
            or listing.get("truncated") is not False
            or not isinstance(result.get("data"), list)
            or not isinstance(listing.get("data"), list)
        ):
            raise Activation189Error("phase result/file list is not bound to its Flow")
        for row in listing["data"]:
            if not isinstance(row, dict) or set(row) != pkg.LIST_ROW_KEYS:
                raise Activation189Error("phase file list row keys differ")
        if download_id is None:
            continue
        downloads = by_step.get(download_id, [])
        if len(downloads) != 1:
            raise Activation189Error("phase download chain is missing or duplicated")
        download_call = downloads[0]
        download = _successful(download_call, "download_flow_file")
        listed = {
            row.get("file_id"): row for row in listing["data"]
            if isinstance(row, dict) and isinstance(row.get("file_id"), str)
        }
        file_id = download_call.get("arguments", {}).get("file_id")
        selected = listed.get(file_id)
        if (
            not isinstance(selected, dict)
            or download_call.get("arguments") != {"flow_id": flow_id, "file_id": file_id}
            or download.get("flow_id") != flow_id or download.get("file_id") != file_id
            or download.get("original_path") != selected.get("original_path")
            or download.get("size") != selected.get("file_size")
            or download_call.get("sequence", 0) <= files[0].get("sequence", 0)
        ):
            raise Activation189Error("phase download is not bound to its listed Flow/file identity")
    return flow_ids


def _phase(
    root: Path, phase: Any, scenario_id: str, graph: dict[str, tuple[dict[str, Any], str, str, str]],
    policy: evidence.FrozenSourcePolicy, creation_path: Path | None,
    seen: dict[str, tuple[int, str]],
) -> dict[str, Any]:
    if not isinstance(phase, dict) or set(phase) != PHASE_KEYS:
        raise Activation189Error("activation phase keys differ")
    if not isinstance(phase.get("run_id"), str) or not phase["run_id"] or not isinstance(phase.get("restore_attempt_id"), str) or not phase["restore_attempt_id"]:
        raise Activation189Error("phase run/attempt identity is absent")
    refs = {name: evidence._ref(root, phase[name], f"phase.{name}", seen) for name in PHASE_KEYS - {"run_id", "restore_attempt_id"}}
    scenario, source_sha, index_sha, fixture_sha = graph[scenario_id]
    report = _json(refs["report"], "phase report")
    if (
        set(report) != legacy.REPORT_KEYS or report.get("schema_version") != 2
        or report.get("status") != "success" or report.get("scenario") != scenario_id
        or report.get("run_id") != phase["run_id"] or report.get("source_sha256") != source_sha
        or report.get("index_sha256") != index_sha or report.get("fixture_spec_sha256") != fixture_sha
        or report.get("transport") != "streamable-http"
        or report.get("endpoint") != "http://192.168.204.232:28790/mcp"
        or report.get("authorization_configured") is not True or report.get("failure") is not None
        or report.get("unexecuted_step_ids") != []
    ):
        raise Activation189Error("phase report is not the bound complete schema2 success report")
    parent = phase["report"]["path"].rsplit("/", 1)[0]
    fixture = legacy._verify_fixture_instance(root, parent, report, scenario, fixture_sha)
    listing = _json(legacy.plain_file(root, f"{parent}/tools-list.json"), "tools list")
    normalized = legacy._normalized_tools_bytes(listing)
    schema_path = legacy.plain_file(root, f"{parent}/tools-schema.json")
    if schema_path.read_bytes() != normalized or legacy.digest(schema_path) != report.get("tools_schema_sha256"):
        raise Activation189Error("phase tools schema does not bind the raw tools list")
    snapshot = _json(refs["snapshot_evidence"], "snapshot evidence")
    if (
        set(snapshot) != legacy.SNAPSHOT_EVIDENCE_KEYS
        or legacy.digest(refs["snapshot_evidence"]) != report.get("snapshot_evidence_sha256")
        or snapshot.get("scenario_id") != scenario_id or snapshot.get("source_sha256") != source_sha
        or snapshot.get("index_sha256") != index_sha
    ):
        raise Activation189Error("snapshot evidence does not bind report and frozen sources")
    legacy._verify_phase_identities(report, snapshot)
    legacy.verify_observation(report, root / parent)
    flows = _business_chain(report, refs["package_manifest"].parent)
    _package_downloads(report, refs["package_manifest"].parent)
    legacy._verify_phase_execution(report, scenario, fixture)
    restore_result = restore7.verify_epoch7_restore(snapshot.get("restore"), root, policy=policy, creation_path=creation_path)
    if restore_result["run_id"] != phase["run_id"] or restore_result["restore_attempt_id"] != phase["restore_attempt_id"]:
        raise Activation189Error("restore decoded identity differs from its phase")
    legacy._verify_ready(root, phase, seen, expected_restore=snapshot["restore"])
    legacy._verify_dependency_acceptance(root, phase, seen)
    legacy._verify_entry_gate(root, phase, seen)
    legacy._verify_network_evidence(root, phase, seen)
    _phase_manifest(root, phase, report, seen)
    return {
        "report": report, "restore": restore_result, "flows": flows,
        "session": report["mcp_session"]["id"],
        "runner": (report["runner"]["pid"], report["runner"]["process_start_time_utc"], report["runner"]["executable_sha256"]),
        "server": (report["server_identity"]["pid"], report["server_identity"]["process_start_time_utc"], report["server_identity"]["instance_id"]),
    }


def activation_path_bytes(root: Path) -> bytes:
    return (root / "activation-evidence.json").read_bytes()


def _verify_receipt(
    root: Path, document: dict[str, Any], epoch7_canonical: bytes, seen: dict[str, tuple[int, str]]
) -> None:
    """Verify the same-layer PC022 v2 issuance receipt (P05 v19 0.PC021.2.1).

    The root never references the receipt; it is found at the fixed sibling
    path ``issuance-receipt.json`` inside ``A``.  All thirteen keys, the six
    ordered events, the two-array source digests, the epoch7/cycle2/Root
    bindings, and the three-way ``issued_at`` byte equality are checked.
    """
    path = root / RECEIPT_NAME
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise Activation189Error("issuance receipt is not one plain file")
    receipt = _json(path, "issuance receipt")
    if set(receipt) != RECEIPT_KEYS:
        raise Activation189Error("issuance receipt keys differ")
    if (
        receipt.get("schema_version") != 2
        or receipt.get("kind") != RECEIPT_KIND
        or receipt.get("workflow_id") != evidence.WORKFLOW_ID
        or receipt.get("operation") != "P05_ACTIVATION_ISSUE"
        or receipt.get("status") != "ROOT_VALIDATED"
        or receipt.get("error") is not None
    ):
        raise Activation189Error("issuance receipt identity or status differs")
    if receipt.get("issuance_id") != str(uuid.UUID(root.name)) or receipt["issuance_id"] != root.name:
        raise Activation189Error("issuance receipt is not bound to the activation uuid")
    source = receipt.get("source")
    if not isinstance(source, dict) or set(source) != RECEIPT_SOURCE_KEYS:
        raise Activation189Error("issuance receipt source keys differ")
    if source["source_inputs_sha256"] != evidence._sha(
        evidence.canonical_json(document["source_inputs"])
    ) or source["implementation_sources_sha256"] != evidence._sha(
        evidence.canonical_json(document["implementation_sources"])
    ):
        raise Activation189Error("issuance receipt source digests differ from the root arrays")
    epoch7 = receipt.get("epoch7")
    if not isinstance(epoch7, dict) or set(epoch7) != RECEIPT_EPOCH7_KEYS:
        raise Activation189Error("issuance receipt epoch7 keys differ")
    if (
        epoch7.get("canonical_sha256") != evidence._sha(epoch7_canonical)
        or epoch7.get("schema_version") != 6
        or epoch7.get("epoch") != 7
        or epoch7.get("phase") != "PREPARATION_BASELINE"
        or epoch7.get("active_snapshot") != evidence.SNAPSHOT_187
    ):
        raise Activation189Error("issuance receipt epoch7 binding differs")
    cycle2 = receipt.get("cycle2")
    if not isinstance(cycle2, dict) or set(cycle2) != RECEIPT_CYCLE2_KEYS:
        raise Activation189Error("issuance receipt cycle2 keys differ")
    second = document["candidate_cycles"][1]
    if (
        cycle2.get("restore_attempt_id") != second.get("restore_attempt_id")
        or cycle2.get("run_id") != second.get("run_id")
        or cycle2.get("report") != second.get("report")
        or cycle2.get("package_manifest") != second.get("package_manifest")
    ):
        raise Activation189Error("issuance receipt cycle2 binding differs from the root")
    activation_root = receipt.get("activation_root")
    if (
        not isinstance(activation_root, dict)
        or set(activation_root) != {"path", "size", "sha256"}
        or activation_root.get("path") != "activation-evidence.json"
        or activation_root.get("size") != (root / "activation-evidence.json").stat().st_size
        or activation_root.get("sha256") != evidence._sha(activation_path_bytes(root))
    ):
        raise Activation189Error("issuance receipt activation_root binding differs")
    events = receipt.get("events")
    if not isinstance(events, list) or len(events) != 6:
        raise Activation189Error("issuance receipt events are not six")
    for position, event in enumerate(events, start=1):
        if (
            not isinstance(event, dict)
            or set(event) != EVENT_KEYS
            or event.get("sequence") != position
            or event.get("event") != EVENT_ORDER[position - 1]
        ):
            raise Activation189Error("issuance receipt event order or shape differs")
        _utc(event.get("at"), f"issuance receipt event {position} at")
    if (
        receipt.get("issued_at") != document.get("issued_at")
        or events[1]["at"] != document.get("issued_at")
    ):
        raise Activation189Error(
            "issued_at must be byte-equal across the root, receipt, and ISSUED_AT_SAMPLED"
        )


def _verify(
    activation_path: Path, *, policy: evidence.FrozenSourcePolicy, epoch7_canonical: bytes,
    root_policy: evidence.FrozenSourcePolicy | None = None,
) -> dict[str, Any]:
    if not isinstance(activation_path, Path) or not activation_path.is_absolute() or activation_path.is_symlink():
        raise Activation189Error("activation root must be an absolute plain file")
    root = activation_path.parent
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or root.parent.name != "activation-189":
        raise Activation189Error("activation root is outside activation-189 layout")
    try:
        uuid.UUID(root.name)
    except ValueError as exc:
        raise Activation189Error("activation package directory is not a UUID") from exc
    document = _json(activation_path, "activation root")
    if set(document) != ROOT_KEYS:
        raise Activation189Error("activation root keys differ")
    if (
        document.get("schema_version") != 1 or document.get("kind") != "snapshot189-activation-evidence-v1"
        or document.get("workflow_id") != evidence.WORKFLOW_ID or document.get("candidate") != evidence.SNAPSHOT_189
    ):
        raise Activation189Error("activation identity is not Snapshot189")
    marker = document.get("checkpoint_marker")
    if not isinstance(marker, str) or not re.fullmatch(r"Win10MalBox-Velo-Snapshot[0-9]+\.vmsn", marker):
        raise Activation189Error("activation checkpoint marker differs")
    evidence.verify_schema6_shape(epoch7_canonical, expected_epoch=7)
    canonical = evidence._json_bytes(epoch7_canonical, "trusted epoch7 canonical")
    if canonical["active_snapshot"]["name"] != evidence.SNAPSHOT_187:
        raise Activation189Error("trusted epoch7 canonical is not active Snapshot187")
    seen: dict[str, tuple[int, str]] = {}
    preparation_path = evidence._ref(root, document["preparation_evidence"], "preparation", seen)
    migration_path = evidence._ref(root, document["migration_evidence"], "migration", seen)
    creation_path = evidence._ref(root, document["creation_metadata"], "creation", seen)
    preparation = evidence.verify_preparation(preparation_path, policy=policy)
    migration = evidence.verify_migration(migration_path, original_preparation=preparation_path, policy=policy)
    if canonical["preparation_evidence"]["evidence_sha256"] != legacy.digest(preparation_path) or canonical["migration_evidence"]["evidence_sha256"] != legacy.digest(migration_path):
        raise Activation189Error("trusted epoch7 canonical does not bind preparation and migration bytes")
    binding = root_policy or policy
    sources = evidence._sources(root, document["source_inputs"], binding.source_inputs, "source_inputs", seen)
    implementations = evidence._sources(root, document["implementation_sources"], binding.implementation_sources, "implementation_sources", seen)
    graph = _source_graph(sources, implementations)
    creation_result = creation.verify_snapshot189_creation(
        creation_path, preparation_admission=preparation_path, policy=policy, expected_marker=marker,
    )
    cycles = document.get("candidate_cycles")
    if not isinstance(cycles, list) or len(cycles) != 2:
        raise Activation189Error("activation requires exactly two candidate cycles")
    phases = [
        _phase(root, document["initial"], "p05-flow-triage-repair-initial", graph, policy, None, seen),
        _phase(root, cycles[0], "p05-flow-triage-repair-candidate", graph, policy, creation_path, seen),
        _phase(root, cycles[1], "p05-flow-triage-repair-candidate", graph, policy, creation_path, seen),
    ]
    phase_docs = [document["initial"], *cycles]
    for key in ("run_id", "restore_attempt_id"):
        if len({phase[key] for phase in phase_docs}) != 3:
            raise Activation189Error(f"three phases reuse {key}")
    for key in ("session", "runner", "server"):
        if len({phase[key] for phase in phases}) != 3:
            raise Activation189Error(f"three phases reuse decoded {key} identity")
    for left in range(3):
        for right in range(left + 1, 3):
            if phases[left]["flows"] & phases[right]["flows"]:
                raise Activation189Error("three phases reuse decoded Flow identity")
    # The root's verified Refs encode the normative causal DAG: creation and
    # all three complete phase byte graphs must already exist to hash and issue
    # this root.  Report times are guest clock readings, creation times are host
    # command readings, and issued_at is an issuer clock reading; compare none
    # of their magnitudes across domains (P05 PC020 section 6).
    _utc(document.get("issued_at"), "issued_at")
    _verify_receipt(root, document, epoch7_canonical, seen)
    return {
        "scope": "snapshot189_three_phase_activation_evidence",
        "workflow_id": evidence.WORKFLOW_ID, "candidate": evidence.SNAPSHOT_189,
        "checkpoint_marker": marker, "issued_at": document["issued_at"],
        "phase_count": 3, "preparation_id": preparation["admission_id"],
        "migration_id": migration["migration_id"], "creation_operation_id": creation_result["operation_id"],
        "synthetic_fixture": policy.synthetic_fixture, "operational_ready": False,
        "authorizes_activation_write": False, "authorizes_p06": False,
    }


def verify_snapshot189_activation(
    activation_path: Path, *, policy: evidence.FrozenSourcePolicy, epoch7_canonical: bytes,
    root_policy: evidence.FrozenSourcePolicy | None = None,
) -> dict[str, Any]:
    """Verify immutable bytes only; never execute input commands or write state.

    ``policy`` stays the unmodified PC020 frozen policy for the embedded
    preparation/migration bundles; ``root_policy`` (when given) is the larger
    PC021/PC022 source set bound by the activation root itself.
    """
    try:
        return _verify(
            activation_path, policy=policy, epoch7_canonical=epoch7_canonical,
            root_policy=root_policy,
        )
    except Activation189Error:
        raise
    except (evidence.Pc020EvidenceError, legacy.EvidenceError, OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise Activation189Error(str(exc)) from exc
