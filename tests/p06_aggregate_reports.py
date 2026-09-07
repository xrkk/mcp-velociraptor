"""Strictly aggregate the five selected P06 reports without executing tools.

Consumes schema2 reports produced by the shared scenario runner on the
formal Streamable HTTP transport.  Every identity check required by P05 0.3
and 0.5 (tools-schema binding, snapshot evidence, server observation join,
session identity) is recomputed from the run directories; schema1 reports
and stdio diagnostics are rejected as formal evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = ROOT / "Logs" / "P06" / "wf-01a05d1d-p06"
LEDGER = EVIDENCE_ROOT / "接收清单.jsonl"
SELECTION = EVIDENCE_ROOT / "final-selection.json"
MANIFEST = ROOT / "tests" / "data" / "p06_coverage_manifest.json"
OUTPUT = EVIDENCE_ROOT / "aggregate.json"

SNAPSHOT_186 = "Snapshot 186-Velociraptor-MCP网络部署基线"
ENDPOINT_PATTERN = re.compile(r"^http://(\d{1,3}(?:\.\d{1,3}){3}):28790/mcp$")
REPORT_KEYS = {
    "schema_version",
    "scenario",
    "source_sha256",
    "index_sha256",
    "fixture_spec_sha256",
    "fixture_instance_sha256",
    "run_id",
    "transport",
    "endpoint",
    "authorization_configured",
    "tools_schema_sha256",
    "snapshot_evidence_sha256",
    "mcp_session",
    "server_identity",
    "server_observation_sha256",
    "runner",
    "started_at",
    "ended_at",
    "duration_ms",
    "status",
    "calls",
    "steps",
    "cleanup",
    "failure",
    "unexecuted_step_ids",
    "coverage",
}
LEDGER_IDENTITY_FIELDS = (
    "source_sha256",
    "index_sha256",
    "fixture_instance_sha256",
    "fixture_spec_sha256",
    "tools_schema_sha256",
)


class AggregateError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def contained_plain_file(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise AggregateError("report path must be relative and contained")
    path = root / candidate
    if not path.is_file() or path.is_symlink():
        raise AggregateError("report must be a plain file")
    resolved_root = root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise AggregateError("report escapes evidence root") from exc
    return resolved


def load_ledger(path: Path = LEDGER) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    attempts = [row.get("monotonic_attempt") for row in rows]
    if attempts != list(range(1, len(rows) + 1)):
        raise AggregateError("ledger attempt numbers are not continuous and monotonic")
    paths = [row.get("report_relative_path") for row in rows]
    report_hashes = [row.get("report_sha256") for row in rows]
    package_hashes = [row.get("package_sha256") for row in rows]
    if len(paths) != len(set(paths)) or len(report_hashes) != len(set(report_hashes)):
        raise AggregateError("ledger contains duplicate report identity")
    if len(package_hashes) != len(set(package_hashes)):
        raise AggregateError("ledger contains duplicate evidence package")
    return rows


def verify_tools_schema_binding(report: dict[str, Any], run_dir: Path) -> None:
    """tools-schema.json bytes, recomputed hash, and report hash must agree."""
    tools_path = run_dir / "tools-schema.json"
    if not tools_path.is_file() or tools_path.is_symlink():
        raise AggregateError("run directory lacks tools-schema.json")
    raw = tools_path.read_bytes()
    if sha256_bytes(raw) != report["tools_schema_sha256"]:
        raise AggregateError("tools-schema.json bytes differ from the report hash")
    document = json.loads(raw.decode("utf-8"))
    recomputed = sha256_bytes(canonical_bytes(document))
    if recomputed != report["tools_schema_sha256"]:
        raise AggregateError("tools-schema canonical recomputation differs")
    if len(document) != 130:
        raise AggregateError("tools-schema inventory does not contain 130 tools")


def verify_snapshot_evidence(report: dict[str, Any], run_dir: Path) -> dict[str, Any]:
    """Recompute snapshot-evidence.json and enforce the P06_ACTIVE restore."""
    evidence_path = run_dir / "snapshot-evidence.json"
    if not evidence_path.is_file() or evidence_path.is_symlink():
        raise AggregateError("run directory lacks snapshot-evidence.json")
    raw = evidence_path.read_bytes()
    if sha256_bytes(raw) != report["snapshot_evidence_sha256"]:
        raise AggregateError("snapshot-evidence.json bytes differ from the report hash")
    evidence = json.loads(raw.decode("utf-8"))
    if set(evidence) != {
        "restore",
        "scenario_id",
        "source_sha256",
        "index_sha256",
        "mcp_session_id",
        "server_instance_id",
        "server_observation_sha256",
    }:
        raise AggregateError("snapshot evidence keys are invalid")
    restore = evidence["restore"]
    if evidence["scenario_id"] != report["scenario"]:
        raise AggregateError("snapshot evidence scenario differs")
    if evidence["source_sha256"] != report["source_sha256"]:
        raise AggregateError("snapshot evidence source hash differs")
    if evidence["index_sha256"] != report["index_sha256"]:
        raise AggregateError("snapshot evidence index hash differs")
    if evidence["mcp_session_id"] != report["mcp_session"]["id"]:
        raise AggregateError("snapshot evidence session id differs")
    if evidence["server_instance_id"] != report["server_identity"]["instance_id"]:
        raise AggregateError("snapshot evidence instance id differs")
    if evidence["server_observation_sha256"] != report["server_observation_sha256"]:
        raise AggregateError("snapshot evidence observation hash differs")
    if restore.get("run_id") != report["run_id"]:
        raise AggregateError("snapshot evidence is bound to another run id")
    if restore.get("snapshot_stage") != "P06_ACTIVE" or restore.get("snapshot_name") != SNAPSHOT_186:
        raise AggregateError("formal P06 report is not bound to the activated Snapshot186 baseline")
    if (
        restore.get("canonical_schema_version") != 3
        or restore.get("canonical_epoch") != 4
        or restore.get("canonical_phase") != "NETWORK_ACTIVE"
    ):
        raise AggregateError("restore does not reference the activated schema3 state")
    return restore


def verify_report_shape(report: dict[str, Any]) -> None:
    if set(report) != REPORT_KEYS:
        raise AggregateError("report root keys do not match schema2")
    if report["schema_version"] != 2:
        raise AggregateError("formal P06 evidence must be schema2; schema1 is history-only")
    if report["transport"] != "streamable-http":
        raise AggregateError("formal P06 evidence must use the formal HTTP transport")
    if not report["endpoint"] or not ENDPOINT_PATTERN.match(report["endpoint"]):
        raise AggregateError("endpoint is not the sanitized formal entry URL")
    if report["authorization_configured"] is not True:
        raise AggregateError("formal report must record authorization_configured=true")
    session = report["mcp_session"]
    if set(session) != {"id", "initialized_at", "closed_at"}:
        raise AggregateError("mcp_session keys are invalid")
    if not session["id"] or not session["initialized_at"] or not session["closed_at"]:
        raise AggregateError("mcp_session lifecycle is incomplete")
    identity = report["server_identity"]
    if set(identity) != {
        "computer_name",
        "service_name",
        "pid",
        "process_start_time_utc",
        "instance_id",
        "executable_sha256",
    }:
        raise AggregateError("server_identity keys are invalid")
    if identity["computer_name"] != "DESKTOP-3FI41GR" or not identity["instance_id"]:
        raise AggregateError("server_identity is incomplete")
    if set(report["runner"]) != {"pid", "process_start_time_utc", "executable_sha256"}:
        raise AggregateError("runner identity keys are invalid")
    if not report["server_observation_sha256"]:
        raise AggregateError("server observation hash is missing")


def aggregate(
    *,
    evidence_root: Path = EVIDENCE_ROOT,
    ledger_path: Path = LEDGER,
    selection_path: Path = SELECTION,
    manifest_path: Path = MANIFEST,
) -> dict[str, Any]:
    ledger = load_ledger(ledger_path)
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_scenarios = manifest["scenario_ids"]
    if set(selection) != {"schema_version", "all_attempts", "selected"} or selection["schema_version"] != 1:
        raise AggregateError("invalid final selection shape")
    if selection["all_attempts"] != [row["monotonic_attempt"] for row in ledger]:
        raise AggregateError("final selection omits or reorders attempt history")
    selected = selection["selected"]
    if set(selected) != set(expected_scenarios) or len(selected) != 5:
        raise AggregateError("final selection must choose each reviewed scenario exactly once")
    ledger_by_attempt = {row["monotonic_attempt"]: row for row in ledger}
    reports: list[dict[str, Any]] = []
    input_hashes: list[dict[str, Any]] = []
    coverage: set[tuple[str, str]] = set()
    tools_hashes: set[str] = set()
    fixture_specs: set[str] = set()
    session_ids: set[str] = set()
    run_ids: set[str] = set()
    restore_attempts: set[str] = set()
    server_instances: set[str] = set()
    runner_identities: set[tuple[Any, Any]] = set()
    for scenario_id in expected_scenarios:
        chosen = selected[scenario_id]
        if set(chosen) != {"monotonic_attempt", "report_sha256"}:
            raise AggregateError("selected report identity is incomplete")
        ledger_row = ledger_by_attempt.get(chosen["monotonic_attempt"])
        if ledger_row is None or ledger_row["scenario"] != scenario_id:
            raise AggregateError("selected attempt belongs to another scenario")
        if ledger_row["report_sha256"] != chosen["report_sha256"]:
            raise AggregateError("selected report hash differs from ledger")
        report_path = contained_plain_file(evidence_root, ledger_row["report_relative_path"])
        actual_hash = sha256_file(report_path)
        if actual_hash != ledger_row["report_sha256"]:
            raise AggregateError("report bytes differ from the host receive ledger")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        verify_report_shape(report)
        if report["scenario"] != scenario_id or report["status"] != "success":
            raise AggregateError("selected report is not a successful matching scenario")
        sequences = [row.get("sequence") for row in report.get("calls", [])]
        if sequences != list(range(1, len(sequences) + 1)):
            raise AggregateError("report call sequence is not continuous")
        if report["unexecuted_step_ids"] or report["failure"]:
            raise AggregateError("successful report contains failure or unexecuted steps")
        if any(row.get("is_error") for row in report["calls"]):
            raise AggregateError("formal scenario contains an MCP error call")
        if len(report["coverage"]) != 130:
            raise AggregateError("selected report does not provide 130 relations")
        for row in report["coverage"]:
            key = (row.get("scenario_id"), row.get("tool"))
            if key in coverage:
                raise AggregateError("coverage relation is duplicated")
            coverage.add(key)
        run_dir = report_path.parent
        verify_tools_schema_binding(report, run_dir)
        restore = verify_snapshot_evidence(report, run_dir)
        session_ids.add(report["mcp_session"]["id"])
        run_ids.add(report["run_id"])
        restore_attempts.add(restore["restore_attempt_id"])
        server_instances.add(report["server_identity"]["instance_id"])
        runner = report["runner"]
        runner_identity = (runner.get("pid"), runner.get("process_start_time_utc"))
        if None in runner_identity:
            raise AggregateError("runner process identity is incomplete")
        runner_identities.add(runner_identity)
        tools_hashes.add(report["tools_schema_sha256"])
        fixture_specs.add(report["fixture_spec_sha256"])
        for field in LEDGER_IDENTITY_FIELDS:
            if report.get(field) != ledger_row.get(field):
                raise AggregateError(f"report identity field differs from ledger: {field}")
        reports.append(report)
        input_hashes.append(
            {
                "monotonic_attempt": ledger_row["monotonic_attempt"],
                "package_sha256": ledger_row["package_sha256"],
                "report_relative_path": ledger_row["report_relative_path"],
                "report_sha256": actual_hash,
                "restore_attempt_id": restore["restore_attempt_id"],
                "run_id": report["run_id"],
                "scenario": scenario_id,
            }
        )
    expected_relations = {(row["scenario_id"], row["tool"]) for row in manifest["relations"]}
    if coverage != expected_relations or len(coverage) != 650:
        raise AggregateError("manifest, scenario, and report coverage sets differ")
    if len(tools_hashes) != 1 or None in tools_hashes or len(fixture_specs) != 1:
        raise AggregateError("selected reports do not share tool and fixture identities")
    if len(session_ids) != 5 or len(run_ids) != 5:
        raise AggregateError("selected reports do not have five distinct sessions and runs")
    if len(restore_attempts) != 5:
        raise AggregateError("selected reports must prove five independent restore attempts")
    if len(runner_identities) != 5:
        raise AggregateError("selected scenarios do not have five distinct runner lifecycles")
    return {
        "schema_version": 2,
        "status": "success",
        "scenario_count": 5,
        "tool_count": 130,
        "relation_count": 650,
        "manifest_sha256": sha256_file(manifest_path),
        "ledger_sha256": sha256_file(ledger_path),
        "selection_sha256": sha256_file(selection_path),
        "tools_schema_sha256": next(iter(tools_hashes)),
        "fixture_spec_sha256": next(iter(fixture_specs)),
        "distinct_session_count": len(session_ids),
        "distinct_restore_attempt_count": len(restore_attempts),
        "runner_lifecycle_count": len(runner_identities),
        "server_instance_count": len(server_instances),
        "unexpected_error_count": 0,
        "unexecuted_step_count": 0,
        "inputs": input_hashes,
        "total_duration_ms": sum(row["duration_ms"] for row in reports),
    }


def main() -> int:
    result = aggregate()
    OUTPUT.write_bytes(canonical_bytes(result))
    print(json.dumps({"output": str(OUTPUT), "status": result["status"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
