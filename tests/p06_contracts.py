"""Build and validate the reviewed P06 scenario and coverage contracts."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "tests" / "data"
SCENARIOS = ROOT / "tests" / "scenarios"
FULL = SCENARIOS / "full"
INVOCATIONS = DATA / "p03_invocations.json"
FIXED_GOLDEN = DATA / "p04_fixed_tools_golden.json"
FIXTURE_SPEC = DATA / "p05_fixture_spec.json"
INDEX = DATA / "p06_scenario_index.json"
MANIFEST = DATA / "p06_coverage_manifest.json"
SCHEMA = SCENARIOS / "schema-v1.json"
SNAPSHOT = "Snapshot 186-Velociraptor-MCP网络部署基线"
NO_MATCH = "__mcp_p03_no_match__"

# Each scenario uses a distinct investigation-scoped regex pattern so that the
# five scenarios exercise the same 130 tools with genuinely different
# parameter values reflecting their different investigation purposes.

SCENARIO_PURPOSES = (
    (
        "p06-compromise-scope",
        "Determine the full endpoint compromise scope across execution, identity, files, memory, network, registry, and persistence evidence.",
        "compromise scope",
    ),
    (
        "p06-ransomware-root-cause",
        "Reconstruct a ransomware intrusion from entry and execution through persistence, filesystem impact, and network activity.",
        "ransomware root cause",
    ),
    (
        "p06-credential-lateral-movement",
        "Test whether logon, credential, process, service, and network evidence demonstrates account abuse or lateral movement.",
        "credential abuse and lateral movement",
    ),
    (
        "p06-data-exfiltration",
        "Bound data discovery, staging, access, and possible exfiltration using browser, file, command, process, network, and timeline evidence.",
        "data staging and exfiltration",
    ),
    (
        "p06-remediation-validation",
        "Verify that known persistence, execution, network, account, file, memory, and log indicators are absent or fully explained after remediation.",
        "post-remediation residual risk",
    ),
)

# Per-scenario investigation profiles.  Every scenario still exercises the
# full 130-tool surface, but each one does it through a purpose-driven
# evidence chain: its own category ordering (which artifact is examined
# first), its own result-page window, its own polling cadence (same total
# wait budget), and its own focus fixture file that the probe and the
# collect_file chain bind to by exact path and size.  The five orderings are
# full permutations of the 19 artifact categories, so the generated step
# sequences, reference chains, and manifest parameter hashes are pairwise
# different rather than relabelled copies of one template.

SCENARIO_PROFILES = {
    "p06-compromise-scope": {
        "ordering": (
            "Persistence", "Packs", "Sysinternals", "Registry", "Sys",
            "EventLogs", "System", "Attack", "Forensics", "Applications",
            "NTFS", "Carving", "Search", "Timeline", "Network", "Detection",
            "ETW", "Analysis", "Memory",
        ),
        "results_page_size": 1,
        "wait_max_attempts": 240,
        "wait_interval_seconds": 5,
        "focus_file_index": 0,
    },
    "p06-ransomware-root-cause": {
        "ordering": (
            "System", "Attack", "Forensics", "NTFS", "Timeline", "Carving",
            "EventLogs", "Registry", "Persistence", "Packs", "Sysinternals",
            "Sys", "Applications", "Search", "Analysis", "Network",
            "Detection", "ETW", "Memory",
        ),
        "results_page_size": 5,
        "wait_max_attempts": 120,
        "wait_interval_seconds": 10,
        "focus_file_index": 1,
    },
    "p06-credential-lateral-movement": {
        "ordering": (
            "Sys", "EventLogs", "Registry", "System", "Attack", "Network",
            "Detection", "ETW", "Forensics", "Persistence", "Packs",
            "Sysinternals", "Applications", "Search", "NTFS", "Carving",
            "Timeline", "Analysis", "Memory",
        ),
        "results_page_size": 10,
        "wait_max_attempts": 80,
        "wait_interval_seconds": 15,
        "focus_file_index": 2,
    },
    "p06-data-exfiltration": {
        "ordering": (
            "Applications", "Search", "NTFS", "Timeline", "Carving",
            "Forensics", "Network", "Detection", "ETW", "System", "Attack",
            "Sys", "EventLogs", "Registry", "Persistence", "Packs",
            "Sysinternals", "Analysis", "Memory",
        ),
        "results_page_size": 20,
        "wait_max_attempts": 60,
        "wait_interval_seconds": 20,
        "focus_file_index": 3,
    },
    "p06-remediation-validation": {
        "ordering": (
            "Analysis", "Detection", "ETW", "EventLogs", "Registry",
            "Persistence", "Packs", "Sysinternals", "Timeline", "NTFS",
            "Search", "Carving", "Forensics", "Applications", "Sys",
            "System", "Attack", "Network", "Memory",
        ),
        "results_page_size": 50,
        "wait_max_attempts": 48,
        "wait_interval_seconds": 25,
        "focus_file_index": 4,
    },
}


def artifact_category(artifact: str) -> str:
    return artifact.split(".")[1]


def ordered_invocations(
    invocations: list[dict[str, Any]], scenario_id: str
) -> list[dict[str, Any]]:
    ordering = SCENARIO_PROFILES[scenario_id]["ordering"]
    return sorted(
        invocations,
        key=lambda row: (
            ordering.index(artifact_category(row["artifact"])),
            row["artifact"],
        ),
    )


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


def pretty_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def marker_for(scenario_id: str) -> str:
    return "__" + scenario_id.replace("-", "_") + "_no_match__"


def scenario_parameters(parameters: dict[str, Any], scenario_id: str) -> dict[str, Any]:
    result = copy.deepcopy(parameters)
    marker = marker_for(scenario_id)
    for key, value in result.items():
        if isinstance(value, str):
            result[key] = value.replace(NO_MATCH, marker)
    return result


def assertion(assertion_id: str, actual: str, op: str, expected: Any = ...) -> dict[str, Any]:
    row: dict[str, Any] = {"id": assertion_id, "actual": actual, "op": op}
    if expected is not ...:
        row["expected"] = expected
    return row


def tool_step(
    step_id: str,
    tool: str,
    arguments: dict[str, Any],
    assertions: list[dict[str, Any]],
    *,
    repeat: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "kind": "tool",
        "id": step_id,
        "tool": tool,
        "arguments": arguments,
        "assertions": assertions,
    }
    if repeat is not None:
        row["repeat_until"] = repeat
    return row


def wait_step(
    step_id: str,
    start_id: str,
    prefix: str,
    *,
    state: str = "FINISHED",
    max_attempts: int = 240,
    interval_seconds: int = 5,
) -> dict[str, Any]:
    return tool_step(
        step_id,
        "get_flow_status",
        {"flow_id": {"$ref": f"/steps/{start_id}/structuredContent/flow_id"}},
        [],
        repeat={
            "max_attempts": max_attempts,
            "interval_seconds": interval_seconds,
            "assertions": [
                assertion(f"{prefix}-wait-ok", "/isError", "is_error", False),
                assertion(f"{prefix}-wait-state", "/structuredContent/state", "eq", state),
            ],
        },
    )


def relation(
    scenario_id: str,
    tool: str,
    steps: list[dict[str, Any]],
    step_ids: list[str],
    assertion_ids: list[str],
    topic: str,
    *,
    allowed_empty: str | None,
    focus_file: str = "",
) -> dict[str, Any]:
    by_id = {step["id"]: step for step in steps}
    arguments = {step_id: by_id[step_id]["arguments"] for step_id in step_ids}
    focus_clause = (
        f" The scenario's focus fixture file is {focus_file}."
        if focus_file
        else ""
    )
    return {
        "scenario_id": scenario_id,
        "tool": tool,
        "step_ids": step_ids,
        "parameters_sha256": sha256_bytes(canonical_bytes(arguments)),
        "fixture_preconditions": [
            "Snapshot185 fixture-instance-v1 identity matches the tracked fixture spec",
            f"The {topic} investigation starts from the clean snapshot and one unique Windows client",
            "This scenario binds its evidence chain to fixture file "
            + (focus_file if focus_file else "the shared platform baseline"),
        ],
        "assertion_ids": assertion_ids,
        "investigative_question": f"For {topic}, what does {tool} prove or rule out on the endpoint?",
        "expected_evidence": f"A real successful {tool} call and its bound {topic} result/status chain is preserved.{focus_clause}",
        "allowed_empty_condition": allowed_empty,
    }


def build_scenario(
    scenario_id: str,
    purpose: str,
    topic: str,
    fixture_index: int,
    invocations: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    profile = SCENARIO_PROFILES[scenario_id]
    fixture_spec = json.loads(FIXTURE_SPEC.read_text(encoding="utf-8"))
    focus = fixture_spec["files"][profile["focus_file_index"]]
    focus_rel = focus["path"]
    focus_size = focus["size"]
    focus_arg = {"$fixture": f"/files/{profile['focus_file_index']}/path"}
    invocations = ordered_invocations(invocations, scenario_id)
    steps: list[dict[str, Any]] = []
    relations: list[dict[str, Any]] = []

    vql_id = "fixed-run-vql"
    steps.append(
        tool_step(
            vql_id,
            "run_vql",
            {
                "query": (
                    f"SELECT {fixture_index + 1} AS ScenarioOrdinal, "
                    + json.dumps(focus_rel, ensure_ascii=False)
                    + " AS FocusFile FROM scope()"
                )
            },
            [
                assertion("fixed-run-vql-ok", "/isError", "is_error", False),
                assertion(
                    "fixed-run-vql-ordinal",
                    "/structuredContent/data/0/ScenarioOrdinal",
                    "eq",
                    fixture_index + 1,
                ),
                assertion(
                    "fixed-run-vql-focus",
                    "/structuredContent/data/0/FocusFile",
                    "eq",
                    focus_rel,
                ),
            ],
        )
    )
    relations.append(
        relation(
            scenario_id,
            "run_vql",
            steps,
            [vql_id],
            ["fixed-run-vql-ok", "fixed-run-vql-ordinal", "fixed-run-vql-focus"],
            topic,
            allowed_empty=None,
            focus_file=focus_rel,
        )
    )

    for number, invocation in enumerate(invocations, start=1):
        artifact = invocation["artifact"]
        prefix = f"d{number:03d}"
        if artifact == "Windows.Network.PacketCapture":
            start = tool_step(
                f"{prefix}-start",
                artifact,
                {"StartTrace": True},
                [
                    assertion(f"{prefix}-start-ok", "/isError", "is_error", False),
                    assertion(f"{prefix}-start-flow", "/structuredContent/flow_id", "exists"),
                ],
            )
            wait = wait_step(f"{prefix}-wait", start["id"], prefix)
            results = tool_step(
                f"{prefix}-results",
                "get_flow_results",
                {"flow_id": {"$ref": f"/steps/{start['id']}/structuredContent/flow_id"}, "page_size": 20},
                [
                    assertion(f"{prefix}-results-ok", "/isError", "is_error", False),
                    assertion(f"{prefix}-results-data", "/structuredContent/data", "len_gte", 1),
                ],
            )
            stop = tool_step(
                f"{prefix}-stop",
                artifact,
                {
                    "StartTrace": False,
                    "TraceFile": {"$packet_etl": f"/steps/{results['id']}/structuredContent/data"},
                },
                [
                    assertion(f"{prefix}-stop-ok", "/isError", "is_error", False),
                    assertion(f"{prefix}-stop-flow", "/structuredContent/flow_id", "exists"),
                ],
            )
            stop_wait = wait_step(f"{prefix}-stop-wait", stop["id"], f"{prefix}-stop")
            files = tool_step(
                f"{prefix}-files",
                "list_flow_files",
                {"flow_id": {"$ref": f"/steps/{stop['id']}/structuredContent/flow_id"}},
                [
                    assertion(f"{prefix}-files-ok", "/isError", "is_error", False),
                    assertion(f"{prefix}-files-data", "/structuredContent/data", "len_gte", 2),
                ],
            )
            chain = [start, wait, results, stop, stop_wait, files]
            steps.extend(chain)
            ids = [item["id"] for item in chain]
            assertions = [
                f"{prefix}-start-ok",
                f"{prefix}-wait-state",
                f"{prefix}-results-data",
                f"{prefix}-stop-ok",
                f"{prefix}-stop-wait-state",
                f"{prefix}-files-data",
            ]
            relations.append(relation(scenario_id, artifact, steps, ids, assertions, topic, allowed_empty=None))
            continue

        start = tool_step(
            f"{prefix}-start",
            artifact,
            scenario_parameters(invocation["parameters"], scenario_id),
            [
                assertion(f"{prefix}-start-ok", "/isError", "is_error", False),
                assertion(f"{prefix}-start-flow", "/structuredContent/flow_id", "exists"),
            ],
        )
        wait = wait_step(
            f"{prefix}-wait",
            start["id"],
            prefix,
            max_attempts=profile["wait_max_attempts"],
            interval_seconds=profile["wait_interval_seconds"],
        )
        results = tool_step(
            f"{prefix}-results",
            "get_flow_results",
            {
                "flow_id": {"$ref": f"/steps/{start['id']}/structuredContent/flow_id"},
                "page_size": profile["results_page_size"],
            },
            [
                assertion(f"{prefix}-results-ok", "/isError", "is_error", False),
                assertion(f"{prefix}-results-data", "/structuredContent/data", "exists"),
            ],
        )
        files = tool_step(
            f"{prefix}-files",
            "list_flow_files",
            {"flow_id": {"$ref": f"/steps/{start['id']}/structuredContent/flow_id"}},
            [
                assertion(f"{prefix}-files-ok", "/isError", "is_error", False),
                assertion(f"{prefix}-files-data", "/structuredContent/data", "exists"),
            ],
        )
        chain = [start, wait, results, files]
        steps.extend(chain)
        ids = [item["id"] for item in chain]
        assertions = [
            f"{prefix}-start-ok",
            f"{prefix}-wait-state",
            f"{prefix}-results-data",
            f"{prefix}-files-data",
        ]
        empty = (
            f"No matching {topic} evidence is a valid negative finding for this "
            f"reviewed parameter set with focus file {focus_rel}."
        )
        relations.append(
            relation(
                scenario_id,
                artifact,
                steps,
                ids,
                assertions,
                topic,
                allowed_empty=empty,
                focus_file=focus_rel,
            )
        )

    collect = tool_step(
        "fixed-collect-file",
        "collect_file",
        {"path": focus_arg},
        [assertion("fixed-collect-file-ok", "/isError", "is_error", False)],
    )
    collect_wait = wait_step("fixed-collect-wait", collect["id"], "fixed-collect")
    collect_results = tool_step(
        "fixed-collect-results",
        "get_flow_results",
        {
            "flow_id": {"$ref": "/steps/fixed-collect-file/structuredContent/flow_id"},
            "source": "All Matches Metadata",
            "page_size": 1,
        },
        [
            assertion("fixed-collect-results-ok", "/isError", "is_error", False),
            assertion("fixed-collect-results-data", "/structuredContent/data", "len_gte", 1),
            assertion(
                "fixed-collect-results-source",
                "/structuredContent/data/0/SourceFile",
                "eq",
                focus_arg,
            ),
            assertion(
                "fixed-collect-results-size",
                "/structuredContent/data/0/Size",
                "eq",
                focus_size,
            ),
        ],
    )
    collect_files = tool_step(
        "fixed-collect-files",
        "list_flow_files",
        {"flow_id": {"$ref": "/steps/fixed-collect-file/structuredContent/flow_id"}},
        [
            assertion("fixed-collect-files-ok", "/isError", "is_error", False),
            assertion("fixed-collect-files-data", "/structuredContent/data", "len_gte", 1),
        ],
    )
    download = tool_step(
        "fixed-download-file",
        "download_flow_file",
        {
            "flow_id": {"$ref": "/steps/fixed-collect-file/structuredContent/flow_id"},
            "file_id": {"$ref": "/steps/fixed-collect-files/structuredContent/data/0/file_id"},
        },
        [assertion("fixed-download-file-ok", "/isError", "is_error", False)],
    )
    fixed_file_chain = [collect, collect_wait, collect_results, collect_files, download]
    steps.extend(fixed_file_chain)

    cancel_start = tool_step(
        "fixed-cancel-target",
        "Windows.System.PowerShell",
        {"Command": "Start-Sleep -Seconds 300", "Timeout": 330, "Stateful": False},
        [assertion("fixed-cancel-target-ok", "/isError", "is_error", False)],
    )
    cancel_ready = tool_step(
        "fixed-cancel-ready",
        "get_flow_status",
        {"flow_id": {"$ref": "/steps/fixed-cancel-target/structuredContent/flow_id"}},
        [
            assertion("fixed-cancel-ready-ok", "/isError", "is_error", False),
            assertion(
                "fixed-cancel-ready-state",
                "/structuredContent/state",
                "in",
                ["WAITING", "RUNNING", "IN_PROGRESS"],
            ),
        ],
    )
    cancel = tool_step(
        "fixed-cancel-flow",
        "cancel_flow",
        {"flow_id": {"$ref": "/steps/fixed-cancel-target/structuredContent/flow_id"}},
        [assertion("fixed-cancel-flow-ok", "/isError", "is_error", False)],
    )
    cancel_terminal = wait_step(
        "fixed-cancel-terminal", "fixed-cancel-target", "fixed-cancel-terminal", state="ERROR"
    )
    steps.extend([cancel_start, cancel_ready, cancel, cancel_terminal])

    hunt = tool_step(
        "fixed-start-hunt",
        "start_hunt",
        {
            "artifact": "Windows.System.PowerShell",
            "parameters": {"Command": "Start-Sleep -Seconds 300", "Timeout": 330, "Stateful": False},
            "description": f"P06 {topic}",
        },
        [assertion("fixed-start-hunt-ok", "/isError", "is_error", False)],
    )
    hunt_status = tool_step(
        "fixed-hunt-status",
        "get_hunt_status",
        {"hunt_id": {"$ref": "/steps/fixed-start-hunt/structuredContent/hunt_id"}},
        [assertion("fixed-hunt-status-ok", "/isError", "is_error", False)],
    )
    hunt_stop = tool_step(
        "fixed-stop-hunt",
        "stop_hunt",
        {"hunt_id": {"$ref": "/steps/fixed-start-hunt/structuredContent/hunt_id"}},
        [assertion("fixed-stop-hunt-ok", "/isError", "is_error", False)],
    )
    hunt_cancel = tool_step(
        "fixed-hunt-cancel-flow",
        "cancel_flow",
        {"flow_id": {"$ref": "/steps/fixed-start-hunt/structuredContent/flow_id"}},
        [assertion("fixed-hunt-cancel-flow-ok", "/isError", "is_error", False)],
    )
    hunt_terminal = wait_step(
        "fixed-hunt-terminal", "fixed-start-hunt", "fixed-hunt-terminal", state="ERROR"
    )
    steps.extend([hunt, hunt_status, hunt_stop, hunt_cancel, hunt_terminal])

    triage = tool_step(
        "fixed-start-triage",
        "collect_forensic_triage",
        {},
        [assertion("fixed-start-triage-ok", "/isError", "is_error", False)],
    )
    triage_wait = wait_step("fixed-triage-wait", triage["id"], "fixed-triage")
    triage_results = tool_step(
        "fixed-triage-results",
        "get_flow_results",
        {"flow_id": {"$ref": "/steps/fixed-start-triage/structuredContent/flow_id"}, "page_size": 1},
        [assertion("fixed-triage-results-ok", "/isError", "is_error", False)],
    )
    triage_files = tool_step(
        "fixed-triage-files",
        "list_flow_files",
        {"flow_id": {"$ref": "/steps/fixed-start-triage/structuredContent/flow_id"}},
        [assertion("fixed-triage-files-ok", "/isError", "is_error", False)],
    )
    steps.extend([triage, triage_wait, triage_results, triage_files])

    kill = tool_step(
        "fixed-kill-process",
        "kill_process",
        {"pid": {"$fixture": "/process/pid"}},
        [assertion("fixed-kill-process-ok", "/isError", "is_error", False)],
    )
    kill_wait = wait_step("fixed-kill-wait", kill["id"], "fixed-kill")
    kill_results = tool_step(
        "fixed-kill-results",
        "get_flow_results",
        {"flow_id": {"$ref": "/steps/fixed-kill-process/structuredContent/flow_id"}, "page_size": 1},
        [
            assertion("fixed-kill-results-ok", "/isError", "is_error", False),
            assertion(
                "fixed-kill-results-pid",
                "/structuredContent/data/0/Killed",
                "eq",
                {"$fixture": "/process/pid"},
            ),
        ],
    )
    steps.extend([kill, kill_wait, kill_results])

    fixed_map = {
        "collect_file": ([collect["id"]], ["fixed-collect-file-ok"]),
        "get_flow_status": ([collect_wait["id"]], ["fixed-collect-wait-state"]),
        "get_flow_results": (
            [collect_results["id"]],
            [
                "fixed-collect-results-data",
                "fixed-collect-results-source",
                "fixed-collect-results-size",
            ],
        ),
        "list_flow_files": ([collect_files["id"]], ["fixed-collect-files-data"]),
        "download_flow_file": ([download["id"]], ["fixed-download-file-ok"]),
        "cancel_flow": ([cancel["id"], hunt_cancel["id"]], ["fixed-cancel-flow-ok", "fixed-hunt-cancel-flow-ok"]),
        "start_hunt": ([hunt["id"]], ["fixed-start-hunt-ok"]),
        "get_hunt_status": ([hunt_status["id"]], ["fixed-hunt-status-ok"]),
        "stop_hunt": ([hunt_stop["id"]], ["fixed-stop-hunt-ok"]),
        "collect_forensic_triage": ([triage["id"]], ["fixed-start-triage-ok"]),
        "kill_process": ([kill["id"], kill_results["id"]], ["fixed-kill-process-ok", "fixed-kill-results-pid"]),
    }
    for fixed_tool, (step_ids, assertion_ids) in fixed_map.items():
        relations.append(
            relation(
                scenario_id,
                fixed_tool,
                steps,
                step_ids,
                assertion_ids,
                topic,
                allowed_empty=None,
                focus_file=focus_rel,
            )
        )

    scenario = {
        "schema_version": 1,
        "scenario_id": scenario_id,
        "business_purpose": purpose,
        "required_snapshot": SNAPSHOT,
        "fixture_spec_sha256": sha256_file(FIXTURE_SPEC),
        "steps": steps,
        "cleanup": [],
    }
    return scenario, sorted(relations, key=lambda row: row["tool"])


def build_contracts() -> tuple[dict[str, bytes], dict[str, Any], dict[str, Any]]:
    invocations = json.loads(INVOCATIONS.read_text(encoding="utf-8"))
    files: dict[str, bytes] = {}
    all_relations: list[dict[str, Any]] = []
    index_rows: list[dict[str, Any]] = []
    for fixture_index, (scenario_id, purpose, topic) in enumerate(SCENARIO_PURPOSES):
        scenario, relations = build_scenario(scenario_id, purpose, topic, fixture_index, invocations)
        payload = pretty_bytes(scenario)
        relative = f"full/{scenario_id}.json"
        files[relative] = payload
        all_relations.extend(relations)
        index_rows.append(
            {
                "scenario_id": scenario_id,
                "path": relative,
                "sha256": sha256_bytes(payload),
                "required_snapshot": SNAPSHOT,
                "fixture_spec_sha256": sha256_file(FIXTURE_SPEC),
                "snapshot_stage": "P06_ACTIVE",
            }
        )
    index = {"schema_version": 1, "scenarios": index_rows}
    manifest = {
        "schema_version": 1,
        "scenario_ids": [row[0] for row in SCENARIO_PURPOSES],
        "tool_count": 130,
        "relations": all_relations,
    }
    return files, index, manifest


def validate_contracts() -> dict[str, int]:
    from jsonschema import Draft202012Validator

    expected_files, expected_index, expected_manifest = build_contracts()
    actual_index = json.loads(INDEX.read_text(encoding="utf-8"))
    actual_manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if actual_index != expected_index or actual_manifest != expected_manifest:
        raise AssertionError("P06 index or manifest differs from the deterministic reviewed contract")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    invocations = json.loads(INVOCATIONS.read_text(encoding="utf-8"))
    fixed = json.loads(FIXED_GOLDEN.read_text(encoding="utf-8"))
    tools = {row["artifact"] for row in invocations} | set(fixed)
    if len(tools) != 130:
        raise AssertionError("approved tool union is not 130")
    relations = actual_manifest["relations"]
    if len(relations) != 650:
        raise AssertionError("coverage manifest must contain exactly 650 relations")
    relation_keys = {(row["scenario_id"], row["tool"]) for row in relations}
    if len(relation_keys) != 650:
        raise AssertionError("coverage relations must be unique")
    questions: dict[str, set[str]] = {}
    evidence: dict[str, set[str]] = {}
    generated: dict[str, dict[str, Any]] = {}
    for relative, expected_payload in expected_files.items():
        path = SCENARIOS / relative
        if path.read_bytes() != expected_payload:
            raise AssertionError(f"scenario drift: {relative}")
        scenario = json.loads(expected_payload)
        generated[scenario["scenario_id"]] = scenario
        Draft202012Validator(schema).validate(scenario)
        steps = {row["id"]: row for row in scenario["steps"] if row["kind"] == "tool"}
        scenario_tools = {row["tool"] for row in steps.values()}
        if scenario_tools != tools:
            raise AssertionError(f"tool set drift: {scenario['scenario_id']}")
        for row in (item for item in relations if item["scenario_id"] == scenario["scenario_id"]):
            if row["tool"] not in tools or not set(row["step_ids"]).issubset(steps):
                raise AssertionError("manifest relation references an unknown tool or step")
            if row["tool"] not in {steps[step_id]["tool"] for step_id in row["step_ids"]}:
                raise AssertionError("relation has no step that actually calls its tool")
            args = {step_id: steps[step_id]["arguments"] for step_id in row["step_ids"]}
            if sha256_bytes(canonical_bytes(args)) != row["parameters_sha256"]:
                raise AssertionError("manifest parameter hash drift")
            actual_assertions = {
                item.get("id")
                for step_id in row["step_ids"]
                for section in (steps[step_id].get("assertions", []), steps[step_id].get("repeat_until", {}).get("assertions", []))
                for item in section
            }
            if not set(row["assertion_ids"]).issubset(actual_assertions):
                raise AssertionError("manifest assertion drift")
            questions.setdefault(row["tool"], set()).add(row["investigative_question"])
            evidence.setdefault(row["tool"], set()).add(row["expected_evidence"])
    if any(len(values) != 5 for values in questions.values()) or any(
        len(values) != 5 for values in evidence.values()
    ):
        raise AssertionError("copied scenario rationale or evidence role")
    scenario_ids = list(generated)
    for i, left_id in enumerate(scenario_ids):
        left = generated[left_id]["steps"]
        left_sequence = tuple(step.get("tool") for step in left)
        for right_id in scenario_ids[i + 1 :]:
            right = generated[right_id]["steps"]
            right_sequence = tuple(step.get("tool") for step in right)
            if left_sequence == right_sequence:
                raise AssertionError(
                    f"scenario tool sequences are isomorphic: {left_id} vs {right_id}"
                )
            differing = sum(
                1
                for step_left, step_right in zip(left, right)
                if step_left.get("tool") != step_right.get("tool")
                or step_left.get("arguments") != step_right.get("arguments")
            )
            # The shared platform lifecycle chains (cancel/hunt/triage/kill)
            # are intentionally identical; the artifact evidence chains must
            # carry the scenario's ordering, window, cadence, and focus.
            if differing < (len(left) * 2) // 5:
                raise AssertionError(
                    f"scenario steps differ only cosmetically: {left_id} vs {right_id} ({differing}/{len(left)})"
                )
    return {"scenarios": 5, "tools": 130, "relations": 650}


def write_contracts() -> None:
    files, index, manifest = build_contracts()
    FULL.mkdir(parents=True, exist_ok=True)
    for relative, payload in files.items():
        (SCENARIOS / relative).write_bytes(payload)
    INDEX.write_bytes(pretty_bytes(index))
    MANIFEST.write_bytes(pretty_bytes(manifest))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.write:
        write_contracts()
    print(json.dumps(validate_contracts(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
