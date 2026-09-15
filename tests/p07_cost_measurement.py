"""ACC-024 cost measurement v2: real captures, real run data, same methodology.

Inputs (content-addressed, no estimates substituted for measurements):

- Upstream 78-tool baseline: a real stdio tools/list capture of the unchanged
  upstream bridge source (git 9dc8054, the P01-verified baseline blob) run on
  the same VM, venv, and mcp 2.x SDK as the current product, via a FastMCP ->
  MCPServer alias shim (Logs/P07/upstream78-launcher.py). The P01 evidence
  (stdio-probe-stderr.txt) shows the upstream code has never been runnable in
  this environment with an mcp v1 SDK, so both sides are rendered by the same
  installed SDK and differ only in their tool set.
- Current 130-tool face: the live tools/list schema captured inside every
  formal P06 report run (tools-schema.json, identical across the five runs).
- Fixed investigation task costs: real call/retry/output measurements from the
  five formal differentiated P06 scenario reports.

Boundary ruling (P07 plan section 4.2): the schema dimension has a complete
two-sided comparison; the fixed-task dimension has no comparable upstream run
baseline (P01 recorded static registration counts only), which is disclosed
as-is rather than fabricated. The report does not preset a "smaller/better"
direction.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_CAPTURE = REPO_ROOT / "Logs" / "P07" / "upstream78-tools-list.jsonl"
UPSTREAM_TASK = REPO_ROOT / "Logs" / "P07" / "upstream78-fixed-task.json"
P06_ROOT = REPO_ROOT / "Logs" / "P06" / "wf-01a05d1d-p06-r3"
SCENARIOS = (
    "p06-compromise-scope",
    "p06-ransomware-root-cause",
    "p06-credential-lateral-movement",
    "p06-data-exfiltration",
    "p06-remediation-validation",
)
COST_PAIR_GROUPS = {
    "p06-compromise-scope": "g1-compromise-scope",
    "p06-ransomware-root-cause": "g2-ransomware-root-cause",
    "p06-credential-lateral-movement": "g3-credential-lateral-movement",
    "p06-data-exfiltration": "g4-data-exfiltration",
    "p06-remediation-validation": "g5-remediation-validation",
}


def final_selection_runs() -> dict[str, str]:
    """Resolve the five final-selection run ids from the r3 receive ledger."""
    r3 = P06_ROOT
    selection = json.loads((r3 / "final-selection.json").read_text(encoding="utf-8"))
    rows = {
        row["monotonic_attempt"]: row
        for row in (
            json.loads(line)
            for line in (r3 / "接收清单.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    }
    runs = {}
    for scenario, chosen in selection["selected"].items():
        relative = rows[chosen["monotonic_attempt"]]["report_relative_path"]
        runs[scenario] = relative.split("/")[1]
    if set(runs) != set(SCENARIOS):
        raise ValueError("final selection does not cover the five scenarios")
    return runs


OUTPUT = REPO_ROOT / "Logs" / "P07" / "cost-measurement.json"


def canonical_text(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def upstream_tools() -> tuple[list[dict], str]:
    raw = UPSTREAM_CAPTURE.read_text(encoding="utf-8")
    tools_response = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        document = json.loads(line)
        if document.get("id") == 2:
            tools_response = document
    if tools_response is None:
        raise ValueError("upstream capture lacks the tools/list response")
    return tools_response["result"]["tools"], sha256_file(UPSTREAM_CAPTURE)


def current_tools() -> tuple[list[dict], str, str]:
    hashes: set[str] = set()
    tools: list[dict] | None = None
    runs = final_selection_runs()
    for scenario in SCENARIOS:
        path = P06_ROOT / scenario / runs[scenario] / "tools-schema.json"
        hashes.add(sha256_file(path))
        tools = json.loads(path.read_text(encoding="utf-8"))
    if len(hashes) != 1:
        raise ValueError("the five formal runs do not share one tools schema")
    if tools is None or len(tools) != 130:
        raise ValueError("current tools schema is not the 130-tool inventory")
    return tools, hashes.pop(), "formal-HTTP-session-captured"


def measure_task_costs() -> list[dict]:
    rows = []
    runs = final_selection_runs()
    for scenario in SCENARIOS:
        path = P06_ROOT / scenario / runs[scenario] / "report.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        calls = report["calls"]
        retry_calls = sum(1 for call in calls if call.get("attempt", 1) > 1)
        output_bytes = sum(
            len(canonical_text(call.get("structured")).encode("utf-8")) for call in calls
        )
        rows.append(
            {
                "scenario": scenario,
                "run_id": runs[scenario],
                "report_sha256": sha256_file(path),
                "tool_calls": len(calls),
                "retry_calls_beyond_first_attempt": retry_calls,
                "max_attempt_observed": max(call.get("attempt", 1) for call in calls),
                "structured_output_bytes_sum": output_bytes,
                "duration_ms": report["duration_ms"],
            }
        )
    return rows


def current_task_chain_rows() -> list[dict]:
    """The current-side RecycleBin evidence chain of each final-selection run.

    Calls are bound by the RecycleBin flow id (not step-name heuristics):
    the start call plus every status/results/files call that references the
    same flow. Poll rounds that did not yet observe FINISHED are the real
    retries, mirroring the externally observed upstream retry rounds.
    """
    rows = []
    runs = final_selection_runs()
    for scenario in SCENARIOS:
        path = P06_ROOT / scenario / runs[scenario] / "report.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        start = next(
            call for call in report["calls"] if call.get("tool") == "Windows.Forensics.RecycleBin"
        )
        flow_id = (start.get("structured") or {}).get("flow_id")
        if not flow_id:
            raise ValueError(f"{scenario}: RecycleBin start lacks its flow identity")
        # P04 result/file models intentionally do not echo flow_id; bind by
        # the request arguments as well as the status echo.
        chain = [
            call
            for call in report["calls"]
            if call is start
            or (
                call.get("tool") in {"get_flow_status", "get_flow_results", "list_flow_files"}
                and (
                    (call.get("structured") or {}).get("flow_id") == flow_id
                    or call.get("arguments", {}).get("flow_id") == flow_id
                )
            )
        ]
        wait_rounds = [c for c in chain if c.get("tool") == "get_flow_status"]
        retry_rounds = sum(
            1 for c in wait_rounds if (c.get("structured") or {}).get("state") != "FINISHED"
        )
        results_calls = [c for c in chain if c.get("tool") == "get_flow_results"]
        rows.append(
            {
                "scenario": scenario,
                "run_id": runs[scenario],
                "flow_id": flow_id,
                "tool_calls": len(chain),
                "poll_rounds": len(wait_rounds),
                "retry_rounds": retry_rounds,
                "structured_output_bytes": sum(
                    len(canonical_text(call.get("structured")).encode("utf-8")) for call in chain
                ),
                "elapsed_seconds": (
                    datetime.fromisoformat(chain[-1]["ended_at"].replace("Z", "+00:00"))
                    - datetime.fromisoformat(chain[0]["started_at"].replace("Z", "+00:00"))
                ).total_seconds(),
                "results_rows": sum(
                    len(
                        ((call.get("structured") or {}).get("data"))
                        or ((call.get("structured") or {}).get("rows"))
                        or []
                    )
                    for call in results_calls
                ),
                "file_rows": sum(
                    len(
                        ((call.get("structured") or {}).get("files"))
                        or ((call.get("structured") or {}).get("data"))
                        or []
                    )
                    for call in chain
                    if call.get("tool") == "list_flow_files"
                ),
            }
        )
    return rows


def upstream_group_rows() -> list[dict]:
    """The five upstream fixed-task runs, one per restored-188 group."""
    rows = []
    for scenario, group in COST_PAIR_GROUPS.items():
        path = REPO_ROOT / "Logs" / "P07" / "cost-pairs" / group / "upstream-task.json"
        if not path.is_file():
            raise ValueError(f"upstream group missing: {group}")
        task = json.loads(path.read_text(encoding="utf-8"))
        if task.get("status") != "success":
            raise ValueError(f"upstream group {group} did not succeed: {task.get('failure')}")
        rows.append(
            {
                "scenario": scenario,
                "group": group,
                "restore_bound": task.get("group"),
                "transport": task["transport"],
                "tool_calls": task["call_count"],
                "results_rounds": task["results_rounds"],
                "retry_rounds": task["retry_rounds"],
                "structured_output_bytes": sum(call["payload_bytes"] for call in task["calls"]),
                "elapsed_seconds": sum(call["elapsed_seconds"] for call in task["calls"]),
                "results_rows": task["results_rows"],
                "file_rows": task["file_list_rows"] or 0,
                "calls": [
                    {
                        "tool": call["tool"],
                        "is_error": call["is_error"],
                        "elapsed_seconds": call["elapsed_seconds"],
                        "payload_bytes": call["payload_bytes"],
                    }
                    for call in task["calls"]
                ],
            }
        )
    return rows


def cost_pair_rows(upstream: list[dict], current: list[dict]) -> list[dict]:
    by_scenario = {row["scenario"]: row for row in current}
    pairs = []
    for up in upstream:
        cur = by_scenario[up["scenario"]]
        pairs.append(
            {
                "scenario": up["scenario"],
                "upstream": up,
                "current": cur,
                "deltas_current_minus_upstream": {
                    "tool_calls": cur["tool_calls"] - up["tool_calls"],
                    "retry_rounds": cur["retry_rounds"] - up["retry_rounds"],
                    "structured_output_bytes": cur["structured_output_bytes"]
                    - up["structured_output_bytes"],
                    "results_rows": cur["results_rows"] - up["results_rows"],
                    "file_rows": cur["file_rows"] - up["file_rows"],
                },
                "transport_disclosure": (
                    "upstream: windows-isolated stdio subprocess (git 9dc8054 via the "
                    "FastMCP->MCPServer shim); current: formal external streamable-http "
                    "session of the final-selection run; the transports differ by design "
                    "and are not claimed to be one client environment"
                ),
            }
        )
    return pairs


def main() -> int:
    upstream, upstream_capture_sha = upstream_tools()
    current, current_schema_sha, current_source = current_tools()
    upstream_groups = upstream_group_rows()
    current_task_chains = current_task_chain_rows()
    pairs = cost_pair_rows(upstream_groups, current_task_chains)

    def face(tools: list[dict]) -> dict:
        text = canonical_text(tools)
        data = text.encode("utf-8")
        return {
            "tool_count": len(tools),
            "canonical_json_bytes": len(data),
            "canonical_json_sha256": hashlib.sha256(data).hexdigest(),
            "token_estimate_chars_div_4": len(text) // 4,
        }

    upstream_face = face(upstream)
    current_face = face(current)
    task_rows = measure_task_costs()

    report = {
        "schema": "p07-cost-measurement-v2",
        "measured_at": datetime.now(UTC).isoformat(),
        "methodology": {
            "canonical_serialization": "json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))",
            "token_estimate": "canonical JSON characters divided by 4; documented approximation, not a tokenizer measurement",
            "upstream_rendering": (
                "unchanged upstream source (git 9dc8054) executed on the same VM/venv/mcp-2.x SDK "
                "via the FastMCP->MCPServer alias shim (Logs/P07/upstream78-launcher.py, "
                "content-addressed); P01 evidence shows mcp v1 was never installed in this "
                "environment, so both sides are rendered by the same installed SDK"
            ),
            "current_rendering": "live tools/list captured in each formal P06 HTTP session (tools-schema.json)",
            "task_cost_source": "runner-recorded structured outputs of the five formal differentiated P06 runs",
        },
        "tool_face": {
            "upstream_78": {
                **upstream_face,
                "capture_file": "Logs/P07/upstream78-tools-list.jsonl",
                "capture_sha256": upstream_capture_sha,
            },
            "current_130": {
                **current_face,
                "tools_schema_sha256": current_schema_sha,
                "source": current_source,
            },
            "comparison": {
                "tool_count_delta": current_face["tool_count"] - upstream_face["tool_count"],
                "canonical_bytes_delta": current_face["canonical_json_bytes"]
                - upstream_face["canonical_json_bytes"],
                "token_estimate_delta": current_face["token_estimate_chars_div_4"]
                - upstream_face["token_estimate_chars_div_4"],
            },
        },
        "fixed_investigation_task_costs": {
            "per_scenario": task_rows,
            "totals": {
                "tool_calls": sum(row["tool_calls"] for row in task_rows),
                "retry_calls_beyond_first_attempt": sum(
                    row["retry_calls_beyond_first_attempt"] for row in task_rows
                ),
                "structured_output_bytes_sum": sum(
                    row["structured_output_bytes_sum"] for row in task_rows
                ),
                "duration_ms_sum": sum(row["duration_ms"] for row in task_rows),
            },
            "five_cost_pairs": {
                "methodology": (
                    "each of the five upstream groups ran the fixed RecycleBin investigation "
                    "endpoint (collect_artifact -> externally observed get_collection_results "
                    "rounds with max_retries=1 so every internal retry is a recorded round -> "
                    "bounded uploads file list via the upstream native run_vql) on its own "
                    "independent restore of the activated Snapshot188, in a Windows isolated "
                    "stdio subprocess; the current side is the same endpoint's evidence chain "
                    "from the final-selection formal HTTP run of the same scenario"
                ),
                "pairs": pairs,
            },
        },
        "conclusion": (
            "Raw measured quantities with the stated methodology; no preset smaller/better "
            "direction. The current 130-tool face is larger than the upstream 78-tool face "
            "on every schema dimension. The five fixed-task pairs are comparable per group "
            "on call counts, retry rounds, structured-output bytes, result rows and file "
            "rows; elapsed times cross transports (stdio vs formal HTTP) and are disclosed "
            "as such rather than claimed equivalent."
        ),
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "out": str(OUTPUT),
                "upstream_tools": upstream_face["tool_count"],
                "current_tools": current_face["tool_count"],
                "upstream_bytes": upstream_face["canonical_json_bytes"],
                "current_bytes": current_face["canonical_json_bytes"],
                "task_calls_total": report["fixed_investigation_task_costs"]["totals"]["tool_calls"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
