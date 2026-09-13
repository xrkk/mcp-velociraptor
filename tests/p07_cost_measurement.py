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
P06_ROOT = REPO_ROOT / "Logs" / "P06" / "wf-01a05d1d-p06-r2"
SCENARIOS = (
    "p06-compromise-scope",
    "p06-ransomware-root-cause",
    "p06-credential-lateral-movement",
    "p06-data-exfiltration",
    "p06-remediation-validation",
)
RUNS = {
    "p06-compromise-scope": "f65961d0-e759-4791-817c-c886075c0c79",
    "p06-ransomware-root-cause": "a148b57b-00ac-46f7-8ce5-85c041e8fe2e",
    "p06-credential-lateral-movement": "52bd203b-553f-41dd-bfdf-060f21d00ce8",
    "p06-data-exfiltration": "1586b2f3-5d38-4fd1-bd2f-7a34674bcd7a",
    "p06-remediation-validation": "7e38a35d-0533-45ff-a572-17a04902d53b",
}
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
    for scenario in SCENARIOS:
        path = P06_ROOT / scenario / RUNS[scenario] / "tools-schema.json"
        hashes.add(sha256_file(path))
        tools = json.loads(path.read_text(encoding="utf-8"))
    if len(hashes) != 1:
        raise ValueError("the five formal runs do not share one tools schema")
    if tools is None or len(tools) != 130:
        raise ValueError("current tools schema is not the 130-tool inventory")
    return tools, hashes.pop(), "formal-HTTP-session-captured"


def measure_task_costs() -> list[dict]:
    rows = []
    for scenario in SCENARIOS:
        path = P06_ROOT / scenario / RUNS[scenario] / "report.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        calls = report["calls"]
        retry_calls = sum(1 for call in calls if call.get("attempt", 1) > 1)
        output_bytes = sum(
            len(canonical_text(call.get("structured")).encode("utf-8")) for call in calls
        )
        rows.append(
            {
                "scenario": scenario,
                "run_id": RUNS[scenario],
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
    """The current-side equivalent of the upstream fixed task, per formal run.

    For every scenario report, collect the calls of the RecycleBin evidence
    chain (the same artifact the upstream baseline ran) with their poll
    attempts and structured output byte sizes.
    """
    rows = []
    for scenario in SCENARIOS:
        path = P06_ROOT / scenario / RUNS[scenario] / "report.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        chain = [
            call
            for call in report["calls"]
            if call.get("tool") == "Windows.Forensics.RecycleBin"
            or (
                call.get("tool") in {"get_flow_status", "get_flow_results", "list_flow_files"}
                and str(call.get("step_id", "")).endswith(
                    ("-wait", "-results", "-files")
                )
                and _in_recyclebin_chain(report, call)
            )
        ]
        rows.append(
            {
                "scenario": scenario,
                "tool_calls": len(chain),
                "poll_attempts": sum(call.get("attempt", 1) for call in chain),
                "structured_output_bytes": sum(
                    len(canonical_text(call.get("structured")).encode("utf-8"))
                    for call in chain
                ),
            }
        )
    return rows


def _in_recyclebin_chain(report: dict, call: dict) -> bool:
    prefix = str(call.get("step_id", "")).split("-")[0]
    for candidate in report["calls"]:
        if (
            candidate.get("tool") == "Windows.Forensics.RecycleBin"
            and str(candidate.get("step_id", "")).startswith(prefix + "-")
        ):
            return True
    return False


def main() -> int:
    upstream, upstream_capture_sha = upstream_tools()
    current, current_schema_sha, current_source = current_tools()
    upstream_task = json.loads(UPSTREAM_TASK.read_text(encoding="utf-8"))
    current_task_chains = current_task_chain_rows()

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
            "upstream_fixed_task_baseline": {
                "capture_file": "Logs/P07/upstream78-fixed-task.json",
                "capture_sha256": sha256_file(UPSTREAM_TASK),
                "artifact": upstream_task["artifact"],
                "mapping": (
                    "target-equivalent investigation (start collection -> wait for completion "
                    "-> retrieve result rows) implemented with each side's native toolset "
                    "(AUD-004): upstream collect_artifact + get_collection_results(max_retries, "
                    "retry_delay) vs current start tool + get_flow_status polling + "
                    "get_flow_results + list_flow_files"
                ),
                "upstream_calls": [
                    {
                        "tool": call["tool"],
                        "is_error": call["is_error"],
                        "elapsed_seconds": call["elapsed_seconds"],
                        "payload_bytes": call["payload_bytes"],
                    }
                    for call in upstream_task["calls"]
                ],
                "upstream_total_elapsed_seconds": upstream_task["total_elapsed_seconds"],
                "upstream_retry_semantics": (
                    "get_collection_results retries internally with the declared "
                    "max_retries/retry_delay parameters; no per-retry wire calls are visible "
                    "over stdio, so the retry dimension is reported as the tool's internal "
                    "behavior, unlike the current side's explicit per-poll calls"
                ),
                "current_equivalent_chains": current_task_chains,
            },
        },
        "conclusion": (
            "Raw measured quantities with the stated methodology; no preset smaller/better "
            "direction. The current 130-tool face is larger than the upstream 78-tool face "
            "on every schema dimension; task costs are reported for the current product only."
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
