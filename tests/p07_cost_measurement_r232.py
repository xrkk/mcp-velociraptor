"""R12 cost measurement rerun: .232 selected sub-chain vs upstream 9dc8054.

Same methodology as tests/p07_cost_measurement.py (P07 v2), re-pointed at the
.232-era evidence without touching the historical .149 measurement:

- Upstream side: the five fixed RecycleBin investigation endpoints re-run on
  the retained .232 baseline (upstream source bytes = git 9dc8054, verified by
  git hash-object before the push; FastMCP->MCPServer alias shim; isolated
  stdio subprocess). Unlike the .149 era there is no per-group snapshot
  restore: all five runs and the current-side runs share one retained state.
- Current side: the same endpoint's evidence chain extracted from the five
  R11 final-selection .232 runs (report.json steps, flow-id bound).
- Tool face: upstream 78 capture vs the current 137-tool face, reported as
  one 130-tool DFIR slice plus one 7-tool transfer slice; denominators are
  not mixed.

No host-specific absolute paths live in this file; the evidence root is a
required argument.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import sys
if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.p07_cost_measurement import SCENARIOS, COST_PAIR_GROUPS, UPSTREAM_CAPTURE, canonical_text, sha256_file, upstream_tools

REPO_ROOT = Path(__file__).resolve().parents[1]
PAIRS_ROOT = REPO_ROOT / "Logs" / "P07" / "cost-pairs-232"
TRANSCRIPTS_ROOT = REPO_ROOT / "Logs" / "P07" / "transcripts-232"
OUTPUT = REPO_ROOT / "Logs" / "P07" / "cost-measurement-232.json"


def load_final_selection(evidence_root: Path) -> dict[str, str]:
    document = json.loads((evidence_root / "p232-scenarios" / "final-selection.json").read_text(encoding="utf-8"))
    runs = {}
    for scenario, row in document["scenarios"].items():
        selected = row["selected"]
        if selected.get("status") != "success":
            raise ValueError(f"{scenario}: final selection is not a success run")
        runs[scenario] = selected["run_id"]
    if set(runs) != set(SCENARIOS):
        raise ValueError("final selection does not cover the five scenarios")
    return runs


def current_chain_rows(evidence_root: Path, runs: dict[str, str]) -> list[dict]:
    rows = []
    for scenario in SCENARIOS:
        path = evidence_root / "p232-scenarios" / scenario / runs[scenario] / "report.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        steps = report["steps"]
        start = next(step for step in steps if step.get("tool") == "Windows.Forensics.RecycleBin")
        flow_id = (start.get("structured") or {}).get("flow_id")
        if not flow_id:
            raise ValueError(f"{scenario}: RecycleBin start lacks its flow identity")
        chain = [
            step for step in steps
            if step is start
            or (
                step.get("tool") in {"get_flow_status", "get_flow_results", "list_flow_files"}
                and (
                    (step.get("structured") or {}).get("flow_id") == flow_id
                    or step.get("arguments", {}).get("flow_id") == flow_id
                )
            )
        ]
        wait_rounds = [step for step in chain if step.get("tool") == "get_flow_status"]
        retry_rounds = sum(
            1 for step in wait_rounds if (step.get("structured") or {}).get("state") != "FINISHED"
        )
        results_calls = [step for step in chain if step.get("tool") == "get_flow_results"]
        rows.append(
            {
                "scenario": scenario,
                "run_id": runs[scenario],
                "report_sha256": sha256_file(path),
                "flow_id": flow_id,
                "tool_calls": len(chain),
                "poll_rounds": len(wait_rounds),
                "retry_rounds": retry_rounds,
                "structured_output_bytes": sum(
                    len(canonical_text(step.get("structured")).encode("utf-8")) for step in chain
                ),
                "elapsed_seconds": (
                    datetime.fromisoformat(chain[-1]["ended_at"].replace("Z", "+00:00"))
                    - datetime.fromisoformat(chain[0]["started_at"].replace("Z", "+00:00"))
                ).total_seconds(),
                "results_rows": sum(
                    len(
                        ((step.get("structured") or {}).get("data"))
                        or ((step.get("structured") or {}).get("rows"))
                        or []
                    )
                    for step in results_calls
                ),
                "file_rows": sum(
                    len(
                        ((step.get("structured") or {}).get("files"))
                        or ((step.get("structured") or {}).get("data"))
                        or []
                    )
                    for step in chain
                    if step.get("tool") == "list_flow_files"
                ),
            }
        )
    return rows


def current_task_rows(evidence_root: Path, runs: dict[str, str]) -> list[dict]:
    rows = []
    for scenario in SCENARIOS:
        path = evidence_root / "p232-scenarios" / scenario / runs[scenario] / "report.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        steps = report["steps"]
        rows.append(
            {
                "scenario": scenario,
                "run_id": runs[scenario],
                "report_sha256": sha256_file(path),
                "tool_calls": len(steps),
                "retry_calls_beyond_first_attempt": sum(1 for s in steps if s.get("attempt", 1) > 1),
                "max_attempt_observed": max(s.get("attempt", 1) for s in steps),
                "structured_output_bytes_sum": sum(
                    len(canonical_text(s.get("structured")).encode("utf-8")) for s in steps
                ),
                "duration_ms": report["duration_seconds"] * 1000,
            }
        )
    return rows


def upstream_group_rows() -> list[dict]:
    """Upstream metrics from the task record plus the full response transcripts.

    CHK-R14-005: the v1 report compared the upstream raw ``content[0].text``
    byte lengths against canonicalized current-side structured payloads - two
    different field domains. The transcripts are now the source of truth and
    every upstream response is measured twice: ``text_bytes`` (raw UTF-8 wire
    text, upstream-only observation) and ``canonical_bytes`` (canonical JSON
    of the parsed response, the same serialization and field domain as the
    current side, and therefore the only comparable metric).
    """
    rows = []
    for scenario, group in COST_PAIR_GROUPS.items():
        path = PAIRS_ROOT / group / "upstream-task.json"
        transcript_path = TRANSCRIPTS_ROOT / f"upstream-task-{group}-transcript.jsonl"
        task = json.loads(path.read_text(encoding="utf-8"))
        if task.get("status") != "success":
            raise ValueError(f"upstream group {group} did not succeed: {task.get('failure')}")
        if task.get("upstream_tool_count") != 78:
            raise ValueError(f"upstream group {group} did not render the 78-tool face")
        transcripts = [json.loads(line) for line in transcript_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        payloads = [entry["payload"] for entry in transcripts if "payload" in entry and entry.get("row")]
        calls = task["calls"]
        if len(payloads) != len(calls):
            raise ValueError(f"upstream group {group}: transcript does not cover every call")
        canonical_calls = []
        text_total = 0
        canonical_total = 0
        for call, payload in zip(calls, payloads):
            text_bytes = len(payload.encode("utf-8"))
            canonical = len(canonical_text(json.loads(payload)).encode("utf-8"))
            if text_bytes != call["payload_bytes"]:
                raise ValueError(f"upstream group {group}: transcript disagrees with the task record")
            text_total += text_bytes
            canonical_total += canonical
            canonical_calls.append(
                {
                    "tool": call["tool"],
                    "is_error": call["is_error"],
                    "elapsed_seconds": call["elapsed_seconds"],
                    "text_bytes": text_bytes,
                    "canonical_bytes": canonical,
                }
            )
        rows.append(
            {
                "scenario": scenario,
                "group": group,
                "transport": task["transport"],
                "tool_calls": task["call_count"],
                "results_rounds": task["results_rounds"],
                "retry_rounds": task["retry_rounds"],
                "text_bytes_sum_upstream_only": text_total,
                "structured_output_bytes": canonical_total,
                "transcript_sha256": sha256_file(transcript_path),
                "elapsed_seconds": sum(call["elapsed_seconds"] for call in calls),
                "results_rows": task["results_rows"],
                "file_rows": task["file_list_rows"] or 0,
                "calls": canonical_calls,
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
                "metric": "structured_output_bytes = canonical JSON on both sides (see methodology.output_metrics)",
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
                    "FastMCP->MCPServer shim) re-run on the retained .232 baseline; current: "
                    "formal external streamable-http session of the R11 final-selection run; "
                    "transports differ by design; unlike the .149-era pairs neither side uses "
                    "per-group snapshot restores - both sides shared the same retained state"
                ),
            }
        )
    return pairs


def face(tools: list[dict]) -> dict:
    text = canonical_text(tools)
    data = text.encode("utf-8")
    return {
        "tool_count": len(tools),
        "canonical_json_bytes": len(data),
        "canonical_json_sha256": hashlib.sha256(data).hexdigest(),
        "token_estimate_chars_div_4": len(text) // 4,
    }


def main_historical() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", required=True,
                        help="directory containing p232-scenarios/ and tools-list-232-137.json")
    args = parser.parse_args()
    evidence_root = Path(args.evidence_root).expanduser().resolve()
    runs = load_final_selection(evidence_root)

    upstream, upstream_capture_sha = upstream_tools()
    face_document = json.loads((evidence_root / "tools-list-232-137.json").read_text(encoding="utf-8"))
    current = face_document["tools"]
    if len(current) != 137:
        raise ValueError("current tools capture is not the 137-tool face")
    transfer_slice = [tool for tool in current if tool["name"].startswith("transfer_")]
    dfir_slice = [tool for tool in current if not tool["name"].startswith("transfer_")]
    if len(transfer_slice) != 7 or len(dfir_slice) != 130:
        raise ValueError("137-face slice split is not 130+7")

    upstream_face = face(upstream)
    dfir_face = face(dfir_slice)
    transfer_face = face(transfer_slice)
    total_face = face(current)

    upstream_groups = upstream_group_rows()
    current_chains = current_chain_rows(evidence_root, runs)
    pairs = cost_pair_rows(upstream_groups, current_chains)
    task_rows = current_task_rows(evidence_root, runs)

    report = {
        "schema": "p07-cost-measurement-232-v2",
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "methodology": {
            "canonical_serialization": "json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))",
            "token_estimate": "canonical JSON characters divided by 4; documented approximation, not a tokenizer measurement",
            "upstream_rendering": (
                "unchanged upstream source (git 9dc8054, blob-verified by git hash-object before the "
                "policy-scoped pushes p07-cost-push-a2/b2/c2-20261001) executed on the .232 VM venv "
                "and mcp 2.x SDK via the FastMCP->MCPServer alias shim; isolated stdio subprocess"
            ),
            "upstream_baseline": (
                "retained .232 E2 deployment state; no per-group snapshot restores (the .149-era "
                "Snapshot188 per-group restores have no .232 equivalent); all five upstream runs and "
                "all five current-side runs shared the same retained state"
            ),
            "current_rendering": (
                "live tools/list captured from the formal .232 entry "
                f"({face_document.get('captured_from')} at {face_document.get('captured_at')})"
            ),
            "current_task_source": "runner-recorded structured outputs of the five R11 final-selection .232 runs",
            "output_metrics": (
                "structured_output_bytes is canonical JSON of the parsed response on BOTH sides "
                "(upstream: canonical of each transcript payload; current: canonical of structuredContent) "
                "and is the only cross-side comparable byte metric; text_bytes_sum_upstream_only is the raw "
                "content[0].text UTF-8 length, an upstream-only wire observation (the .232 driver records "
                "structuredContent with an empty content list, so no symmetric current-side text metric exists); "
                "the v1 report mixed raw upstream bytes with canonical current bytes in pairs - corrected here"
            ),
            "denominator_rule": "130-tool DFIR slice compared against the upstream 78 face; the 7 transfer tools are a disclosed increment slice, denominators are not mixed",
        },
        "tool_face": {
            "upstream_78": {
                **upstream_face,
                "capture_file": "Logs/P07/upstream78-tools-list.jsonl",
                "capture_sha256": upstream_capture_sha,
            },
            "current_dfir_130": {
                **dfir_face,
                "capture_file": "tools-list-232-137.json (evidence root)",
                "capture_sha256": sha256_file(evidence_root / "tools-list-232-137.json"),
            },
            "current_transfer_7": {
                **transfer_face,
                "note": "PC024 transfer increment; covered by the R06-C independent matrix, not part of the DFIR 130 comparison",
            },
            "current_137_total": total_face,
            "comparison_dfir_minus_upstream": {
                "tool_count_delta": dfir_face["tool_count"] - upstream_face["tool_count"],
                "canonical_bytes_delta": dfir_face["canonical_json_bytes"] - upstream_face["canonical_json_bytes"],
                "token_estimate_delta": dfir_face["token_estimate_chars_div_4"] - upstream_face["token_estimate_chars_div_4"],
            },
        },
        "fixed_investigation_task_costs": {
            "per_scenario": task_rows,
            "totals": {
                "tool_calls": sum(row["tool_calls"] for row in task_rows),
                "retry_calls_beyond_first_attempt": sum(
                    row["retry_calls_beyond_first_attempt"] for row in task_rows
                ),
                "structured_output_bytes_sum": sum(row["structured_output_bytes_sum"] for row in task_rows),
                "duration_ms_sum": sum(row["duration_ms"] for row in task_rows),
            },
            "five_cost_pairs": {
                "methodology": (
                    "each of the five upstream groups ran the fixed RecycleBin investigation endpoint "
                    "(collect_artifact -> externally observed get_collection_results rounds with "
                    "max_retries=1 so every internal retry is a recorded round -> bounded uploads file "
                    "list via the upstream native run_vql) on the retained .232 baseline in a Windows "
                    "isolated stdio subprocess; the current side is the same endpoint's evidence chain "
                    "from the R11 final-selection .232 run of the same scenario"
                ),
                "pairs": pairs,
            },
        },
        "conclusion": (
            "Raw measured quantities with the stated methodology; no preset smaller/better direction. "
            "The 130-tool DFIR slice remains larger than the upstream 78-tool face on every schema "
            "dimension; the 7 transfer tools add a separately disclosed increment. The five fixed-task "
            "pairs compare call counts, retry rounds, canonical structured bytes, result rows and file "
            "rows per group; upstream raw text bytes are disclosed as an upstream-only observation. "
            "Elapsed times cross transports (stdio vs formal HTTP) and are disclosed as such rather "
            "than claimed equivalent."
        ),
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "out": str(OUTPUT),
                "upstream_tools": upstream_face["tool_count"],
                "dfir_tools": dfir_face["tool_count"],
                "transfer_tools": transfer_face["tool_count"],
                "upstream_bytes": upstream_face["canonical_json_bytes"],
                "dfir_bytes": dfir_face["canonical_json_bytes"],
                "task_calls_total": report["fixed_investigation_task_costs"]["totals"]["tool_calls"],
            },
            sort_keys=True,
        )
    )
    return 0


def main() -> int:
    """The old .232 no-restore layout cannot publish a current cost result."""
    from tests import p06_pc026_binding, p06_aggregate_reports
    admission = p06_pc026_binding.load()
    p06_aggregate_reports._aggregate_current(admission)
    admission.recheck()
    raise ValueError('historical .232 schema3/no-restore pairs cannot satisfy current P07')


if __name__ == "__main__":
    raise SystemExit(main())
