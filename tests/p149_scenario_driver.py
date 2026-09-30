"""Run the frozen P06 scenarios against the adopted .149 baseline entry.

The official tests/scenario_runner.py gates formal HTTP execution on the
Snapshot-189 restore chain, which only existed on the retired .232 host. This
driver reuses the runner's frozen step engine (scenario loading, fixture
loading, argument resolution, execution and assertions) unchanged and replaces
only the impossible snapshot gate with the adopted .149 baseline binding:

  - one official-SDK Streamable HTTP session for the whole scenario,
  - Mcp-Session-Id plus X-MCP-Server-Instance captured as the service binding,
  - a plain baseline declaration recorded verbatim in the report.

Steps whose tool is registered environment-not-applicable on .149 are recorded
as failed steps and the run continues, so the remaining frozen steps still
produce real coverage. Reports are written to a p149 evidence root; they are
labeled baseline reports and never pretend to be the runner's r3 originals.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from scenario_runner import (  # noqa: E402
    HttpHeaderCapture,
    ScenarioFailure,
    ScenarioInputError,
    execute_tool_step,
    load_fixture,
    load_indexed_scenario,
)

P149_ROOT = REPO_ROOT / "Logs" / "P06" / "p149-baseline"
REGISTERED_NOT_APPLICABLE = {
    "Windows.Applications.Edge.History",
    "Windows.Registry.EnableUnsafeClientMailRules",
    "Windows.Detection.BinaryHunter",
}


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


async def run(scenario_id: str, endpoint: str, token: str, out_root: Path,
             fixture_instance: Path | None = None) -> dict:
    scenario, index_row, source_hash, index_path = load_indexed_scenario(scenario_id)
    fixture, fixture_hash = load_fixture(scenario, fixture_instance)
    run_id = str(uuid.uuid4())
    run_dir = out_root / scenario_id / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    report: dict = {
        "schema": "velo.p149.scenario-report.v1",
        "baseline": {
            "adoption": "2026-09-30 working assumption (.149 deployment replaces Snapshot-189 restore chain)",
            "endpoint": endpoint,
            "snapshot_gate": "not-applicable-on-149; recorded, not fabricated",
        },
        "scenario_id": scenario_id,
        "scenario_source_sha256": source_hash,
        "index_row": index_row,
        "fixture_instance_sha256": fixture_hash,
        "fixture": {
            "workflow_id": fixture["workflow_id"],
            "attempt_id": fixture["attempt_id"],
            "process_pid": fixture.get("process", {}).get("pid"),
        },
        "run_id": run_id,
        "started_at": utc_now(),
        "steps": [],
        "registered_not_applicable": sorted(REGISTERED_NOT_APPLICABLE),
    }
    steps_path = run_dir / "steps.jsonl"
    import httpx2
    from mcp.client.streamable_http import streamable_http_client

    capture = HttpHeaderCapture(httpx2.AsyncHTTPTransport())
    http_client = httpx2.AsyncClient(
        headers={"Authorization": f"Bearer {token}"}, timeout=120.0, transport=capture)
    completed: dict = {}
    failed_steps: list[dict] = []
    executed = 0
    started = time.monotonic()
    status = "success"
    async with streamable_http_client(endpoint, http_client=http_client) as (read, write):
        from mcp import ClientSession
        async with ClientSession(read, write) as session:
            await session.initialize()
            init_row = next((r for r in capture.responses
                             if r["method"] == "POST" and r["mcp_session_id"]), None)
            if init_row is None:
                raise ScenarioFailure("no Mcp-Session-Id captured at initialize")
            report["mcp_session"] = {"id": init_row["mcp_session_id"]}
            report["server_identity"] = {"instance_id": init_row["server_instance_id"]}
            with steps_path.open("w", encoding="utf-8") as sink:
                for ordinal, step in enumerate(scenario["steps"]):
                    if step.get("kind", "tool") != "tool":
                        continue
                    row = {"id": step["id"], "tool": step.get("tool"), "ordinal": ordinal}
                    try:
                        value, assertions = await execute_tool_step(
                            session, step, completed, fixture, report["steps"])
                        completed[step["id"]] = value
                        passed = all(a.get("passed") for a in assertions)
                        row.update({"passed": passed, "assertions": assertions})
                        if not passed:
                            row["registered"] = step.get("tool") in REGISTERED_NOT_APPLICABLE
                            failed_steps.append(row)
                            status = "completed_with_registered_exceptions"
                    except ScenarioFailure as exc:
                        row.update({"passed": False, "failure": str(exc)[:400],
                                    "registered": step.get("tool") in REGISTERED_NOT_APPLICABLE})
                        failed_steps.append(row)
                        status = "completed_with_registered_exceptions"
                    except ScenarioInputError as exc:
                        row.update({"passed": False, "input_error": str(exc)[:300],
                                    "registered": False})
                        failed_steps.append(row)
                        status = "failed"
                        break
                    executed += 1
                    sink.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
                    sink.flush()
                    report["steps"].append({"id": step["id"], "tool": step.get("tool"),
                                            "passed": row.get("passed", False)})
    report["status"] = status
    report["finished_at"] = utc_now()
    report["duration_seconds"] = round(time.monotonic() - started, 1)
    report["counts"] = {
        "steps_executed": executed,
        "steps_total": len(scenario["steps"]),
        "steps_failed": len(failed_steps),
        "failed_tools": sorted({r["tool"] for r in failed_steps}),
    }
    report_path = run_dir / "report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=1, default=str),
                           encoding="utf-8")
    slim = dict(report)
    slim["steps"] = f"<{len(report['steps'])} rows in steps.jsonl>"
    print(json.dumps(slim, ensure_ascii=False, indent=1))
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario-id", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--token-env", default="VELOCIRAPTOR_MCP_BEARER_TOKEN")
    parser.add_argument("--out-root", default=str(P149_ROOT))
    parser.add_argument("--fixture-instance", default=None)
    args = parser.parse_args()
    token = __import__("os").environ.get(args.token_env, "").strip()
    if not token:
        print(f"{args.token_env} is required", file=sys.stderr)
        return 2
    if not re.fullmatch(r"http://[0-9.]+:28790/mcp", args.endpoint):
        print("endpoint must be http://<ip>:28790/mcp", file=sys.stderr)
        return 2
    fixture_instance = Path(args.fixture_instance) if args.fixture_instance else None
    try:
        report = asyncio.run(run(args.scenario_id, args.endpoint, token,
                                 Path(args.out_root), fixture_instance))
    except (ScenarioInputError, ScenarioFailure, OSError, json.JSONDecodeError) as exc:
        print(f"p149-driver: {exc}", file=sys.stderr)
        return 2
    return 0 if report["status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
