"""PC025 schema3 batch orchestration: qualification plus the five scenarios.

Runs on the host against the adopted .232 baseline: one baseline binding, one
qualification attempt (writing the resource selection), then the five frozen
scenarios through the schema3 runner mode. Every completed attempt (success or
failed) is received into the append-only ledger by the runner itself.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tests.p06_evidence import plain_file  # noqa: E402

SCENARIOS = (
    "p06-compromise-scope",
    "p06-ransomware-root-cause",
    "p06-credential-lateral-movement",
    "p06-data-exfiltration",
    "p06-remediation-validation",
)


def write_resource_selection(root: Path) -> None:
    """Bind the just-finished qualification attempt as the gate selection."""
    from tests.p06_package import digest

    ledger = root / "接收清单.jsonl"
    rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line]
    qualification = [row for row in rows if row["scenario"] == "resource-qualification"]
    if len(qualification) != 1 or qualification[0]["status"] != "success":
        raise SystemExit("qualification attempt is not the single successful ledger entry")
    selection = {
        "report_relative_path": qualification[0]["report_relative_path"],
        "report_sha256": qualification[0]["report_sha256"],
    }
    (root / "resource-qualification-selection.json").write_text(
        json.dumps(selection, ensure_ascii=False, indent=1), encoding="utf-8")
    # Re-verify the binding the gate will use.
    plain_file(root, "resource-qualification-selection.json")
    if digest(root / selection["report_relative_path"]) != selection["report_sha256"]:
        raise SystemExit("qualification selection bytes differ")


async def run_qualification(args) -> None:
    from tests import p06_resource_qualification as qualification

    report, run_dir = await qualification.qualify(
        args.endpoint, args.token_env,
        baseline_binding=Path(args.baseline_binding),
        evidence_root_out=Path(args.evidence_root),
        server_observation=Path(args.server_observation),
        fixture_instance=Path(args.fixture_instance))
    if report["status"] != "success":
        raise SystemExit(f"qualification failed: {json.dumps(report.get('failure'))[:400]}")
    write_resource_selection(Path(args.evidence_root))
    print(json.dumps({"step": "qualification", "run_dir": str(run_dir)}))


async def run_scenario_once(args, scenario_id: str) -> dict:
    from tests.scenario_runner import run_scenario

    report, path = await run_scenario(
        scenario_id,
        transport="streamable-http",
        endpoint=args.endpoint,
        token_env=args.token_env,
        evidence_root=Path(args.evidence_root),
        server_observation=Path(args.server_observation),
        baseline_binding=Path(args.baseline_binding),
        fixture_instance=Path(args.fixture_instance),
        expected_tool_count=137)
    print(json.dumps({"scenario": scenario_id, "status": report["status"],
                      "report": str(path), "failed_steps": report.get("counts", {}).get("steps_failed")}))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--token-env", default="VELOCIRAPTOR_MCP_BEARER_TOKEN")
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--baseline-binding", required=True)
    parser.add_argument("--server-observation", required=True)
    parser.add_argument("--fixture-instance", required=True)
    parser.add_argument("--scenarios", default=",".join(SCENARIOS),
                        help="comma-separated subset to run in order")
    parser.add_argument("--skip-qualification", action="store_true",
                        help="reuse the existing resource selection in the root")
    args = parser.parse_args()
    root = Path(args.evidence_root)
    root.mkdir(parents=True, exist_ok=True)
    if not args.skip_qualification:
        asyncio.run(run_qualification(args))
    outcomes = {}
    for scenario_id in [name for name in args.scenarios.split(",") if name]:
        report = asyncio.run(run_scenario_once(args, scenario_id))
        outcomes[scenario_id] = report["status"]
    print(json.dumps({"outcomes": outcomes}, ensure_ascii=False))
    return 0 if all(status == "success" for status in outcomes.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
