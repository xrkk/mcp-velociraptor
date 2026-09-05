"""P05 external acceptance entry: formal HTTP verification from outside the VM.

This script only accepts an endpoint URL, a token environment variable name,
and an evidence directory. It never accepts arbitrary commands, tokens as
arguments, or credentials in any persisted output. It verifies the formal
entry gate negatives and runs one representative scenario through the shared
runner HTTP branch; the canonical scenario/restore evidence contract is
enforced by the runner itself.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))

ENDPOINT_PATTERN = re.compile(r"^http://(\d{1,3}(?:\.\d{1,3}){3}):28790/mcp$")


def _raw_rpc(endpoint: str, token: str, payload: dict[str, Any], headers: dict[str, str]):
    import httpx2

    async def run():
        base = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {token}",
        }
        base.update(headers)
        async with httpx2.AsyncClient(timeout=30.0) as http:
            return await http.post(endpoint, json=payload, headers=base)

    return asyncio.run(run())


def _initialize_payload() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "p05-external-acceptance", "version": "0"},
        },
    }


def verify_entry_gate(endpoint: str, token: str, allowed_origin: str | None) -> dict[str, Any]:
    """Positive and negative checks of the formal entry request gate."""
    results: dict[str, Any] = {}

    ok = _raw_rpc(endpoint, token, _initialize_payload(), headers={})
    results["no_origin_authorized"] = ok.status_code == 200
    results["instance_header_present"] = bool(ok.headers.get("x-mcp-server-instance"))
    results["session_header_present"] = bool(ok.headers.get("mcp-session-id"))

    missing = _raw_rpc(endpoint, token, _initialize_payload(), headers={"Authorization": ""})
    results["missing_bearer_rejected_401"] = missing.status_code == 401

    wrong = _raw_rpc(
        endpoint, token, _initialize_payload(), headers={"Authorization": "Bearer wrong"}
    )
    results["wrong_bearer_rejected_401"] = wrong.status_code == 401

    bad_host = _raw_rpc(endpoint, token, _initialize_payload(), headers={"Host": "rebind.example"})
    results["bad_host_rejected"] = bad_host.status_code == 421

    bad_origin = _raw_rpc(
        endpoint,
        token,
        _initialize_payload(),
        headers={"Origin": "https://not-allowed.example"},
    )
    results["unapproved_origin_rejected"] = bad_origin.status_code == 403

    if allowed_origin:
        good_origin = _raw_rpc(
            endpoint, token, _initialize_payload(), headers={"Origin": allowed_origin}
        )
        results["allowed_origin_accepted"] = good_origin.status_code == 200

    if token.encode() in json.dumps(results).encode():
        results["TOKEN_LEAK_IN_RESULTS"] = True
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--token-env", required=True)
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--scenario-id", default="p05-flow-triage-network-candidate")
    parser.add_argument("--allowed-origin", default=None)
    parser.add_argument("--server-observation", default=None)
    args = parser.parse_args()

    if not ENDPOINT_PATTERN.match(args.endpoint):
        print("external-acceptance: endpoint must be http://<ip>:28790/mcp", file=sys.stderr)
        return 2
    token = os.environ.get(args.token_env, "").strip()
    if not token:
        print(
            f"external-acceptance: {args.token_env} must be set in the environment",
            file=sys.stderr,
        )
        return 2
    evidence_root = Path(args.evidence_root).resolve()
    if not evidence_root.is_dir():
        print("external-acceptance: evidence root must be an existing directory", file=sys.stderr)
        return 2

    gate = verify_entry_gate(args.endpoint, token, args.allowed_origin)
    gate_ok = all(value is True for value in gate.values())
    gate_path = evidence_root / "entry-gate.json"
    gate_path.write_text(json.dumps(gate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not gate_ok:
        print(
            json.dumps({"entry_gate": "failed", "detail": gate}, ensure_ascii=False, sort_keys=True)
        )
        return 1

    from scenario_runner import SnapshotEvidenceError, ScenarioInputError, run_scenario

    try:
        report, path = asyncio.run(
            run_scenario(
                args.scenario_id,
                transport="streamable-http",
                endpoint=args.endpoint,
                token_env=args.token_env,
                evidence_root=evidence_root,
                server_observation=(
                    Path(args.server_observation) if args.server_observation else None
                ),
            )
        )
    except (ScenarioInputError, SnapshotEvidenceError, OSError, json.JSONDecodeError) as exc:
        print(f"external-acceptance: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {"entry_gate": "passed", "report": str(path), "status": report["status"]},
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
