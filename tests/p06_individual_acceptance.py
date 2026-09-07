"""Win10-only inventory and fixed error-contract acceptance for P06."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from velociraptor_dynamic_artifacts import APPROVED_WINDOWS_ARTIFACTS
from velociraptor_fixed_tools import FIXED_TOOL_NAMES


OUT = REPO_ROOT / "Logs" / "P06" / "wf-01a05d1d-p06" / "individual-acceptance.json"


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def result_row(result) -> dict:
    return {
        "is_error": bool(result.is_error),
        "content_count": len(result.content),
        "structured": result.structured_content,
    }


def tools_digest(tools) -> str:
    rows = sorted(
        [tool.model_dump(mode="json", exclude_none=True) for tool in tools],
        key=lambda row: row["name"],
    )
    payload = (json.dumps(rows, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return hashlib.sha256(payload).hexdigest()


async def call(session, evidence: dict, label: str, tool: str, arguments: dict) -> dict:
    row = result_row(await session.call_tool(tool, arguments))
    evidence["calls"][label] = {"tool": tool, "arguments": arguments, "result": row}
    return row


async def wait_terminal(session, evidence: dict, flow_id: str, label: str) -> dict:
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        row = await call(
            session,
            evidence,
            f"{label}-{len(evidence['calls']):03d}",
            "get_flow_status",
            {"flow_id": flow_id},
        )
        if row["is_error"]:
            raise AssertionError(row)
        if row["structured"]["state"] in {"FINISHED", "ERROR"}:
            return row["structured"]
        await asyncio.sleep(1)
    raise AssertionError(f"flow did not terminate: {flow_id}")


async def main_async() -> int:
    if os.environ.get("COMPUTERNAME", "").upper() != "DESKTOP-3FI41GR":
        raise RuntimeError("P06 acceptance only runs on DESKTOP-3FI41GR")
    evidence = {
        "schema": "p06-individual-acceptance-v1",
        "started_at": utc_now(),
        "hostname": os.environ.get("COMPUTERNAME"),
        "calls": {},
        "status": "running",
    }
    stderr_file = tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False)
    stderr_path = Path(stderr_file.name)
    try:
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(REPO_ROOT / "mcp_velociraptor_bridge.py")],
            cwd=REPO_ROOT,
            env=dict(os.environ),
        )
        async with stdio_client(params, errlog=stderr_file) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                first = (await session.list_tools()).tools
                second = (await session.list_tools()).tools
                names = {tool.name for tool in first}
                expected = set(APPROVED_WINDOWS_ARTIFACTS) | set(FIXED_TOOL_NAMES)
                if len(first) != 130 or len(names) != 130 or names != expected:
                    raise AssertionError("tools/list differs from the reviewed 130-tool set")
                if tools_digest(first) != tools_digest(second):
                    raise AssertionError("tools/list changed within one session")
                evidence["inventory"] = {
                    "count": len(first),
                    "dynamic": len(set(APPROVED_WINDOWS_ARTIFACTS)),
                    "fixed": len(FIXED_TOOL_NAMES),
                    "sha256": tools_digest(first),
                }

                cases = (
                    ("unknown-flow", "get_flow_status", {"flow_id": "F.__p06_missing__"}, "NOT_FOUND"),
                    ("unknown-hunt", "get_hunt_status", {"hunt_id": "H.__p06_missing__"}, "NOT_FOUND"),
                    ("invalid-pid", "kill_process", {"pid": 0}, "INVALID_ARGUMENT"),
                    ("hunt-not-allowlisted", "start_hunt", {"artifact": "Windows.Not.Approved"}, "NOT_FOUND"),
                    ("path-escape", "collect_file", {"path": "..\\outside.txt"}, "INVALID_ARGUMENT"),
                    ("empty-vql", "run_vql", {"query": ""}, "INVALID_ARGUMENT"),
                )
                for label, tool, arguments, code in cases:
                    row = await call(session, evidence, label, tool, arguments)
                    if not row["is_error"] or row["structured"].get("code") != code:
                        raise AssertionError(f"{label}: expected {code}, got {row}")

                completed = await call(
                    session,
                    evidence,
                    "terminal-start",
                    "Windows.System.PowerShell",
                    {"Command": "exit 0", "Timeout": 30, "Stateful": False},
                )
                if completed["is_error"]:
                    raise AssertionError(completed)
                flow_id = completed["structured"]["flow_id"]
                final = await wait_terminal(session, evidence, flow_id, "terminal-wait")
                if final["state"] != "FINISHED":
                    raise AssertionError(final)
                cancel = await call(
                    session, evidence, "terminal-cancel", "cancel_flow", {"flow_id": flow_id}
                )
                if not cancel["is_error"] or cancel["structured"].get("code") != "NOT_CANCELLABLE":
                    raise AssertionError(cancel)
        evidence["status"] = "success"
        return 0
    except Exception as exc:
        evidence["status"] = "failed"
        evidence["failure"] = {"type": type(exc).__name__, "message": str(exc)}
        return 1
    finally:
        stderr_file.flush()
        stderr_file.seek(0)
        stderr = stderr_file.read()
        stderr_file.close()
        stderr_path.unlink(missing_ok=True)
        evidence["ended_at"] = utc_now()
        evidence["stderr"] = {
            "length": len(stderr),
            "contains_traceback": "Traceback" in stderr,
            "contains_secret_path": "api_client.yaml" in stderr,
        }
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"out": str(OUT), "status": evidence["status"]}, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main_async()))
