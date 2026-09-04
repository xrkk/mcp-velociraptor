"""Win10-only P03 acceptance: invoke every approved artifact through MCP stdio."""

from __future__ import annotations

import asyncio
import ctypes
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import velociraptor_api
from velociraptor_dynamic_artifacts import APPROVED_WINDOWS_ARTIFACTS


INVOCATIONS = REPO_ROOT / "tests" / "data" / "p03_invocations.json"
DEFAULT_EVIDENCE = (
    REPO_ROOT
    / "Logs"
    / "P03"
    / "wf-01a05d1d-p03"
    / "win10-all-artifact-acceptance.json"
)
MIN_DISK_FREE = 12 * 1024**3
MIN_MEMORY_FREE = 1 * 1024**3
MAX_DISK_DELTA = 4 * 1024**3
MAX_TOTAL_UPLOAD = 2 * 1024**3
MAX_FLOW_UPLOAD = 512 * 1024**2
MAX_WALL_SECONDS = 4 * 60 * 60
CALL_TIMEOUT_SECONDS = 60
CANCEL_TIMEOUT_SECONDS = 30
TERMINAL_STATES = {"FINISHED", "ERROR"}
DEPENDENCY_DEFERRED_ARTIFACTS = {
    "Windows.Network.PacketCapture",
    "Windows.Sysinternals.Autoruns",
}


class MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ulong),
        ("memory_load", ctypes.c_ulong),
        ("total_physical", ctypes.c_ulonglong),
        ("available_physical", ctypes.c_ulonglong),
        ("total_page_file", ctypes.c_ulonglong),
        ("available_page_file", ctypes.c_ulonglong),
        ("total_virtual", ctypes.c_ulonglong),
        ("available_virtual", ctypes.c_ulonglong),
        ("available_extended_virtual", ctypes.c_ulonglong),
    ]


def available_memory() -> int:
    status = MemoryStatusEx()
    status.length = ctypes.sizeof(MemoryStatusEx)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise ctypes.WinError()
    return int(status.available_physical)


def resources() -> dict[str, int]:
    return {
        "disk_free_bytes": shutil.disk_usage(REPO_ROOT.anchor).free,
        "memory_available_bytes": available_memory(),
    }


def flow_rows(client_id: str) -> list[dict[str, Any]]:
    return velociraptor_api.run_vql_query(
        "SELECT session_id, state, request, total_uploaded_bytes "
        f"FROM flows(client_id={velociraptor_api.vql_literal(client_id)})",
        root_org=True,
    )


def hunt_ids() -> set[str]:
    rows = velociraptor_api.run_vql_query(
        "SELECT hunt_id FROM hunts()",
        root_org=True,
    )
    return {str(row["hunt_id"]) for row in rows if row.get("hunt_id")}


def flow_detail(client_id: str, flow_id: str) -> dict[str, Any] | None:
    rows = velociraptor_api.run_vql_query(
        "SELECT session_id, state, request, total_uploaded_bytes "
        f"FROM flows(client_id={velociraptor_api.vql_literal(client_id)}) "
        f"WHERE session_id={velociraptor_api.vql_literal(flow_id)} LIMIT 1",
        root_org=True,
    )
    return rows[0] if rows else None


def cancel_flow(client_id: str, flow_id: str) -> list[dict[str, Any]]:
    return velociraptor_api.run_vql_query(
        "SELECT cancel_flow("
        f"client_id={velociraptor_api.vql_literal(client_id)}, "
        f"flow_id={velociraptor_api.vql_literal(flow_id)}) AS cancellation "
        "FROM scope()",
        root_org=True,
    )


def is_terminal(state: Any) -> bool:
    return str(state or "").upper() in TERMINAL_STATES


def wait_for_terminal(client_id: str, flow_id: str) -> tuple[dict[str, Any], bool]:
    detail = flow_detail(client_id, flow_id)
    if detail is None:
        raise AssertionError(f"flow {flow_id} disappeared")
    cancellation_sent = False
    if not is_terminal(detail.get("state")):
        cancel_flow(client_id, flow_id)
        cancellation_sent = True
        deadline = time.monotonic() + CANCEL_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            time.sleep(1)
            detail = flow_detail(client_id, flow_id)
            if detail is not None and is_terminal(detail.get("state")):
                break
        else:
            raise AssertionError(f"flow {flow_id} did not reach a terminal state")
    return detail, cancellation_sent


def env_map(detail: dict[str, Any]) -> dict[str, Any]:
    request = detail.get("request") or {}
    specs = request.get("specs") or []
    if not specs:
        return {}
    values = ((specs[0].get("parameters") or {}).get("env") or [])
    return {str(item.get("key")): item.get("value") for item in values}


def values_equal(actual: Any, expected: Any) -> bool:
    if actual == expected:
        return True
    if isinstance(expected, bool):
        return str(actual).lower() in ({"true", "y", "1"} if expected else {"", "false", "n", "0"})
    if isinstance(expected, list):
        try:
            return json.loads(str(actual)) == expected
        except json.JSONDecodeError:
            return False
    return str(actual) == str(expected)


def assert_request(detail: dict[str, Any], artifact: str, expected: dict[str, Any]) -> None:
    request = detail.get("request") or {}
    if request.get("artifacts") != [artifact]:
        raise AssertionError(f"{artifact}: backend artifact request mismatch")
    actual = env_map(detail)
    if set(actual) != set(expected):
        raise AssertionError(f"{artifact}: backend parameter names mismatch")
    for name, value in expected.items():
        if not values_equal(actual[name], value):
            raise AssertionError(f"{artifact}: backend parameter {name} mismatch")


def write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".next")
    temporary.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    temporary.replace(path)


def exception_summary(exc: BaseException) -> dict[str, Any]:
    summary: dict[str, Any] = {"type": type(exc).__name__, "message": str(exc)}
    children = getattr(exc, "exceptions", None)
    if children:
        summary["children"] = [exception_summary(child) for child in children]
    return summary


async def run() -> int:
    config = os.environ.get("VELOCIRAPTOR_API_CONFIG", "").strip()
    if not config or not Path(config).is_file():
        raise AssertionError("VELOCIRAPTOR_API_CONFIG is required")
    velociraptor_api.init_stub(config)
    clients = velociraptor_api.list_windows_clients_strict()
    if len(clients) != 1:
        raise AssertionError(f"expected one Windows client, got {len(clients)}")
    client_id = str(clients[0]["client_id"])

    invocations = json.loads(INVOCATIONS.read_text(encoding="utf-8"))
    artifact_names = [item["artifact"] for item in invocations]
    if len(invocations) != 118 or len(set(artifact_names)) != 118:
        raise AssertionError("invocation table must contain 118 unique artifacts")
    if set(artifact_names) != set(APPROVED_WINDOWS_ARTIFACTS):
        raise AssertionError("invocation table and approved allowlist differ")

    before_resources = resources()
    if before_resources["disk_free_bytes"] < MIN_DISK_FREE:
        raise AssertionError("disk preflight below 12 GiB")
    if before_resources["memory_available_bytes"] < MIN_MEMORY_FREE:
        raise AssertionError("memory preflight below 1 GiB")
    before_flows = {str(row["session_id"]) for row in flow_rows(client_id)}
    before_hunts = hunt_ids()
    started = time.monotonic()
    evidence_path = Path(os.environ.get("P03_EVIDENCE_PATH", str(DEFAULT_EVIDENCE)))
    evidence: dict[str, Any] = {
        "workflow_id": "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2",
        "hostname": os.environ.get("COMPUTERNAME", ""),
        "client_id": client_id,
        "snapshot_baseline": "Snapshot 184-Velociraptor-MCP测试基线",
        "limits": {
            "call_seconds": CALL_TIMEOUT_SECONDS,
            "cancel_seconds": CANCEL_TIMEOUT_SECONDS,
            "wall_seconds": MAX_WALL_SECONDS,
            "minimum_disk_free_bytes": MIN_DISK_FREE,
            "minimum_memory_available_bytes": MIN_MEMORY_FREE,
            "maximum_disk_delta_bytes": MAX_DISK_DELTA,
            "maximum_total_upload_bytes": MAX_TOTAL_UPLOAD,
            "maximum_single_flow_upload_bytes": MAX_FLOW_UPLOAD,
            "maximum_active_workflow_flows": 1,
        },
        "before": {**before_resources, "flow_count": len(before_flows), "hunt_ids": sorted(before_hunts)},
        "results": [],
        "dependency_deferred": [],
        "checkpoints": [],
        "status": "running",
    }
    write_evidence(evidence_path, evidence)

    params = StdioServerParameters(
        command=sys.executable,
        args=[str(REPO_ROOT / "mcp_velociraptor_bridge.py")],
        cwd=REPO_ROOT,
        env=dict(os.environ),
    )
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                listed_names = {tool.name for tool in listed.tools}
                if not set(APPROVED_WINDOWS_ARTIFACTS).issubset(listed_names):
                    raise AssertionError("stdio tool list is missing approved artifacts")
                for index, invocation in enumerate(invocations, start=1):
                    if time.monotonic() - started > MAX_WALL_SECONDS:
                        raise AssertionError("P03 wall clock limit exceeded")
                    artifact = invocation["artifact"]
                    arguments = invocation["parameters"]
                    call_started = time.monotonic()
                    result = await asyncio.wait_for(
                        session.call_tool(artifact, arguments),
                        timeout=CALL_TIMEOUT_SECONDS,
                    )
                    if artifact in DEPENDENCY_DEFERRED_ARTIFACTS:
                        structured = result.structured_content or {}
                        current_flow_ids = {
                            str(row["session_id"]) for row in flow_rows(client_id)
                        }
                        if (
                            not result.is_error
                            or result.content
                            or structured.get("code") != "BACKEND_ERROR"
                            or structured.get("details", {}).get("reason") != "missing_flow_id"
                            or current_flow_ids != before_flows
                            | {row["flow_id"] for row in evidence["results"]}
                            or hunt_ids() != before_hunts
                        ):
                            raise AssertionError(
                                f"{artifact}: dependency-deferred pre-flow boundary changed"
                            )
                        evidence["dependency_deferred"].append(
                            {
                                "index": index,
                                "artifact": artifact,
                                "parameters": arguments,
                                "not_counted_as_success": True,
                                "error_code": structured.get("code"),
                                "error_details": structured.get("details"),
                                "flow_delta": [],
                                "hunt_delta": [],
                                "owner": "P05 dependency preparation; P06 real-flow retest",
                            }
                        )
                        continue
                    if result.is_error or result.content:
                        raise AssertionError(f"{artifact}: MCP call did not return pure structured success")
                    structured = result.structured_content or {}
                    flow_id = structured.get("flow_id")
                    if not isinstance(flow_id, str) or not flow_id.startswith("F."):
                        raise AssertionError(f"{artifact}: missing real flow id")
                    if flow_id in before_flows or any(
                        row["flow_id"] == flow_id for row in evidence["results"]
                    ):
                        raise AssertionError(f"{artifact}: flow id was not unique")
                    if structured.get("operation") != "start_artifact_collection":
                        raise AssertionError(f"{artifact}: operation mismatch")

                    detail = flow_detail(client_id, flow_id)
                    if detail is None:
                        raise AssertionError(f"{artifact}: backend flow not found")
                    initial_detail_state = str(detail.get("state") or "")
                    final_detail, cancellation_sent = wait_for_terminal(client_id, flow_id)
                    assert_request(final_detail, artifact, arguments)
                    upload_bytes = int(final_detail.get("total_uploaded_bytes") or 0)
                    if upload_bytes > MAX_FLOW_UPLOAD:
                        raise AssertionError(f"{artifact}: per-flow upload limit exceeded")

                    evidence["results"].append(
                        {
                            "index": index,
                            "artifact": artifact,
                            "parameters": arguments,
                            "risk_class": invocation["risk_class"],
                            "cancel_policy": invocation["cancel_policy"],
                            "flow_id": flow_id,
                            "mcp_status": structured.get("status"),
                            "initial_observed_state": initial_detail_state,
                            "final_state": final_detail.get("state"),
                            "cancellation_sent": cancellation_sent,
                            "upload_bytes": upload_bytes,
                            "call_elapsed_seconds": round(time.monotonic() - call_started, 3),
                            "request_parameters_verified": True,
                        }
                    )

                    created_ids = {row["flow_id"] for row in evidence["results"]}
                    active = [
                        row for row in flow_rows(client_id)
                        if str(row.get("session_id")) in created_ids and not is_terminal(row.get("state"))
                    ]
                    if active:
                        raise AssertionError(f"{artifact}: workflow flow remained active")
                    if index % 10 == 0 or index == len(invocations):
                        current = resources()
                        total_upload = sum(row["upload_bytes"] for row in evidence["results"])
                        if before_resources["disk_free_bytes"] - current["disk_free_bytes"] > MAX_DISK_DELTA:
                            raise AssertionError("disk delta exceeded 4 GiB")
                        if current["memory_available_bytes"] < MIN_MEMORY_FREE:
                            raise AssertionError("memory fell below 1 GiB")
                        if total_upload > MAX_TOTAL_UPLOAD:
                            raise AssertionError("total upload exceeded 2 GiB")
                        if hunt_ids() != before_hunts:
                            raise AssertionError("a Hunt was created during dynamic artifact acceptance")
                        evidence["checkpoints"].append(
                            {
                                "completed": index,
                                **current,
                                "active_workflow_flows": 0,
                                "total_upload_bytes": total_upload,
                                "hunt_delta": [],
                            }
                        )
                        write_evidence(evidence_path, evidence)

        after_resources = resources()
        evidence["after"] = {
            **after_resources,
            "disk_delta_bytes": before_resources["disk_free_bytes"] - after_resources["disk_free_bytes"],
            "hunt_ids": sorted(hunt_ids()),
            "total_upload_bytes": sum(row["upload_bytes"] for row in evidence["results"]),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        evidence["status"] = "passed_with_dependency_deferral"
        evidence["passed"] = len(evidence["results"])
        evidence["verified_invocations"] = len(evidence["results"]) + len(evidence["dependency_deferred"])
        write_evidence(evidence_path, evidence)
        print(
            json.dumps(
                {
                    "status": evidence["status"],
                    "real_flow_count": len(evidence["results"]),
                    "dependency_deferred_count": len(evidence["dependency_deferred"]),
                    "evidence": str(evidence_path),
                }
            )
        )
        return 0
    except Exception as exc:
        evidence["status"] = "failed"
        evidence["failure"] = exception_summary(exc)
        evidence["elapsed_seconds"] = round(time.monotonic() - started, 3)
        write_evidence(evidence_path, evidence)
        print(json.dumps({"status": "failed", "type": type(exc).__name__, "message": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
