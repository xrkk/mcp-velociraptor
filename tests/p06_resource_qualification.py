"""Win10-only resource qualification for the five formal P06 scenarios."""

from __future__ import annotations

import asyncio
import ctypes
import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


INVOCATIONS = REPO_ROOT / "tests" / "data" / "p03_invocations.json"
FIXTURE = Path(r"C:\VelociraptorMCP\fixtures-p05\fixture-instance-v1.json")
DATASTORE = Path(r"C:\VelociraptorMCP\datastore")
DOWNLOAD_ROOT = Path(os.environ.get("VELOCIRAPTOR_DOWNLOAD_ROOT", r"C:\VelociraptorMCP\downloads"))
OUT = Path(
    os.environ.get(
        "P06_EVIDENCE_ROOT", str(REPO_ROOT / "Logs" / "P06" / "wf-01a05d1d-p06")
    )
) / "resource-qualification.json"
STATIC_EXTRA = 4 * 1024**3
MEMORY_MARGIN = 64 * 1024**2
MIN_FINAL_FREE = 4 * 1024**3


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


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def memory() -> tuple[int, int]:
    state = MemoryStatusEx()
    state.length = ctypes.sizeof(state)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(state)):
        raise ctypes.WinError()
    return int(state.total_physical), int(state.available_physical)


def tree_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    total = 0
    for base, _, files in os.walk(path):
        for name in files:
            candidate = Path(base) / name
            try:
                total += candidate.stat().st_size
            except OSError:
                continue
    return total


def resources() -> dict[str, int]:
    total_memory, available_memory = memory()
    disk = shutil.disk_usage("C:\\")
    return {
        "physical_memory_bytes": total_memory,
        "available_memory_bytes": available_memory,
        "c_total_bytes": disk.total,
        "c_free_bytes": disk.free,
        "datastore_bytes": tree_bytes(DATASTORE),
        "download_root_bytes": tree_bytes(DOWNLOAD_ROOT),
        "report_root_bytes": tree_bytes(OUT.parent),
    }


def prepare_download_root(path: Path) -> None:
    """Create the fixed test output directory required by the product contract."""
    if not path.is_absolute():
        raise ValueError("P06 download root must be absolute")
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir() or path.is_symlink():
        raise ValueError("P06 download root must be a plain directory")


def exception_detail(exc: BaseException) -> dict[str, object]:
    detail: dict[str, object] = {
        "type": type(exc).__name__,
        "message": str(exc),
    }
    nested = getattr(exc, "exceptions", None)
    if nested:
        detail["causes"] = [exception_detail(item) for item in nested]
    return detail


def result_row(result) -> dict:
    return {"is_error": bool(result.is_error), "structured": result.structured_content}


async def call(session, calls: list[dict], tool: str, arguments: dict) -> dict:
    started = time.monotonic()
    row = result_row(await session.call_tool(tool, arguments))
    calls.append(
        {
            "sequence": len(calls) + 1,
            "tool": tool,
            "arguments": arguments,
            "result": row,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
    )
    if row["is_error"]:
        raise AssertionError(f"{tool} returned MCP error: {row['structured']}")
    return row["structured"]


async def wait_finished(session, calls: list[dict], flow_id: str, timeout: int) -> dict:
    deadline = time.monotonic() + timeout
    states = []
    while time.monotonic() < deadline:
        row = await call(session, calls, "get_flow_status", {"flow_id": flow_id})
        states.append(row["state"])
        if row["flow_id"] != flow_id:
            raise AssertionError("flow status identity substitution")
        if row["state"] == "FINISHED":
            return {"final": row, "states": states}
        if row["state"] == "ERROR":
            raise AssertionError(f"flow ended in ERROR: {flow_id}")
        await asyncio.sleep(5)
    raise TimeoutError(f"flow deadline exceeded: {flow_id}")


def extract_etl(rows: list[dict]) -> str:
    matches = set()
    for row in rows:
        for value in row.values():
            if isinstance(value, str):
                matches.update(re.findall(r"[A-Za-z]:\\[^\r\n]*?\.etl", value, re.IGNORECASE))
    if len(matches) != 1:
        raise AssertionError(f"PacketCapture returned {len(matches)} ETL paths")
    return next(iter(matches))


async def run_flow(
    session,
    evidence: dict,
    label: str,
    tool: str,
    arguments: dict,
    *,
    timeout: int,
) -> dict:
    before = resources()
    started = time.monotonic()
    created = await call(session, evidence["calls"], tool, arguments)
    flow_id = created.get("flow_id")
    if not isinstance(flow_id, str) or not flow_id.startswith("F."):
        raise AssertionError(f"{tool} did not return a real flow id")
    terminal = await wait_finished(session, evidence["calls"], flow_id, timeout)
    results = await call(
        session, evidence["calls"], "get_flow_results", {"flow_id": flow_id, "page_size": 1}
    )
    files = await call(session, evidence["calls"], "list_flow_files", {"flow_id": flow_id})
    after = resources()
    row = {
        "label": label,
        "tool": tool,
        "flow_id": flow_id,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "states": terminal["states"],
        "result_rows_observed": len(results["data"]),
        "files": files["data"],
        "before": before,
        "after": after,
        "c_consumed_bytes": before["c_free_bytes"] - after["c_free_bytes"],
        "datastore_delta_bytes": after["datastore_bytes"] - before["datastore_bytes"],
        "download_delta_bytes": after["download_root_bytes"] - before["download_root_bytes"],
    }
    evidence["steps"].append(row)
    return {"created": created, "results": results, "files": files, "row": row}


def load_restore_binding(evidence_root: Path) -> dict:
    """Bind this qualification run to the P06_ACTIVE restore declaration."""
    import hashlib

    path = evidence_root / "current-restore.json"
    if not path.is_file():
        raise RuntimeError("P06_EVIDENCE_ROOT must contain current-restore.json")
    raw = path.read_bytes()
    document = json.loads(raw.decode("utf-8"))
    if (
        document.get("snapshot_stage") != "P06_ACTIVE"
        or document.get("snapshot_name") != "Snapshot 186-Velociraptor-MCP网络部署基线"
        or document.get("canonical_schema_version") != 3
        or document.get("canonical_epoch") != 4
        or document.get("canonical_phase") != "NETWORK_ACTIVE"
    ):
        raise RuntimeError("restore declaration is not the activated Snapshot186 baseline")
    return {"document": document, "sha256": hashlib.sha256(raw).hexdigest()}


async def main_async() -> int:
    if os.environ.get("COMPUTERNAME", "").upper() != "DESKTOP-3FI41GR":
        raise RuntimeError("P06 resource qualification only runs on DESKTOP-3FI41GR")
    restore_binding = load_restore_binding(Path(os.environ["P06_EVIDENCE_ROOT"]))
    prepare_download_root(DOWNLOAD_ROOT)
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    invocations = [
        row
        for row in json.loads(INVOCATIONS.read_text(encoding="utf-8"))
        if row["risk_class"] == "resource_sensitive"
    ]
    if len(invocations) != 9:
        raise AssertionError("reviewed resource-sensitive set is not 9")
    start = resources()
    static_required = 2 * (start["physical_memory_bytes"] + MEMORY_MARGIN) + STATIC_EXTRA
    evidence = {
        "schema": "p06-resource-qualification-v1",
        "snapshot": "Snapshot 186-Velociraptor-MCP网络部署基线",
        "restore_binding_sha256": restore_binding["sha256"],
        "hostname": os.environ.get("COMPUTERNAME"),
        "started_at": utc_now(),
        "static_required_bytes": static_required,
        "before": start,
        "calls": [],
        "steps": [],
        "status": "running",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    if start["c_free_bytes"] < static_required:
        evidence["status"] = "blocked_low_space_before_calls"
        evidence["ended_at"] = utc_now()
        OUT.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
        return 2
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
                if len((await session.list_tools()).tools) != 130:
                    raise AssertionError("runtime tool inventory is not 130")
                for invocation in invocations:
                    artifact = invocation["artifact"]
                    if resources()["c_free_bytes"] < MIN_FINAL_FREE:
                        raise AssertionError(f"low-space pre-call rejection: {artifact}")
                    if artifact == "Windows.Network.PacketCapture":
                        started = await run_flow(
                            session,
                            evidence,
                            "packet-start",
                            artifact,
                            {"StartTrace": True},
                            timeout=600,
                        )
                        etl = extract_etl(started["results"]["data"])
                        await run_flow(
                            session,
                            evidence,
                            "packet-stop",
                            artifact,
                            {"StartTrace": False, "TraceFile": etl},
                            timeout=900,
                        )
                    else:
                        timeout = 3600 if artifact == "Windows.Memory.Acquisition" else 1200
                        await run_flow(
                            session,
                            evidence,
                            artifact,
                            artifact,
                            invocation["parameters"],
                            timeout=timeout,
                        )

                triage = await run_flow(
                    session,
                    evidence,
                    "forensic-triage",
                    "collect_forensic_triage",
                    {},
                    timeout=2400,
                )
                collected = await run_flow(
                    session,
                    evidence,
                    "fixture-file",
                    "collect_file",
                    {"path": fixture["files"][0]["path"]},
                    timeout=300,
                )
                if not collected["files"]["data"]:
                    raise AssertionError("fixture collection returned no file")
                file_id = collected["files"]["data"][0]["file_id"]
                await call(
                    session,
                    evidence["calls"],
                    "download_flow_file",
                    {"flow_id": collected["row"]["flow_id"], "file_id": file_id},
                )
                if not triage["row"]["flow_id"]:
                    raise AssertionError("triage flow identity missing")
        final = resources()
        elapsed = round(sum(step["elapsed_seconds"] for step in evidence["steps"]), 3)
        peaks = [max(0, step["c_consumed_bytes"]) for step in evidence["steps"]]
        evidence["after"] = final
        evidence["observed_peak_bytes"] = max(peaks, default=0)
        evidence["evidence_reserve_bytes"] = max(OUT.stat().st_size, final["report_root_bytes"] - start["report_root_bytes"])
        evidence["step_deadlines_seconds"] = {
            step["label"]: max(180, int(step["elapsed_seconds"] * 2 + 1)) for step in evidence["steps"]
        }
        evidence["scenario_deadline_seconds"] = int(sum(evidence["step_deadlines_seconds"].values()) * 1.1 + 1)
        evidence["qualification_elapsed_seconds"] = elapsed
        evidence["formal_scenario_minimum_free_bytes"] = evidence["observed_peak_bytes"] + max(
            STATIC_EXTRA, 2 * evidence["evidence_reserve_bytes"]
        )
        if final["c_free_bytes"] < MIN_FINAL_FREE:
            raise AssertionError("qualification consumed the 4 GiB final safety reserve")
        evidence["status"] = "success"
        return 0
    except Exception as exc:
        evidence["status"] = "failed"
        evidence["failure"] = exception_detail(exc)
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
        OUT.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"out": str(OUT), "status": evidence["status"]}, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main_async()))
