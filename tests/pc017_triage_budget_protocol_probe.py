"""Official-SDK stdio/HTTP proof for the fixed triage request budget."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from velociraptor_dynamic_artifacts import APPROVED_WINDOWS_ARTIFACTS
from velociraptor_fixed_tools import FIXED_TOOL_NAMES

FIXTURE = ROOT / "tests" / "pc017_triage_budget_fixture_server.py"
FROZEN_SCHEMA_SHA256 = "454cbf9a7059106f2e16e7c847be44ca1119d1a92079ffba7841b7b4bec0c5e8"


def result(value):
    return {
        "is_error": bool(value.is_error),
        "content": [item.model_dump(mode="json") for item in value.content],
        "structured_content": value.structured_content,
    }


def canonical(value):
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(number):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", number), timeout=.5):
                return
        except OSError:
            time.sleep(.1)
    raise TimeoutError(number)


async def list_tools(session):
    cursor = None
    tools, pages, seen = [], [], set()
    while True:
        page = await session.list_tools(cursor=cursor) if cursor else await session.list_tools()
        pages.append({"cursor_used": cursor, "response": page.model_dump(mode="json", by_alias=True)})
        tools.extend(page.tools)
        cursor = page.next_cursor
        if cursor is None:
            return tools, pages
        assert cursor not in seen
        seen.add(cursor)


async def exercise(session, *, include_inventory):
    initialized = await session.initialize()
    inventory, pages = [], []
    if include_inventory:
        tools, pages = await list_tools(session)
        inventory = [
            {"name": tool.name, "inputSchema": tool.input_schema, "outputSchema": tool.output_schema}
            for tool in tools
        ]
    call = result(await session.call_tool("collect_forensic_triage", {}))
    return {
        "protocol_version": initialized.protocol_version,
        "server": initialized.server_info.model_dump(mode="json"),
        "tools_list_pages": pages,
        "schema_inventory": inventory,
        "call": call,
    }


async def stdio_case(root: Path, *, dependency: bool, include_inventory: bool):
    trace = root / "request-trace.json"
    env = dict(
        os.environ,
        PC017_TRIAGE_TRACE=str(trace),
        PC017_TRIAGE_DEPENDENCY="present" if dependency else "missing",
        PC017_TRIAGE_DOWNLOAD_ROOT=str(root),
    )
    err = tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False)
    try:
        params = StdioServerParameters(
            command=sys.executable, args=[str(FIXTURE)], cwd=ROOT, env=env
        )
        async with stdio_client(params, errlog=err) as streams:
            async with ClientSession(*streams) as session:
                data = await exercise(session, include_inventory=include_inventory)
        err.flush()
        err.seek(0)
        data["process"] = {"context_exited": True, "stderr": err.read()}
        data["request_trace"] = json.loads(trace.read_text(encoding="utf-8"))
        return data
    finally:
        err.close()
        Path(err.name).unlink(missing_ok=True)


async def http_case(root: Path, *, dependency: bool, include_inventory: bool):
    import httpx2

    trace = root / "request-trace.json"
    number = free_port()
    env = dict(
        os.environ,
        PC017_TRIAGE_TRACE=str(trace),
        PC017_TRIAGE_DEPENDENCY="present" if dependency else "missing",
        PC017_TRIAGE_DOWNLOAD_ROOT=str(root),
        PC017_TRIAGE_TRANSPORT="http",
        PC017_TRIAGE_PORT=str(number),
    )
    proc = subprocess.Popen(
        [sys.executable, str(FIXTURE)],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        await asyncio.to_thread(wait_port, number)
        async with httpx2.AsyncClient(timeout=30) as client:
            async with streamable_http_client(
                f"http://127.0.0.1:{number}/mcp", http_client=client
            ) as streams:
                async with ClientSession(*streams[:2]) as session:
                    data = await exercise(session, include_inventory=include_inventory)
    finally:
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate(timeout=15)
    data["process"] = {
        "pid": proc.pid,
        "returncode": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "port": number,
        "terminated": True,
    }
    data["request_trace"] = json.loads(trace.read_text(encoding="utf-8"))
    return data


def assert_case(row, *, dependency):
    call = row["call"]
    trace = row["request_trace"]
    assert call["content"] == []
    assert all(request["org_id"] == "" for request in trace["requests"])
    if not dependency:
        assert call["is_error"] is True
        assert call["structured_content"]["code"] == "DEPENDENCY_MISSING"
        assert call["structured_content"]["details"] == {"artifact": "Windows.Triage.Targets"}
        assert trace["submit_count"] == 0
        return
    assert call == {
        "is_error": False,
        "content": [],
        "structured_content": {
            "operation": "collect_forensic_triage",
            "status": "success",
            "warnings": [],
            "flow_id": "F.triage-budget",
            "state": "WAITING",
        },
    }
    assert trace["submit_count"] == 1
    submit = next(
        item["query"]
        for item in trace["requests"]
        if "LET collection <= collect_client" in item["query"]
    )
    assert "artifacts='Windows.Triage.Targets'" in submit
    assert "env=dict(Targets='[\"_BasicCollection\"]')" in submit
    assert ", timeout=2400" in submit
    assert ", max_bytes=4294967296" in submit


async def main_async(output: Path):
    evidence = {"schema": "pc017-triage-budget-v1"}
    with tempfile.TemporaryDirectory(prefix="triage-budget-stdio-ok-") as path:
        evidence["stdio_success"] = await stdio_case(
            Path(path), dependency=True, include_inventory=True
        )
    with tempfile.TemporaryDirectory(prefix="triage-budget-stdio-missing-") as path:
        evidence["stdio_missing"] = await stdio_case(
            Path(path), dependency=False, include_inventory=False
        )
    with tempfile.TemporaryDirectory(prefix="triage-budget-http-ok-") as path:
        evidence["http_success"] = await http_case(
            Path(path), dependency=True, include_inventory=True
        )
    with tempfile.TemporaryDirectory(prefix="triage-budget-http-missing-") as path:
        evidence["http_missing"] = await http_case(
            Path(path), dependency=False, include_inventory=False
        )

    for transport in ("stdio", "http"):
        assert_case(evidence[f"{transport}_success"], dependency=True)
        assert_case(evidence[f"{transport}_missing"], dependency=False)
    stdio_inventory = evidence["stdio_success"]["schema_inventory"]
    http_inventory = evidence["http_success"]["schema_inventory"]
    names = [row["name"] for row in stdio_inventory]
    assert len(names) == len(set(names)) == 130
    assert set(names) == set(APPROVED_WINDOWS_ARTIFACTS).union(FIXED_TOOL_NAMES)
    stdio_ordered = sorted(stdio_inventory, key=lambda row: row["name"])
    http_ordered = sorted(http_inventory, key=lambda row: row["name"])
    assert stdio_ordered == http_ordered
    schema_sha256 = hashlib.sha256(canonical(stdio_ordered)).hexdigest()
    assert schema_sha256 == FROZEN_SCHEMA_SHA256
    triage_schema = next(
        row for row in stdio_inventory if row["name"] == "collect_forensic_triage"
    )
    assert triage_schema["inputSchema"].get("properties") == {}
    assert triage_schema["inputSchema"].get("required", []) == []
    assert set(triage_schema["outputSchema"]["required"]) == {
        "operation", "status", "warnings", "flow_id", "state"
    }
    evidence["schema_comparison"] = {
        "count": 130,
        "bidirectional_diff": [],
        "all_name_input_output_equal": True,
        "sha256": schema_sha256,
        "triage_has_no_public_parameters": True,
    }
    evidence["ok"] = True
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "output": str(output)}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    asyncio.run(main_async(parser.parse_args().output))


if __name__ == "__main__":
    main()
