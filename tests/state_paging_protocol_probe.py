"""Capture official-SDK stdio and loopback HTTP evidence for PC018/PC019."""

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


FIXTURE = ROOT / "tests" / "state_paging_fixture_server.py"
STATES = ("WAITING", "IN_PROGRESS", "FINISHED", "ERROR", "FUTURE_STATE", "__MISSING__", "__EMPTY__")
START_CALLS = (
    ("collect_file", {"path": r"C:\fixture\state.txt"}),
    ("collect_forensic_triage", {}),
    ("kill_process", {"pid": 123}),
    ("start_hunt", {"artifact": "Windows.System.Pslist"}),
)
EXPECTED_START_BUDGETS = (None, 4_294_967_296, None, None)


def _port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_port(port: int) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"fixture port {port} did not open")


def _result(result) -> dict:
    return {
        "is_error": bool(result.is_error),
        "content": [item.model_dump(mode="json") for item in result.content],
        "structured_content": result.structured_content,
    }


def _canonical(value) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _read_trace(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _schema_inventory(tools) -> list[dict]:
    return [
        {
            "name": tool.name,
            "inputSchema": tool.input_schema,
            "outputSchema": tool.output_schema,
        }
        for tool in tools
    ]


async def _list_all_tools(session: ClientSession):
    cursor = None
    tools = []
    pages = []
    seen_cursors = set()
    while True:
        page = (
            await session.list_tools(cursor=cursor)
            if cursor is not None
            else await session.list_tools()
        )
        pages.append(
            {
                "cursor_used": cursor,
                "response": page.model_dump(mode="json", by_alias=True),
            }
        )
        tools.extend(page.tools)
        next_cursor = page.next_cursor
        if next_cursor is None:
            return tools, pages
        if next_cursor in seen_cursors:
            raise AssertionError("tools/list cursor repeated")
        seen_cursors.add(next_cursor)
        cursor = next_cursor


async def _exercise(session: ClientSession, state: str) -> dict:
    initialized = await session.initialize()
    tools, tool_pages = await _list_all_tools(session)
    starts = {}
    for name, arguments in START_CALLS:
        starts[name] = _result(await session.call_tool(name, arguments))
    record = {
        "protocol_version": initialized.protocol_version,
        "server": initialized.server_info.model_dump(mode="json"),
        "tool_count": len(tools),
        "tool_names": [tool.name for tool in tools],
        "start_requests": [
            {"name": name, "arguments": arguments} for name, arguments in START_CALLS
        ],
        "start_calls": starts,
    }
    if state == "WAITING":
        inventory = _schema_inventory(tools)
        normalized = sorted(inventory, key=lambda row: row["name"])
        record.update(
            {
                "tools_list_pages": tool_pages,
                "schema_inventory": inventory,
                "schema_sha256": _sha256(normalized),
                "input_schema_sha256": _sha256(
                    [
                        {"name": row["name"], "inputSchema": row["inputSchema"]}
                        for row in normalized
                    ]
                ),
                "output_schema_sha256": _sha256(
                    [
                        {"name": row["name"], "outputSchema": row["outputSchema"]}
                        for row in normalized
                    ]
                ),
                "schema_hash_algorithm": (
                    "SHA-256 of UTF-8 JSON; ensure_ascii=false, allow_nan=false, "
                    "sort_keys=true, separators=(',',':'); rows sorted by tool name"
                ),
            }
        )
        calls = (
            ("nonterminal", "get_flow_results", {"flow_id": "F.page-a", "source": "A", "page_size": 1}),
            ("offset_equals_length", "get_flow_results", {"flow_id": "F.page-a", "source": "A", "cursor": "v1:2", "page_size": 1}),
            ("empty_source", "get_flow_results", {"flow_id": "F.empty", "source": "A", "cursor": "v1:0", "page_size": 1}),
            ("unpaged", "run_vql", {"query": "SELECT 1 FROM scope()"}),
            ("dynamic_unchanged", "Windows.System.Pslist", {}),
        )
        record["paging_calls"] = {
            label: _result(await session.call_tool(name, arguments))
            for label, name, arguments in calls
        }
        record["paging_requests"] = [
            {"label": label, "name": name, "arguments": arguments}
            for label, name, arguments in calls
        ]
    return record


def _schema_by_name(row: dict) -> dict[str, dict]:
    inventory = row["schema_inventory"]
    names = [item["name"] for item in inventory]
    assert len(names) == len(set(names)), "duplicate tool name"
    expected = set(APPROVED_WINDOWS_ARTIFACTS).union(FIXED_TOOL_NAMES)
    assert len(expected) == 130
    assert set(names) == expected
    return {item["name"]: item for item in inventory}


def _resolve(schema: dict, root: dict) -> dict:
    node = schema
    while "$ref" in node:
        resolved = root
        for part in node["$ref"].removeprefix("#/").split("/"):
            resolved = resolved[part]
        node = resolved
    return node


def _assert_changed_output_contracts(by_name: dict[str, dict]) -> None:
    for name in ("collect_file", "collect_forensic_triage", "kill_process"):
        output = by_name[name]["outputSchema"]
        assert "state" in output["required"]
        assert output["properties"]["state"]["type"] == "string"
        assert output["properties"]["state"]["minLength"] == 1
    hunt = by_name["start_hunt"]["outputSchema"]
    assert "flow_state" in hunt["required"]
    assert hunt["properties"]["flow_state"]["type"] == "string"
    assert hunt["properties"]["flow_state"]["minLength"] == 1
    flow_results = by_name["get_flow_results"]["outputSchema"]
    pagination = _resolve(flow_results["properties"]["pagination"], flow_results)
    assert "next_cursor" in pagination["required"]
    branches = pagination["properties"]["next_cursor"]["anyOf"]
    assert {branch.get("type") for branch in branches} == {"string", "null"}


async def _stdio(state: str) -> dict:
    env = dict(os.environ)
    env["STATE_PAGING_FIXTURE_STATE"] = state
    stderr = tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False)
    trace = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False)
    trace_path = Path(trace.name)
    trace.close()
    env["STATE_PAGING_FIXTURE_TRACE"] = str(trace_path)
    try:
        params = StdioServerParameters(
            command=sys.executable, args=[str(FIXTURE)], cwd=ROOT, env=env
        )
        async with stdio_client(params, errlog=stderr) as streams:
            async with ClientSession(*streams) as session:
                result = await _exercise(session, state)
        stderr.flush()
        stderr.seek(0)
        result["process"] = {"context_exited": True, "stderr": stderr.read()}
        result["start_collection_calls"] = _read_trace(trace_path)
        return result
    finally:
        stderr.close()
        Path(stderr.name).unlink(missing_ok=True)
        trace_path.unlink(missing_ok=True)


async def _http(state: str) -> dict:
    import httpx2

    port = _port()
    env = dict(os.environ)
    trace = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False)
    trace_path = Path(trace.name)
    trace.close()
    env.update(
        {
            "STATE_PAGING_FIXTURE_STATE": state,
            "STATE_PAGING_FIXTURE_TRANSPORT": "http",
            "STATE_PAGING_FIXTURE_PORT": str(port),
            "STATE_PAGING_FIXTURE_TRACE": str(trace_path),
        }
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
        await asyncio.to_thread(_wait_port, port)
        async with httpx2.AsyncClient(timeout=30) as client:
            async with streamable_http_client(
                f"http://127.0.0.1:{port}/mcp", http_client=client
            ) as streams:
                async with ClientSession(*streams[:2]) as session:
                    result = await _exercise(session, state)
    finally:
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate(timeout=15)
    result["process"] = {
        "pid": proc.pid,
        "returncode": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "port": port,
        "terminated": True,
    }
    result["start_collection_calls"] = _read_trace(trace_path)
    trace_path.unlink(missing_ok=True)
    return result


def _assert_record(evidence: dict) -> None:
    budget_observations = []
    for transport in ("stdio", "http"):
        for state in STATES:
            row = evidence[transport][state]
            assert row["tool_count"] == 130
            observed_budgets = tuple(
                call["max_upload_bytes"] for call in row["start_collection_calls"]
            )
            assert observed_budgets == EXPECTED_START_BUDGETS
            budget_observations.extend(
                {
                    "transport": transport,
                    "state": state,
                    **call,
                }
                for call in row["start_collection_calls"]
            )
            for name, result in row["start_calls"].items():
                if state in {"__MISSING__", "__EMPTY__"}:
                    assert result["is_error"]
                    assert result["structured_content"]["code"] == "BACKEND_ERROR"
                    continue
                assert not result["is_error"]
                structured = result["structured_content"]
                assert structured["status"] == "success"
                assert structured["flow_state" if name == "start_hunt" else "state"] == state
                if name == "start_hunt":
                    assert structured["state"] == "PAUSED"
        paging = evidence[transport]["WAITING"]["paging_calls"]
        assert paging["nonterminal"]["structured_content"]["pagination"]["next_cursor"] == "v1:1"
        for label in ("offset_equals_length", "empty_source"):
            assert paging[label]["structured_content"]["pagination"]["next_cursor"] is None
        assert "pagination" not in paging["unpaged"]["structured_content"]
        assert "state" not in paging["dynamic_unchanged"]["structured_content"]
    stdio = evidence["stdio"]["WAITING"]
    http = evidence["http"]["WAITING"]
    stdio_by_name = _schema_by_name(stdio)
    http_by_name = _schema_by_name(http)
    _assert_changed_output_contracts(stdio_by_name)
    _assert_changed_output_contracts(http_by_name)
    assert stdio_by_name == http_by_name
    assert stdio["schema_sha256"] == http["schema_sha256"]
    assert stdio["input_schema_sha256"] == http["input_schema_sha256"]
    assert stdio["output_schema_sha256"] == http["output_schema_sha256"]
    expected = set(APPROVED_WINDOWS_ARTIFACTS).union(FIXED_TOOL_NAMES)
    evidence["complete_schema_comparison"] = {
        "expected_count": len(expected),
        "stdio_count": len(stdio["schema_inventory"]),
        "http_count": len(http["schema_inventory"]),
        "stdio_unique_count": len(stdio_by_name),
        "http_unique_count": len(http_by_name),
        "stdio_missing": sorted(expected.difference(stdio_by_name)),
        "stdio_extra": sorted(set(stdio_by_name).difference(expected)),
        "http_missing": sorted(expected.difference(http_by_name)),
        "http_extra": sorted(set(http_by_name).difference(expected)),
        "stdio_only": sorted(set(stdio_by_name).difference(http_by_name)),
        "http_only": sorted(set(http_by_name).difference(stdio_by_name)),
        "schema_sha256": stdio["schema_sha256"],
        "input_schema_sha256": stdio["input_schema_sha256"],
        "output_schema_sha256": stdio["output_schema_sha256"],
        "all_name_input_output_equal": True,
        "duplicate_check_performed_before_name_mapping": True,
        "changed_output_contracts_checked": True,
    }
    evidence["budget_assertion"] = {
        "expected_per_start_sequence": list(EXPECTED_START_BUDGETS),
        "observation_count": len(budget_observations),
        "triage_4gib_count": sum(
            row["max_upload_bytes"] == 4_294_967_296
            for row in budget_observations
        ),
        "other_none_count": sum(
            row["max_upload_bytes"] is None for row in budget_observations
        ),
        "all_transports_and_states_checked": True,
    }


async def main_async(output: Path) -> None:
    evidence = {"schema": "state-paging-protocol-v1", "stdio": {}, "http": {}}
    for state in STATES:
        evidence["stdio"][state] = await _stdio(state)
        evidence["http"][state] = await _http(state)
    _assert_record(evidence)
    evidence["ok"] = True
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "output": str(output)}, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(main_async(args.output))


if __name__ == "__main__":
    main()
