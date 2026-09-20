"""Official-SDK stdio/HTTP probe for the PC017 logical-file contract."""

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

FIXTURE = ROOT / "tests" / "pc017_file_fixture_server.py"


def result(value):
    return {
        "is_error": bool(value.is_error),
        "content": [item.model_dump(mode="json") for item in value.content],
        "structured_content": value.structured_content,
    }


def canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(number):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", number), timeout=.5): return
        except OSError: time.sleep(.1)
    raise TimeoutError(number)


async def list_tools(session):
    cursor = None
    tools, pages, seen = [], [], set()
    while True:
        page = await session.list_tools(cursor=cursor) if cursor else await session.list_tools()
        pages.append({"cursor_used": cursor, "response": page.model_dump(mode="json", by_alias=True)})
        tools.extend(page.tools)
        cursor = page.next_cursor
        if cursor is None: return tools, pages
        assert cursor not in seen
        seen.add(cursor)


async def exercise(session):
    initialized = await session.initialize()
    tools, pages = await list_tools(session)
    inventory = [{"name": t.name, "inputSchema": t.input_schema, "outputSchema": t.output_schema} for t in tools]
    names = [row["name"] for row in inventory]
    assert len(names) == len(set(names))
    expected = set(APPROVED_WINDOWS_ARTIFACTS).union(FIXED_TOOL_NAMES)
    assert len(names) == 130 and set(names) == expected

    normal_list = result(await session.call_tool("list_flow_files", {"flow_id": "F.normal"}))
    sparse_list = result(await session.call_tool("list_flow_files", {"flow_id": "F.sparse"}))
    normal_id = normal_list["structured_content"]["data"][0]["file_id"]
    sparse_id = sparse_list["structured_content"]["data"][0]["file_id"]
    calls = {
        "normal_list": normal_list,
        "sparse_list": sparse_list,
        "normal_download": result(await session.call_tool("download_flow_file", {"flow_id": "F.normal", "file_id": normal_id})),
        "sparse_download": result(await session.call_tool("download_flow_file", {"flow_id": "F.sparse", "file_id": sparse_id})),
        "unknown_file": result(await session.call_tool("download_flow_file", {"flow_id": "F.normal", "file_id": "f" * 64})),
        "bad_metadata": result(await session.call_tool("list_flow_files", {"flow_id": "F.bad"})),
        "already_exists": result(await session.call_tool("download_flow_file", {"flow_id": "F.normal", "file_id": normal_id})),
    }
    post_list = result(await session.call_tool("list_flow_files", {"flow_id": "F.post"}))
    post_id = post_list["structured_content"]["data"][0]["file_id"]
    calls["post_publish_error"] = result(await session.call_tool("download_flow_file", {"flow_id": "F.post", "file_id": post_id}))
    calls["error_flow_status_before"] = result(await session.call_tool("get_flow_status", {"flow_id": "F.error"}))
    error_list = result(await session.call_tool("list_flow_files", {"flow_id": "F.error"}))
    error_id = error_list["structured_content"]["data"][0]["file_id"]
    calls["error_flow_download"] = result(await session.call_tool("download_flow_file", {"flow_id": "F.error", "file_id": error_id}))
    calls["error_flow_status_after"] = result(await session.call_tool("get_flow_status", {"flow_id": "F.error"}))

    ordered = sorted(inventory, key=lambda row: row["name"])
    return {
        "protocol_version": initialized.protocol_version,
        "server": initialized.server_info.model_dump(mode="json"),
        "tools_list_pages": pages,
        "schema_inventory": inventory,
        "schema_sha256": hashlib.sha256(canonical(ordered)).hexdigest(),
        "tool_count": len(inventory),
        "calls": calls,
    }


async def stdio(root):
    env = dict(os.environ, PC017_FILE_ROOT=str(root))
    err = tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False)
    try:
        params = StdioServerParameters(command=sys.executable, args=[str(FIXTURE)], cwd=ROOT, env=env)
        async with stdio_client(params, errlog=err) as streams:
            async with ClientSession(*streams) as session: data = await exercise(session)
        err.flush(); err.seek(0); data["process"] = {"context_exited": True, "stderr": err.read()}
        return data
    finally:
        err.close(); Path(err.name).unlink(missing_ok=True)


async def http(root):
    import httpx2
    number = port()
    env = dict(os.environ, PC017_FILE_ROOT=str(root), PC017_FILE_TRANSPORT="http", PC017_FILE_PORT=str(number))
    proc = subprocess.Popen([sys.executable, str(FIXTURE)], cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        await asyncio.to_thread(wait_port, number)
        async with httpx2.AsyncClient(timeout=30) as client:
            async with streamable_http_client(f"http://127.0.0.1:{number}/mcp", http_client=client) as streams:
                async with ClientSession(*streams[:2]) as session: data = await exercise(session)
    finally:
        proc.terminate()
        try: stdout, stderr = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill(); stdout, stderr = proc.communicate(timeout=15)
    data["process"] = {"pid": proc.pid, "returncode": proc.returncode, "stdout": stdout, "stderr": stderr, "port": number, "terminated": True}
    return data


def assert_contract(evidence):
    expected_hashes = []
    for transport in ("stdio", "http"):
        row = evidence[transport]
        assert row["tool_count"] == 130
        expected_hashes.append(row["schema_sha256"])
        calls = row["calls"]
        assert calls["sparse_list"]["structured_content"]["warnings"] == ["sparse_indexes_internal:1"]
        assert calls["normal_download"]["structured_content"]["size"] == len(b"protocol-payload")
        assert calls["sparse_download"]["structured_content"]["size"] == 16
        assert calls["unknown_file"]["structured_content"]["code"] == "NOT_FOUND"
        assert calls["bad_metadata"]["structured_content"]["details"]["reason"] == "unsupported_upload_type"
        assert calls["already_exists"]["structured_content"]["code"] == "ALREADY_EXISTS"
        assert calls["post_publish_error"]["structured_content"]["details"]["reason"] == "download_post_publish_failed"
        post = calls["post_publish_error"]
        assert post["is_error"] is True
        assert post["structured_content"]["code"] == "BACKEND_ERROR"
        assert post["structured_content"]["retryable"] is False
        assert post["structured_content"]["message"] == (
            "The file was published, but post-publication validation or cleanup failed. "
            "The completed file may remain; do not automatically retry or overwrite it."
        )
        assert set(post["structured_content"]) == {"code", "message", "retryable", "details"}
        assert "content.bin" not in post["structured_content"]["message"]
        assert "injected" not in post["structured_content"]["message"]
        assert calls["error_flow_download"]["is_error"] is False
        assert calls["error_flow_status_before"]["structured_content"]["state"] == "ERROR"
        assert calls["error_flow_status_after"]["structured_content"]["state"] == "ERROR"
        for call in calls.values():
            assert call["content"] == []
            assert "protocol-payload" not in json.dumps(call["structured_content"])
    assert expected_hashes[0] == expected_hashes[1]
    stdio = {x["name"]: x for x in evidence["stdio"]["schema_inventory"]}
    http_rows = {x["name"]: x for x in evidence["http"]["schema_inventory"]}
    assert stdio == http_rows
    evidence["schema_comparison"] = {"count": 130, "bidirectional_diff": [], "all_name_input_output_equal": True, "sha256": expected_hashes[0]}


async def main_async(output):
    with tempfile.TemporaryDirectory(prefix="pc017-stdio-") as first, tempfile.TemporaryDirectory(prefix="pc017-http-") as second:
        evidence = {"schema": "pc017-file-protocol-v1", "stdio": await stdio(Path(first)), "http": await http(Path(second))}
    assert_contract(evidence); evidence["ok"] = True
    output.parent.mkdir(parents=True, exist_ok=True); output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "output": str(output)}))


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--output", type=Path, required=True)
    asyncio.run(main_async(parser.parse_args().output))


if __name__ == "__main__": main()
