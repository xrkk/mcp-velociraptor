from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from velociraptor_dynamic_artifacts import APPROVED_WINDOWS_ARTIFACTS
from velociraptor_fixed_tools import FIXED_TOOL_NAMES


OUT = REPO_ROOT / "Logs" / "P04" / "wf-01a05d1d-p04" / "p04-protocol.json"
REMOVED = {
    "list_orgs",
    "client_info",
    "list_clients",
    "get_hunt_results_tool",
    "quarantine_host",
    "unquarantine_host",
    "get_collection_results",
}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def tool_digest(tools):
    rows = [
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.input_schema,
            "outputSchema": tool.output_schema,
        }
        for tool in tools
    ]
    return hashlib.sha256(canonical(rows).encode("utf-8")).hexdigest()


def result_row(result):
    return {
        "is_error": bool(result.is_error),
        "content_count": len(result.content),
        "structured": result.structured_content,
    }


async def main_async():
    config = os.environ.get("VELOCIRAPTOR_API_CONFIG", "")
    download_root = os.environ.get("VELOCIRAPTOR_DOWNLOAD_ROOT", "")
    if not config or not Path(config).is_file():
        raise RuntimeError("VELOCIRAPTOR_API_CONFIG must name an existing file")
    if not download_root or not Path(download_root).is_dir():
        raise RuntimeError("VELOCIRAPTOR_DOWNLOAD_ROOT must name an existing directory")
    env = dict(os.environ)
    stderr_file = tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False)
    stderr_path = Path(stderr_file.name)
    evidence = {"schema": "p04-protocol-v1", "calls": {}}
    try:
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(REPO_ROOT / "mcp_velociraptor_bridge.py")],
            cwd=REPO_ROOT,
            env=env,
        )
        async with stdio_client(params, errlog=stderr_file) as (read, write):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                first = (await session.list_tools()).tools
                second = (await session.list_tools()).tools
                names = {tool.name for tool in first}
                assert initialized.server_info.name == "velociraptor-mcp"
                assert names == set(APPROVED_WINDOWS_ARTIFACTS).union(FIXED_TOOL_NAMES)
                assert len(first) == len(second) == 130
                assert tool_digest(first) == tool_digest(second)
                assert names.isdisjoint(REMOVED)
                assert not any(
                    token in name.lower()
                    for name in names
                    for token in ("quarantine", "sinkhole", "network_block", "network_restore")
                )
                evidence["inventory"] = {
                    "count_first": len(first),
                    "count_second": len(second),
                    "digest_first": tool_digest(first),
                    "digest_second": tool_digest(second),
                    "dynamic_count": len(names.intersection(APPROVED_WINDOWS_ARTIFACTS)),
                    "fixed_names": sorted(names.intersection(FIXED_TOOL_NAMES)),
                    "removed_absent": sorted(REMOVED),
                }

                calls = [
                    ("vql_plain", "run_vql", {"query": "SELECT 42 AS Answer FROM scope()"}),
                    ("vql_empty", "run_vql", {"query": "SELECT * FROM range(end=1) WHERE _value = 99"}),
                    ("vql_251", "run_vql", {"query": "SELECT * FROM range(end=251)"}),
                    ("vql_too_large", "run_vql", {"query": "LET X <= SELECT 'xxxxxxxxxx' AS S FROM range(end=30000)\nSELECT join(array=X.S, sep='') AS Blob FROM scope()"}),
                    ("vql_parse_error", "run_vql", {"query": "SELECT FROM broken("}),
                    ("unknown_flow", "get_flow_status", {"flow_id": "F.__mcp_p04_missing__"}),
                    ("unknown_hunt", "get_hunt_status", {"hunt_id": "H.__mcp_p04_missing__"}),
                    ("triage_dependency", "collect_forensic_triage", {}),
                    ("kill_dependency", "kill_process", {"pid": 2147483000}),
                    ("kill_invalid_zero", "kill_process", {"pid": 0}),
                    ("collect_invalid_unc", "collect_file", {"path": "\\\\server\\share\\file.txt"}),
                    ("results_invalid_page", "get_flow_results", {"flow_id": "F.any", "page_size": 0}),
                    ("vql_empty_input", "run_vql", {"query": ""}),
                ]
                for label, name, arguments in calls:
                    evidence["calls"][label] = result_row(
                        await session.call_tool(name, arguments)
                    )

                for removed in sorted(REMOVED):
                    try:
                        result = await session.call_tool(removed, {})
                        evidence["calls"]["removed:" + removed] = result_row(result)
                        assert result.is_error
                    except Exception as exc:
                        evidence["calls"]["removed:" + removed] = {
                            "rejected": True,
                            "exception_type": type(exc).__name__,
                        }

        stderr_file.flush()
        stderr_file.seek(0)
        stderr = stderr_file.read()
        evidence["stderr"] = {
            "length": len(stderr),
            "contains_traceback": "Traceback" in stderr,
            "contains_secret_path": "api_client.yaml" in stderr,
        }
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
        plain = evidence["calls"]["vql_plain"]
        empty = evidence["calls"]["vql_empty"]
        capped = evidence["calls"]["vql_251"]
        large = evidence["calls"]["vql_too_large"]
        parse = evidence["calls"]["vql_parse_error"]
        assert not plain["is_error"] and plain["content_count"] == 0
        assert plain["structured"]["data"] == [{"Answer": 42}]
        assert not empty["is_error"] and empty["structured"]["data"] == []
        assert len(capped["structured"]["data"]) == 250 and capped["structured"]["truncated"]
        assert large["is_error"] and large["structured"]["code"] == "ROW_TOO_LARGE"
        assert parse["is_error"] and parse["structured"]["code"] == "BACKEND_ERROR"
        for label in ("unknown_flow", "unknown_hunt"):
            assert evidence["calls"][label]["structured"]["code"] == "NOT_FOUND"
        for label, artifact in (
            ("triage_dependency", "Windows.Triage.Targets"),
            ("kill_dependency", "Generic.Utils.KillProcess"),
        ):
            row = evidence["calls"][label]
            assert row["is_error"]
            assert row["structured"]["code"] == "DEPENDENCY_MISSING"
            assert row["structured"]["details"] == {"artifact": artifact}
        for label in (
            "kill_invalid_zero",
            "collect_invalid_unc",
            "results_invalid_page",
            "vql_empty_input",
        ):
            row = evidence["calls"][label]
            assert row["is_error"] and row["content_count"] == 0
            assert row["structured"]["code"] == "INVALID_ARGUMENT"
        assert not evidence["stderr"]["contains_traceback"]
        assert not evidence["stderr"]["contains_secret_path"]
        evidence["ok"] = True
    finally:
        stderr_file.close()
        stderr_path.unlink(missing_ok=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(canonical({"ok": evidence.get("ok", False), "out": str(OUT)}))


if __name__ == "__main__":
    asyncio.run(main_async())
