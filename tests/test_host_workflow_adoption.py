"""Host workflow adoption: the real velo_flow execute chain, fake RPC edge.

The production CLI entry (``velo_flow.execute`` with its own
``session_factory`` seam) runs unmodified against a stand-in MCP session
that answers with real SDK ``Tool``/``CallToolResult`` objects built from the
production result models. Only the transport is simulated: no network, no
VM, no real backend. This covers the documented AI daily path — one CLI run
waits WAITING->FINISHED, pages results, lists files, persists the raw
evidence and prints one bounded stdout summary — and proves ERROR and
unfinished-budget outcomes never claim complete.
"""

import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from mcp.types import CallToolResult, ListToolsResult, Tool

from velo_flow.__main__ import EXIT_COMPLETE, EXIT_INCOMPLETE, execute
from velociraptor_mcp_core import (
    DataResult,
    FlowFileEntry,
    FlowFileListResult,
    FlowStatusResult,
    Pagination,
    success_result,
)

FLOW_ID = "F.ADOPTION.OFFLINE"
PAGE_SIZE = 250


def _tool(name, description, input_schema, output_model):
    return Tool(
        name=name,
        description=description,
        inputSchema=input_schema,
        outputSchema=output_model.model_json_schema(),
    )


def flow_session_tools():
    """The three fixed tools with real production output schemas."""
    return [
        _tool(
            "get_flow_status", "read one flow's state",
            {"type": "object",
             "properties": {"flow_id": {"type": "string", "minLength": 1}},
             "required": ["flow_id"], "additionalProperties": False},
            FlowStatusResult),
        _tool(
            "get_flow_results", "page one result source",
            {"type": "object",
             "properties": {
                 "flow_id": {"type": "string", "minLength": 1},
                 "source": {"type": ["string", "null"]},
                 "cursor": {"type": ["string", "null"]},
                 "page_size": {"type": "integer", "minimum": 1, "maximum": 250},
             },
             "required": ["flow_id", "source", "cursor", "page_size"],
             "additionalProperties": False},
            DataResult),
        _tool(
            "list_flow_files", "list uploaded file ids",
            {"type": "object",
             "properties": {"flow_id": {"type": "string", "minLength": 1}},
             "required": ["flow_id"], "additionalProperties": False},
            FlowFileListResult),
    ]


def _status_result(state):
    return success_result(FlowStatusResult(
        operation="get_flow_status", status="success", warnings=[],
        flow_id=FLOW_ID, state=state, status_message="fixture",
        artifacts=["Windows.System.Pslist"], artifacts_with_results=[],
        create_time=1, start_time=1, active_time=1, total_collected_rows=4,
        total_logs=0, total_uploaded_files=2, total_uploaded_bytes=128,
    ))


def _page_result(cursor_echo, data, *, truncated, next_cursor):
    return success_result(DataResult(
        operation="get_flow_results", status="success", warnings=[],
        data=data,
        pagination=Pagination(cursor=cursor_echo, next_cursor=next_cursor,
                              page_size=PAGE_SIZE, returned=len(data),
                              truncated=truncated),
    ))


def _files_result():
    return success_result(FlowFileListResult(
        operation="list_flow_files", status="success", warnings=[],
        data=[
            FlowFileEntry(file_id="upload-1", original_path="C:\\a.bin",
                          file_size=64, uploaded_size=64, accessor="file"),
            FlowFileEntry(file_id="upload-2", original_path="C:\\b.bin",
                          file_size=64, uploaded_size=64, accessor="file"),
        ],
        truncated=False,
    ))


PAGE_ONE = [{"row": 1}, {"row": 2}]
PAGE_TWO = [{"row": 3}, {"row": 4}]


class FakeRpcSession:
    """Answers through real CallToolResult models; counts every call."""

    def __init__(self, *, states=("WAITING", "FINISHED")):
        self.states = list(states)
        self.tools = flow_session_tools()
        self.call_counts = {"get_flow_status": 0, "get_flow_results": 0,
                            "list_flow_files": 0}
        self.list_tools_calls = 0
        self.requests = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return None

    async def list_tools(self, params=None):
        self.list_tools_calls += 1
        return ListToolsResult(tools=self.tools, nextCursor=None)

    async def call_tool(self, name, arguments, **kwargs):
        self.call_counts[name] += 1
        self.requests.append((name, dict(arguments)))
        if name == "get_flow_status":
            index = min(self.call_counts[name] - 1, len(self.states) - 1)
            return _status_result(self.states[index])
        if name == "list_flow_files":
            return _files_result()
        if name == "get_flow_results":
            cursor = arguments.get("cursor")
            if cursor is None:
                return _page_result("v1:0", PAGE_ONE, truncated=True,
                                    next_cursor="v1:250")
            return _page_result(cursor, PAGE_TWO, truncated=False,
                                next_cursor=None)
        raise AssertionError(f"unexpected tool call: {name}")


class AdoptionFixture:
    """Non-sensitive offline profile + spec files under one temp root."""

    def __init__(self, *, budget_overrides=None):
        self.root = Path(tempfile.mkdtemp(prefix="velo-adoption-"))
        profile_dir = self.root / "profile"
        profile_dir.mkdir(mode=0o700)
        token_path = profile_dir / "token"
        token_path.write_text("offline-fixture-token", encoding="ascii")
        os.chmod(token_path, 0o600)
        self.profile_path = profile_dir / "connection.json"
        self.profile_path.write_text(json.dumps({
            "version": "velo.transfer.connection.v1",
            "velo": {"endpoint": "http://127.0.0.1:9/mcp",
                     "token_file": str(token_path)},
            "windows": None,
            "deployment": {
                "python_path": "C:\\Tools\\python\\python.exe",
                "project_root": "C:\\Tools\\mcp-velociraptor",
                "policy_path": "C:\\Protected\\transfer-policy.json",
                "guest_work_root": "C:\\TransferWork",
            },
        }), encoding="utf-8")
        os.chmod(self.profile_path, 0o600)

        budget = {
            "deadline_seconds": 30,
            "request_timeout_seconds": 5,
            "max_status_calls": 8,
            "max_pages": 100,
            "max_result_bytes": 1048576,
            # The coordinator reserves a 1 MiB log slot before every call,
            # so the smallest legal budget would stop right after call one.
            "max_log_bytes": 8388608,
        }
        budget.update(budget_overrides or {})
        self.output_dir = self.root / "run-output"
        self.spec_path = self.root / "request.json"
        self.spec_path.write_text(json.dumps({
            "schema": "velo.flow.request.v1",
            "flow_id": FLOW_ID,
            "connection_profile": str(self.profile_path),
            "output_dir": str(self.output_dir),
            "source": None,
            "page_size": PAGE_SIZE,
            "budget": budget,
        }), encoding="utf-8")

    def run(self, session):
        stdout = io.StringIO()
        import asyncio
        with redirect_stdout(stdout):
            exit_code = asyncio.run(execute(
                self.spec_path, session_factory=lambda: session))
        lines = [line for line in stdout.getvalue().splitlines() if line]
        assert len(lines) == 1, lines
        return exit_code, json.loads(lines[0])


class FlowHostAdoptionTests(unittest.TestCase):
    def test_waiting_to_finished_two_pages_complete(self):
        fixture = AdoptionFixture()
        session = FakeRpcSession(states=("WAITING", "FINISHED"))
        exit_code, stdout_summary = fixture.run(session)

        self.assertEqual(exit_code, EXIT_COMPLETE)
        self.assertTrue(stdout_summary["complete"])
        self.assertEqual(stdout_summary["outcome"], "complete")
        self.assertEqual(stdout_summary["reason"], "finished")
        self.assertEqual(stdout_summary["rows_saved"], 4)
        self.assertEqual(stdout_summary["flow_id"], FLOW_ID)
        # Three call layers, counted exactly: one host CLI execute run,
        # one metadata list_tools, five session business calls.
        self.assertEqual(session.list_tools_calls, 1)
        self.assertEqual(stdout_summary["call_counts"], {
            "get_flow_status": 2, "get_flow_results": 2, "list_flow_files": 1})
        self.assertEqual(sum(session.call_counts.values()), 5)
        self.assertLessEqual(
            len(json.dumps(stdout_summary).encode("utf-8")), 4096)

        result = json.loads((fixture.output_dir / "result.json")
                            .read_text(encoding="utf-8"))
        self.assertTrue(result["complete"])
        self.assertEqual(result["last_state"], "FINISHED")
        self.assertEqual(result["rows_fetched"], 4)
        self.assertEqual(result["rows_saved"], 4)
        self.assertEqual(result["files_count"], 2)
        self.assertTrue(result["files_complete"])
        self.assertIsNone(result["next_unread_cursor"])
        self.assertEqual(len(result["sample_rows"]), 4)
        self.assertEqual(result["sample_omitted_count"], 0)

        calls_lines = (fixture.output_dir / "calls.jsonl").read_text(
            encoding="utf-8").splitlines()
        self.assertEqual(len(calls_lines), 5)
        rows_lines = (fixture.output_dir / "rows.jsonl").read_text(
            encoding="utf-8").splitlines()
        self.assertEqual(len(rows_lines), 4)
        contract = json.loads((fixture.output_dir / "contract.json")
                              .read_text(encoding="utf-8"))
        self.assertEqual(sorted(contract),
                         ["get_flow_results", "get_flow_status",
                          "list_flow_files"])
        # The summary's digests are the real files' digests.
        calls_raw = (fixture.output_dir / "calls.jsonl").read_bytes()
        self.assertEqual(result["calls_sha256"],
                         hashlib.sha256(calls_raw).hexdigest())
        self.assertEqual(result["calls_bytes"], len(calls_raw))
        rows_raw = (fixture.output_dir / "rows.jsonl").read_bytes()
        self.assertEqual(result["rows_sha256"],
                         hashlib.sha256(rows_raw).hexdigest())

    def test_flow_error_is_failed_and_never_fetches_results(self):
        fixture = AdoptionFixture()
        session = FakeRpcSession(states=("ERROR",))
        exit_code, stdout_summary = fixture.run(session)

        self.assertEqual(exit_code, EXIT_INCOMPLETE)
        self.assertFalse(stdout_summary["complete"])
        self.assertEqual(stdout_summary["outcome"], "failed")
        self.assertEqual(stdout_summary["reason"], "flow_error")
        self.assertEqual(stdout_summary["rows_saved"], 0)
        self.assertEqual(session.call_counts["get_flow_results"], 0)
        result = json.loads((fixture.output_dir / "result.json")
                            .read_text(encoding="utf-8"))
        self.assertEqual(result["last_state"], "ERROR")
        self.assertFalse(result["complete"])

    def test_page_budget_partial_keeps_unread_cursor(self):
        fixture = AdoptionFixture(budget_overrides={"max_pages": 1})
        session = FakeRpcSession(states=("FINISHED",))
        exit_code, stdout_summary = fixture.run(session)

        self.assertEqual(exit_code, EXIT_INCOMPLETE)
        self.assertFalse(stdout_summary["complete"])
        self.assertEqual(stdout_summary["outcome"], "partial")
        self.assertEqual(stdout_summary["reason"], "page_budget")
        self.assertEqual(stdout_summary["rows_saved"], 2)
        result = json.loads((fixture.output_dir / "result.json")
                            .read_text(encoding="utf-8"))
        self.assertEqual(result["next_unread_cursor"], "v1:250")
        self.assertEqual(result["result_pages_fetched"], 1)
        self.assertEqual(result["result_pages_saved"], 1)
        self.assertFalse(result["complete"])


if __name__ == "__main__":
    unittest.main()
