"""One bounded flow-host run against an already connected ClientSession.

Business scope is strictly read-only over three existing fixed tools:
``get_flow_status``, ``get_flow_results`` and ``list_flow_files``. The
coordinator waits for FINISHED with a bounded backoff, pages one result source
to its terminal cursor, lists files once, and streams every raw response and
row into an exclusive output directory. It never retries a call, never starts
or cancels collections, and never fabricates success: FINISHED + terminal page
fully persisted + complete file list is the only path to ``complete=True``.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator
from mcp.types import PaginatedRequestParams

from .spec import SpecData, open_exclusive

REQUIRED_TOOLS = ("get_flow_status", "get_flow_results", "list_flow_files")
STATUS_BACKOFF = (1.0, 2.0, 4.0, 8.0, 10.0)
LIST_TOOLS_MAX_PAGES = 16
LOG_RECORD_LIMIT = 1048576
LOG_SLOT_RESERVE = 1048576
RESULT_JSON_LIMIT = 16384
SAMPLE_ROW_LIMIT = 4096
STDOUT_LIMIT = 4096
SUMMARY_CODE_LIMIT = 128
RESULT_SCHEMA = "velo.flow.result.v1"


class RunStop(Exception):
    """Structured end of the run; outcome is partial or failed, never complete."""

    def __init__(self, outcome: str, reason: str):
        self.outcome = outcome
        self.reason = reason
        super().__init__(reason)


@dataclass
class RunResult:
    outcome: str
    reason: str
    complete: bool
    error_code: str | None = None
    secondary_code: str | None = None


class OutputSink:
    """Exclusive append-only writer for one run directory (mode xb everywhere)."""

    def __init__(self, directory: Path):
        self.dir = directory
        self.contract_path = directory / "contract.json"
        self.calls_path = directory / "calls.jsonl"
        self.rows_path = directory / "rows.jsonl"
        self.result_path = directory / "result.json"
        self.calls_bytes = 0
        self.rows_bytes = 0
        self._calls_sha = hashlib.sha256()
        self._rows_sha = hashlib.sha256()
        self.calls_complete = True
        self._calls = open_exclusive(self.calls_path)
        self._rows = open_exclusive(self.rows_path)

    def write_contract(self, contract: dict) -> None:
        try:
            with open_exclusive(self.contract_path) as fh:
                fh.write(json.dumps(contract, ensure_ascii=False, indent=1).encode("utf-8"))
        except OSError:
            raise RunStop("failed", "io_error") from None

    def append_call(self, name: str, args: dict, response) -> None:
        record = {"name": name, "args": args,
                  "response": response.model_dump(mode="json", by_alias=True)}
        raw = (json.dumps(record, ensure_ascii=False, separators=(",", ":"),
                          allow_nan=False) + "\n").encode("utf-8")
        oversized = len(raw) > LOG_RECORD_LIMIT
        if oversized:
            # Keep a bounded marker stating the raw completeness is unknown,
            # then stop the whole run: no further business call may happen.
            marker = {"name": name, "args": args, "response_omitted": True,
                      "raw_completeness": "unknown", "reason": "raw_record_too_large"}
            raw = (json.dumps(marker, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            self._calls.write(raw)
        except OSError:
            raise RunStop("failed", "io_error") from None
        self.calls_bytes += len(raw)
        self._calls_sha.update(raw)
        if oversized:
            self.calls_complete = False
            raise RunStop("failed", "raw_record_too_large")

    def append_rows_page(self, lines: list[bytes]) -> None:
        try:
            for line in lines:
                self._rows.write(line)
                self.rows_bytes += len(line)
                self._rows_sha.update(line)
            self._rows.flush()
        except OSError:
            raise RunStop("failed", "io_error") from None

    def finalize(self) -> dict:
        """Close streams and return path/size/sha facts for the summary."""
        try:
            self._calls.close()
            self._rows.close()
        except OSError:
            raise RunStop("failed", "io_error") from None
        return {
            "contract_path": str(self.contract_path),
            "calls_path": str(self.calls_path),
            "calls_bytes": self.calls_bytes,
            "calls_sha256": self._calls_sha.hexdigest(),
            "rows_path": str(self.rows_path),
            "rows_bytes": self.rows_bytes,
            "rows_sha256": self._rows_sha.hexdigest(),
        }


class FlowHostCoordinator:
    """Drive one flow collection run; pure asyncio core over a narrow session."""

    def __init__(self, spec: SpecData, sink: OutputSink):
        self.spec = spec
        self.sink = sink
        self.call_counts = {name: 0 for name in REQUIRED_TOOLS}
        self.validators: dict[str, tuple[Draft202012Validator, Draft202012Validator]] = {}
        self.warnings_count = 0
        self.pages_fetched = 0
        self.pages_saved = 0
        self.rows_fetched = 0
        self.rows_saved = 0
        self.next_unread_cursor: str | None = None
        self.files_count: int | None = None
        self.files_complete: bool | None = None
        self.sample_rows: list[dict] = []
        self.last_state: str | None = None
        self._deadline = 0.0
        self._downgrade: tuple[str, str] | None = None

    # ---------- shared helpers ----------

    def _remaining(self) -> float:
        return self._deadline - time.monotonic()

    async def _bounded(self, starter):
        """Await one SDK call under exactly min(remaining, request_timeout).

        No grace is added: a result arriving after the binding limit is a
        timeout, never a late success. Classification compares the original
        binding limit that was in force when the call started.
        """
        before = self._remaining()
        if before <= 0:
            raise RunStop("partial", "deadline_exceeded")
        timeout = min(before, self.spec.request_timeout_seconds)
        deadline_bound = before <= self.spec.request_timeout_seconds
        try:
            return await asyncio.wait_for(starter(), timeout=timeout)
        except asyncio.TimeoutError:
            if deadline_bound:
                raise RunStop("partial", "deadline_exceeded") from None
            raise RunStop("failed", "request_timeout") from None
        except RunStop:
            raise
        except asyncio.CancelledError:
            raise
        except Exception:
            raise RunStop("failed", "call_failed") from None

    async def _call(self, session, name: str, args: dict) -> dict:
        if self.sink.calls_bytes + LOG_SLOT_RESERVE > self.spec.max_log_bytes:
            raise RunStop("partial", "log_budget")
        input_validator, _ = self.validators[name]
        if not input_validator.is_valid(args):
            raise RunStop("failed", "invalid_arguments")
        self.call_counts[name] += 1
        result = await self._bounded(lambda: session.call_tool(
            name, args, read_timeout_seconds=min(self._remaining(),
                                                 self.spec.request_timeout_seconds)))
        self.sink.append_call(name, args, result)
        return self._checked(result, name)

    def _checked(self, result, name: str) -> dict:
        if result.is_error:
            payload = result.structured_content
            code = payload.get("code") if isinstance(payload, dict) else None
            if (isinstance(code, str) and code and
                    len(code.encode("utf-8")) <= SUMMARY_CODE_LIMIT):
                raise RunStop("failed", code)
            # Overlong or missing codes stay stable and bounded here; the full
            # raw value is preserved in the saved CallToolResult.
            raise RunStop("failed", "tool_error")
        payload = result.structured_content
        if not isinstance(payload, dict):
            raise RunStop("failed", "protocol_error")
        if payload.get("operation") != name or payload.get("status") != "success":
            raise RunStop("failed", "protocol_error")
        _, output_validator = self.validators[name]
        if not output_validator.is_valid(payload):
            raise RunStop("failed", "schema_mismatch")
        return payload

    # ---------- phases ----------

    async def _load_contract(self, session) -> None:
        """List tool metadata through the real SDK pagination protocol.

        mcp 2.1.1: ``list_tools(*, params: PaginatedRequestParams | None = None)``
        with continuation cursors carried in ``params.cursor`` and the next page
        token read from ``ListToolsResult.next_cursor``.
        """
        found: dict[str, object] = {}
        cursor = None
        seen_cursors = set()
        for _ in range(LIST_TOOLS_MAX_PAGES):
            if cursor is None:
                starter = lambda: session.list_tools()  # noqa: E731
            else:
                starter = lambda cursor=cursor: session.list_tools(
                    params=PaginatedRequestParams(cursor=cursor))
            response = await self._bounded(starter)
            for tool in response.tools:
                if tool.name in found:
                    raise RunStop("failed", "duplicate_tool")
                found[tool.name] = tool
            if all(name in found for name in REQUIRED_TOOLS):
                break
            cursor = response.next_cursor
            if cursor is None:
                break
            if cursor in seen_cursors:
                raise RunStop("failed", "protocol_error")
            seen_cursors.add(cursor)
        else:
            raise RunStop("failed", "tools_missing")
        missing = [name for name in REQUIRED_TOOLS if name not in found]
        if missing:
            raise RunStop("failed", "tools_missing")
        contract = {}
        for name in REQUIRED_TOOLS:
            tool = found[name]
            try:
                Draft202012Validator.check_schema(tool.input_schema)
                Draft202012Validator.check_schema(tool.output_schema)
            except Exception:
                raise RunStop("failed", "schema_invalid") from None
            contract[name] = {"inputSchema": tool.input_schema,
                              "outputSchema": tool.output_schema}
            self.validators[name] = (Draft202012Validator(tool.input_schema),
                                     Draft202012Validator(tool.output_schema))
        self.sink.write_contract(contract)

    async def _wait_finished(self, session) -> None:
        calls = 0
        backoff_index = 0
        while True:
            if calls >= self.spec.max_status_calls:
                raise RunStop("partial", "status_budget")
            payload = await self._call(session, "get_flow_status",
                                       {"flow_id": self.spec.flow_id})
            state = payload["state"]
            self.last_state = state
            self.warnings_count += len(payload.get("warnings", []))
            if payload["flow_id"] != self.spec.flow_id:
                raise RunStop("failed", "protocol_error")
            if state == "FINISHED":
                return
            if state == "ERROR":
                raise RunStop("failed", "flow_error")
            calls += 1
            delay = min(STATUS_BACKOFF[min(backoff_index, len(STATUS_BACKOFF) - 1)],
                        self._remaining())
            if delay <= 0:
                raise RunStop("partial", "deadline_exceeded")
            await asyncio.sleep(delay)
            backoff_index += 1

    async def _collect_pages(self, session) -> None:
        cursor = None
        visited = set()
        for page_index in range(self.spec.max_pages):
            args = {"flow_id": self.spec.flow_id, "source": self.spec.source,
                    "cursor": cursor, "page_size": self.spec.page_size}
            payload = await self._call(session, "get_flow_results", args)
            pagination = payload["pagination"]
            data = payload["data"]
            echo = pagination["cursor"]
            expected = "v1:0" if cursor is None else cursor
            if echo != expected:
                raise RunStop("failed", "protocol_error")
            if pagination["returned"] != len(data) or pagination["page_size"] != self.spec.page_size:
                raise RunStop("failed", "protocol_error")
            truncated = pagination["truncated"]
            nxt = pagination["next_cursor"]
            if truncated:
                if not isinstance(nxt, str) or not nxt or not data:
                    raise RunStop("failed", "protocol_error")
            elif nxt is not None:
                raise RunStop("failed", "protocol_error")
            visited.add(echo)
            self.pages_fetched += 1
            self.rows_fetched += len(data)
            self.warnings_count += len(payload.get("warnings", []))
            try:
                lines = [(json.dumps(row, ensure_ascii=False, separators=(",", ":"),
                                     allow_nan=False) + "\n").encode("utf-8") for row in data]
            except (TypeError, ValueError):
                raise RunStop("failed", "protocol_error") from None
            page_bytes = sum(len(line) for line in lines)
            if self.sink.rows_bytes + page_bytes > self.spec.max_result_bytes:
                self.next_unread_cursor = echo
                raise RunStop("partial", "result_budget")
            self.sink.append_rows_page(lines)
            self.pages_saved += 1
            self.rows_saved += len(data)
            self._extend_sample(data)
            if not truncated:
                self.next_unread_cursor = None
                return
            if nxt in visited:
                raise RunStop("failed", "protocol_error")
            if page_index + 1 >= self.spec.max_pages:
                self.next_unread_cursor = nxt
                raise RunStop("partial", "page_budget")
            cursor = nxt

    async def _list_files(self, session) -> None:
        payload = await self._call(session, "list_flow_files",
                                   {"flow_id": self.spec.flow_id})
        self.warnings_count += len(payload.get("warnings", []))
        self.files_count = len(payload["data"])
        self.files_complete = not payload["truncated"]
        if payload["truncated"]:
            self._downgrade = ("partial", "filelist_truncated")

    def _extend_sample(self, rows: list[dict]) -> None:
        for row in rows:
            if len(self.sample_rows) >= self.spec.sample_rows:
                return
            projected = (row if not self.spec.sample_fields else
                         {name: row[name] for name in self.spec.sample_fields if name in row})
            try:
                line = json.dumps(projected, ensure_ascii=False, separators=(",", ":"),
                                  allow_nan=False)
            except (TypeError, ValueError):
                continue
            if len(line.encode("utf-8")) > SAMPLE_ROW_LIMIT:
                continue
            self.sample_rows.append(projected)

    # ---------- entry ----------

    async def run(self, session, *, deadline_monotonic: float | None = None) -> RunResult:
        self._deadline = (deadline_monotonic if deadline_monotonic is not None
                          else time.monotonic() + self.spec.deadline_seconds)
        try:
            await self._load_contract(session)
            await self._wait_finished(session)
            await self._collect_pages(session)
            await self._list_files(session)
        except RunStop as stop:
            return RunResult(stop.outcome, stop.reason, False, stop.reason)
        outcome, reason = self._downgrade or ("complete", "finished")
        return RunResult(outcome, reason, outcome == "complete")

    def build_summary(self, result: RunResult, file_facts: dict) -> dict:
        """Assemble the bounded summary or fail closed with a stable code.

        The omission count is always rows_saved minus the final sample length,
        so rows kept out by the quota, the per-row byte limit or the total
        summary limit are all counted exactly once. If the summary still
        exceeds the limit with no sample left, it is rejected — never returned
        oversized.
        """
        summary = {
            "schema": RESULT_SCHEMA,
            "outcome": result.outcome,
            "reason": result.reason,
            "flow_id": self.spec.flow_id,
            "source": self.spec.source,
            "last_state": self.last_state,
            "result_pages_fetched": self.pages_fetched,
            "result_pages_saved": self.pages_saved,
            "rows_fetched": self.rows_fetched,
            "rows_saved": self.rows_saved,
            "next_unread_cursor": self.next_unread_cursor,
            "files_count": self.files_count,
            "files_complete": self.files_complete,
            "call_counts": dict(self.call_counts),
            "complete": result.complete,
            "sample_rows": list(self.sample_rows),
            "warnings_count": self.warnings_count,
            "warnings_source": str(self.sink.calls_path),
            "calls_complete": self.sink.calls_complete,
            "error": {"code": result.error_code, "secondary_code": result.secondary_code}
            if result.error_code or result.secondary_code else None,
        }
        summary.update(file_facts)
        while True:
            summary["sample_omitted_count"] = self.rows_saved - len(summary["sample_rows"])
            encoded = len(json.dumps(summary, ensure_ascii=False, separators=(",", ":"),
                                     allow_nan=False).encode("utf-8"))
            if encoded <= RESULT_JSON_LIMIT:
                return summary
            if not summary["sample_rows"]:
                raise RunStop("failed", "summary_overflow")
            summary["sample_rows"].pop()

    def stdout_summary(self, summary: dict, exit_code: int, result_path: str | None) -> dict:
        payload = {
            "schema": summary["schema"],
            "outcome": summary["outcome"],
            "reason": summary["reason"],
            "flow_id": summary["flow_id"],
            "rows_saved": summary["rows_saved"],
            "complete": summary["complete"],
            "result_path": result_path,
            "call_counts": summary["call_counts"],
            "exit_code": exit_code,
        }
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"),
                             allow_nan=False).encode("utf-8")
        if len(encoded) > STDOUT_LIMIT:
            raise RunStop("failed", "stdout_overflow")
        return payload
