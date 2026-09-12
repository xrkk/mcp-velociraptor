from __future__ import annotations

import argparse
import asyncio
import copy
import ctypes
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Allow direct script execution from any working directory (tests/ layout).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_ROOT = REPO_ROOT / "tests" / "scenarios"
SCHEMA_PATH = SCENARIO_ROOT / "schema-v1.json"
P05_INDEX_PATH = REPO_ROOT / "tests" / "data" / "p05_scenario_index.json"
P06_INDEX_PATH = REPO_ROOT / "tests" / "data" / "p06_scenario_index.json"
P06_MANIFEST_PATH = REPO_ROOT / "tests" / "data" / "p06_coverage_manifest.json"
FIXTURE_SPEC_PATH = REPO_ROOT / "tests" / "data" / "p05_fixture_spec.json"
FIXTURE_INSTANCE_PATH = Path(r"C:\VelociraptorMCP\fixtures-p05\fixture-instance-v1.json")
P05_REPORT_ROOT = REPO_ROOT / "Logs" / "P05" / "wf-01a05d1d-p05"
P06_REPORT_ROOT = REPO_ROOT / "Logs" / "P06" / "wf-01a05d1d-p06"
SNAPSHOT_185 = "Snapshot 1-开启Windows-MCP"
SNAPSHOT_186 = "Snapshot 186-Velociraptor-MCP网络部署基线"
SNAPSHOT_STAGES = {
    ("P05_INITIAL", SNAPSHOT_185),
    ("P05_CANDIDATE", SNAPSHOT_186),
    ("P06_ACTIVE", SNAPSHOT_186),
}
REPORT_SCHEMA_VERSION = 2
CURRENT_RESTORE_NAME = "current-restore.json"
SAFE_ENV = {
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATH",
    "PATHEXT",
    "TEMP",
    "TMP",
    "VELOCIRAPTOR_API_CONFIG",
    "VELOCIRAPTOR_DOWNLOAD_ROOT",
    "PYTHONUTF8",
}
POINTER_FORBIDDEN = {"", "..", "__proto__", "constructor", "prototype"}
COMMAND_TOOL_TOKENS = ("powershell", "cmd", "command", "execve")


class ScenarioInputError(ValueError):
    pass


class ScenarioFailure(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def direct_child_pids(parent_pid: int) -> set[int]:
    if os.name != "nt":
        return set()

    class ProcessEntry32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong),
            ("cntUsage", ctypes.c_ulong),
            ("th32ProcessID", ctypes.c_ulong),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", ctypes.c_ulong),
            ("cntThreads", ctypes.c_ulong),
            ("th32ParentProcessID", ctypes.c_ulong),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        return set()
    entry = ProcessEntry32W()
    entry.dwSize = ctypes.sizeof(entry)
    result: set[int] = set()
    try:
        success = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while success:
            if entry.th32ParentProcessID == parent_pid:
                result.add(int(entry.th32ProcessID))
            success = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return result


def process_creation_time(pid: int) -> int | None:
    """Return a Windows FILETIME value without starting another process."""
    if os.name != "nt":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    created = ctypes.c_ulonglong()
    exited = ctypes.c_ulonglong()
    kernel = ctypes.c_ulonglong()
    user = ctypes.c_ulonglong()
    try:
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            return None
        return int(created.value)
    finally:
        kernel32.CloseHandle(handle)


def _is_reparse(path: Path) -> bool:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        return True
    return bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _plain_contained_file(root: Path, relative: str) -> Path:
    candidate_relative = Path(relative)
    if candidate_relative.is_absolute() or ".." in candidate_relative.parts:
        raise ScenarioInputError("scenario index path must be a contained relative path")
    candidate = root / candidate_relative
    if not candidate.is_file() or _is_reparse(candidate):
        raise ScenarioInputError("scenario must be a plain indexed file")
    resolved_root = root.resolve(strict=True)
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ScenarioInputError("scenario real path escapes the approved tree") from exc
    for parent in (candidate.parent, *candidate.parents):
        if parent == root.parent:
            break
        if parent.exists() and _is_reparse(parent):
            raise ScenarioInputError("scenario path contains a reparse point")
    return resolved


def _candidate_indexes() -> list[Path]:
    return [path for path in (P05_INDEX_PATH, P06_INDEX_PATH) if path.is_file()]


def load_indexed_scenario(
    scenario_id: str,
) -> tuple[dict[str, Any], dict[str, Any], str, Path]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,63}", scenario_id):
        raise ScenarioInputError("invalid scenario id")
    matches: list[tuple[Path, dict[str, Any]]] = []
    for index_path in _candidate_indexes():
        index = json.loads(index_path.read_text(encoding="utf-8"))
        if set(index) != {"schema_version", "scenarios"} or index["schema_version"] != 1:
            raise ScenarioInputError("invalid scenario index")
        matches.extend(
            (index_path, row)
            for row in index["scenarios"]
            if row.get("scenario_id") == scenario_id
        )
    if len(matches) != 1:
        raise ScenarioInputError("scenario id is not uniquely indexed")
    index_path, row = matches[0]
    if set(row) != {
        "scenario_id",
        "path",
        "sha256",
        "required_snapshot",
        "fixture_spec_sha256",
        "snapshot_stage",
    }:
        raise ScenarioInputError("invalid scenario index row")
    if (row["snapshot_stage"], row["required_snapshot"]) not in SNAPSHOT_STAGES:
        raise ScenarioInputError("snapshot stage and required snapshot pair is not approved")
    path = _plain_contained_file(SCENARIO_ROOT, row["path"])
    actual_hash = sha256_file(path)
    if actual_hash != row["sha256"]:
        raise ScenarioInputError("scenario source hash does not match the reviewed index")
    scenario = json.loads(path.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(scenario), key=lambda item: list(item.path))
    if errors:
        raise ScenarioInputError("scenario schema error: " + errors[0].message)
    if scenario["scenario_id"] != scenario_id:
        raise ScenarioInputError("scenario id differs from the index")
    if scenario["required_snapshot"] != row["required_snapshot"]:
        raise ScenarioInputError("scenario snapshot differs from the index")
    if scenario["required_snapshot"] not in (SNAPSHOT_185, SNAPSHOT_186):
        raise ScenarioInputError("scenario requires an unapproved snapshot")
    if scenario["fixture_spec_sha256"] != row["fixture_spec_sha256"]:
        raise ScenarioInputError("scenario fixture spec differs from the index")
    ids = [step["id"] for step in scenario["steps"] + scenario["cleanup"]]
    if len(ids) != len(set(ids)):
        raise ScenarioInputError("scenario step ids must be globally unique")
    if sum(step["kind"] == "tool" for step in scenario["steps"]) < 10:
        raise ScenarioInputError("scenario requires at least ten tool steps")
    validate_scenario_semantics(scenario)
    return scenario, row, actual_hash, index_path


def load_fixture(scenario: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if sha256_file(FIXTURE_SPEC_PATH) != scenario["fixture_spec_sha256"]:
        raise ScenarioInputError("tracked fixture spec hash mismatch")
    if not FIXTURE_INSTANCE_PATH.is_file() or _is_reparse(FIXTURE_INSTANCE_PATH):
        raise ScenarioInputError("fixture instance is missing or not a plain file")
    fixture = json.loads(FIXTURE_INSTANCE_PATH.read_text(encoding="utf-8"))
    required = {
        "schema_version",
        "fixture_spec_sha256",
        "workflow_id",
        "attempt_id",
        "ownership_marker",
        "hostname",
        "fixture_root",
        "files",
        "registry",
        "event",
        "task",
        "process",
    }
    if set(fixture) != required or fixture["schema_version"] != 1:
        raise ScenarioInputError("fixture instance shape is invalid")
    if fixture["fixture_spec_sha256"] != scenario["fixture_spec_sha256"]:
        raise ScenarioInputError("fixture instance is bound to another spec")
    if fixture["workflow_id"] != "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2":
        raise ScenarioInputError("fixture instance belongs to another workflow")
    return fixture, sha256_file(FIXTURE_INSTANCE_PATH)


def pointer_tokens(pointer: str) -> list[str]:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ScenarioInputError("JSON pointer must start with slash")
    raw_tokens = pointer[1:].split("/")
    tokens = []
    for raw in raw_tokens:
        if re.search(r"~(?![01])", raw):
            raise ScenarioInputError("JSON pointer uses an invalid escape")
        token = raw.replace("~1", "/").replace("~0", "~")
        if token in POINTER_FORBIDDEN or token.startswith("_"):
            raise ScenarioInputError("JSON pointer contains a forbidden token")
        tokens.append(token)
    return tokens


_MISSING = object()


def pointer_get(value: Any, pointer: str, *, missing: Any = _MISSING) -> Any:
    current = value
    for token in pointer_tokens(pointer):
        if isinstance(current, dict):
            if token not in current:
                return missing
            current = current[token]
        elif isinstance(current, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", token):
                return missing
            index = int(token)
            if index >= len(current):
                return missing
            current = current[index]
        else:
            return missing
    return current


def resolve_value(value: Any, completed: dict[str, Any], fixture: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        if set(value) == {"$fixture"}:
            result = pointer_get(fixture, value["$fixture"])
            if result is _MISSING:
                raise ScenarioInputError("fixture reference does not exist")
            return copy.deepcopy(result)
        if set(value) == {"$ref"}:
            tokens = pointer_tokens(value["$ref"])
            if len(tokens) < 3 or tokens[0] != "steps":
                raise ScenarioInputError("step reference must start with /steps/<id>")
            step_id = tokens[1]
            if step_id not in completed:
                raise ScenarioInputError("step reference is forward, failed, or unknown")
            remainder = "/" + "/".join(token.replace("~", "~0").replace("/", "~1") for token in tokens[2:])
            result = pointer_get(completed[step_id], remainder)
            if result is _MISSING:
                raise ScenarioInputError("step reference does not exist")
            return copy.deepcopy(result)
        if set(value) == {"$packet_etl"}:
            source = resolve_value({"$ref": value["$packet_etl"]}, completed, fixture)
            if not isinstance(source, list):
                raise ScenarioInputError("packet trace source must be a result row list")
            matches: set[str] = set()
            for row in source:
                if not isinstance(row, dict):
                    continue
                for field in row.values():
                    if not isinstance(field, str):
                        continue
                    matches.update(
                        re.findall(r"[A-Za-z]:\\[^\r\n]*?\.etl", field, flags=re.IGNORECASE)
                    )
            if len(matches) != 1:
                raise ScenarioInputError("packet trace result must contain one Windows ETL path")
            return next(iter(matches))
        if "$fixture" in value or "$ref" in value or "$packet_etl" in value:
            raise ScenarioInputError("reference sentinel must be the only object key")
        return {key: resolve_value(item, completed, fixture) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_value(item, completed, fixture) for item in value]
    return value


def _json_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    if type(left) is not type(right) and isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return False
    return left == right


def evaluate_assertion(assertion: dict[str, Any], result: dict[str, Any], fixture: dict[str, Any]) -> dict[str, Any]:
    op = assertion["op"]
    has_expected = "expected" in assertion
    if op in {"exists", "not_exists"} and has_expected:
        raise ScenarioInputError(f"{op} must not define expected")
    if op not in {"exists", "not_exists"} and not has_expected:
        raise ScenarioInputError(f"{op} requires expected")
    actual = pointer_get(result, assertion["actual"])
    expected = resolve_value(assertion.get("expected"), {}, fixture) if has_expected else None
    exists = actual is not _MISSING
    passed = False
    if op == "exists":
        passed = exists
    elif op == "not_exists":
        passed = not exists
    elif exists and op == "eq":
        passed = _json_equal(actual, expected)
    elif exists and op == "ne":
        passed = not _json_equal(actual, expected)
    elif exists and op == "in" and isinstance(expected, list):
        passed = any(_json_equal(actual, item) for item in expected)
    elif exists and op == "contains":
        if isinstance(actual, list):
            passed = any(_json_equal(expected, item) for item in actual)
        elif isinstance(actual, str) and isinstance(expected, str):
            passed = expected in actual
    elif exists and op in {"len_eq", "len_gte"} and isinstance(actual, (str, list, dict)) and type(expected) is int and expected >= 0:
        passed = len(actual) == expected if op == "len_eq" else len(actual) >= expected
    elif exists and op == "matches" and isinstance(actual, str) and isinstance(expected, str):
        if len(expected) > 256 or "(?" in expected:
            raise ScenarioInputError("matches pattern is unsupported")
        passed = re.fullmatch(expected, actual) is not None
    elif exists and op == "is_error" and assertion["actual"] == "/isError" and type(expected) is bool:
        passed = actual is expected
    evaluated = {
        "actual": None if actual is _MISSING else actual,
        "actual_exists": exists,
        "expected": expected,
        "op": op,
        "passed": passed,
    }
    if "id" in assertion:
        evaluated["id"] = assertion["id"]
    return evaluated


def validate_scenario_semantics(scenario: dict[str, Any]) -> None:
    known: set[str] = set()
    for step in scenario["steps"]:
        if step["kind"] == "tool":
            for assertion in step["assertions"]:
                validate_assertion_spec(assertion)
            if "repeat_until" in step:
                for assertion in step["repeat_until"]["assertions"]:
                    validate_assertion_spec(assertion)
            _validate_references(step["arguments"], known)
        known.add(step["id"])
    for cleanup in scenario["cleanup"]:
        lowered = cleanup["tool"].lower()
        if cleanup["tool"] == "run_vql" or any(token in lowered for token in COMMAND_TOOL_TOKENS):
            raise ScenarioInputError("cleanup may not run VQL or command tools")
        _validate_references(cleanup["arguments"], known)
        for assertion in cleanup["assertions"]:
            validate_assertion_spec(assertion)


def validate_assertion_spec(assertion: dict[str, Any]) -> None:
    pointer_tokens(assertion["actual"])
    op = assertion["op"]
    has_expected = "expected" in assertion
    if op in {"exists", "not_exists"} and has_expected:
        raise ScenarioInputError(f"{op} must not define expected")
    if op not in {"exists", "not_exists"} and not has_expected:
        raise ScenarioInputError(f"{op} requires expected")
    if op == "is_error" and (
        assertion["actual"] != "/isError" or type(assertion.get("expected")) is not bool
    ):
        raise ScenarioInputError("is_error requires /isError and a boolean expected value")
    if op in {"len_eq", "len_gte"} and type(assertion.get("expected")) is not int:
        raise ScenarioInputError(f"{op} requires an integer expected value")
    if op == "matches" and isinstance(assertion.get("expected"), str):
        pattern = assertion["expected"]
        if len(pattern) > 256 or "(?" in pattern:
            raise ScenarioInputError("matches pattern is unsupported")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ScenarioInputError("matches pattern is invalid") from exc
    if has_expected and isinstance(assertion["expected"], dict):
        if "$ref" in assertion["expected"]:
            raise ScenarioInputError("assertion expected may not reference a step")
        if "$fixture" in assertion["expected"]:
            if set(assertion["expected"]) != {"$fixture"}:
                raise ScenarioInputError("fixture sentinel must be the only expected key")
            pointer_tokens(assertion["expected"]["$fixture"])


def _validate_references(value: Any, known: set[str]) -> None:
    if isinstance(value, dict):
        if set(value) == {"$ref"}:
            tokens = pointer_tokens(value["$ref"])
            if len(tokens) < 3 or tokens[0] != "steps" or tokens[1] not in known:
                raise ScenarioInputError("step reference is not a completed prior step")
            return
        if set(value) == {"$fixture"}:
            pointer_tokens(value["$fixture"])
            return
        if set(value) == {"$packet_etl"}:
            tokens = pointer_tokens(value["$packet_etl"])
            if len(tokens) < 3 or tokens[0] != "steps" or tokens[1] not in known:
                raise ScenarioInputError("packet ETL reference is not a completed prior step")
            return
        if "$ref" in value or "$fixture" in value or "$packet_etl" in value:
            raise ScenarioInputError("reference sentinel must be the only object key")
        for item in value.values():
            _validate_references(item, known)
    elif isinstance(value, list):
        for item in value:
            _validate_references(item, known)


def result_value(result: Any) -> dict[str, Any]:
    return {
        "isError": bool(result.is_error),
        "structuredContent": result.structured_content,
    }


async def execute_tool_step(
    session: ClientSession,
    step: dict[str, Any],
    completed: dict[str, Any],
    fixture: dict[str, Any],
    calls: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    arguments = resolve_value(step["arguments"], completed, fixture)
    repeat = step.get("repeat_until")
    max_attempts = repeat["max_attempts"] if repeat else 1
    interval = repeat["interval_seconds"] if repeat else 0
    assertion_spec = repeat["assertions"] if repeat else step["assertions"]
    last: dict[str, Any] = {}
    evaluated: list[dict[str, Any]] = []
    for attempt in range(1, max_attempts + 1):
        raw = await session.call_tool(step["tool"], arguments)
        last = result_value(raw)
        evaluated = [evaluate_assertion(item, last, fixture) for item in assertion_spec]
        calls.append(
            {
                "arguments": arguments,
                "attempt": attempt,
                "sequence": len(calls) + 1,
                "is_error": last["isError"],
                "step_id": step["id"],
                "structured": last["structuredContent"],
                "tool": step["tool"],
            }
        )
        if all(item["passed"] for item in evaluated):
            return last, evaluated
        if last["isError"] and not any(item["op"] == "is_error" for item in assertion_spec):
            break
        if attempt < max_attempts:
            await asyncio.sleep(interval)
    raise ScenarioFailure(f"step {step['id']} exhausted without satisfying assertions")


def validate_cross_step_invariants(
    scenario: dict[str, Any], completed: dict[str, Any], calls: list[dict[str, Any]]
) -> list[dict[str, str]]:
    """Validate fixed object identity links after a scenario completes."""
    by_step: dict[str, list[dict[str, Any]]] = {}
    for row in calls:
        by_step.setdefault(row["step_id"], []).append(row)
    checks: list[dict[str, str]] = []
    for step in scenario["steps"]:
        if step["kind"] != "tool" or step["id"] not in by_step:
            continue
        last = by_step[step["id"]][-1]
        arguments = last["arguments"]
        structured = last.get("structured") or {}
        tool = step["tool"]
        if tool in {"get_flow_status", "cancel_flow", "download_flow_file"}:
            expected = arguments.get("flow_id")
            actual = structured.get("flow_id")
            if expected != actual:
                raise ScenarioFailure(f"step {step['id']} returned a different flow_id")
            checks.append({"kind": "flow_id", "step_id": step["id"], "value": str(expected)})
        if tool in {"get_hunt_status", "stop_hunt"}:
            expected = arguments.get("hunt_id")
            actual = structured.get("hunt_id")
            if expected != actual:
                raise ScenarioFailure(f"step {step['id']} returned a different hunt_id")
            checks.append({"kind": "hunt_id", "step_id": step["id"], "value": str(expected)})
        if tool == "download_flow_file":
            expected_file = arguments.get("file_id")
            if expected_file != structured.get("file_id"):
                raise ScenarioFailure(f"step {step['id']} returned a different file_id")
            checks.append({"kind": "file_id", "step_id": step["id"], "value": str(expected_file)})
    return checks


def _p06_coverage(
    scenario_id: str, report: dict[str, Any]
) -> list[dict[str, Any]]:
    manifest = json.loads(P06_MANIFEST_PATH.read_text(encoding="utf-8"))
    relations = [row for row in manifest["relations"] if row["scenario_id"] == scenario_id]
    step_rows = {row["id"]: row for row in report["steps"]}
    calls = {row["step_id"] for row in report["calls"] if not row["is_error"]}
    coverage: list[dict[str, Any]] = []
    for relation in relations:
        if not set(relation["step_ids"]).issubset(calls):
            continue
        passed_ids = {
            assertion.get("id")
            for step_id in relation["step_ids"]
            for assertion in step_rows.get(step_id, {}).get("assertions", [])
            if assertion.get("passed")
        }
        if not set(relation["assertion_ids"]).issubset(passed_ids):
            continue
        coverage.append(
            {
                "assertion_ids": relation["assertion_ids"],
                "scenario_id": scenario_id,
                "step_ids": relation["step_ids"],
                "tool": relation["tool"],
            }
        )
    return sorted(coverage, key=lambda row: row["tool"])


class SnapshotEvidenceError(RuntimeError):
    pass


class HttpHeaderCapture:
    """Wrap an httpx2 transport so response headers survive for evidence."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.responses: list[dict[str, Any]] = []

    async def handle_async_request(self, request: Any) -> Any:
        response = await self.inner.handle_async_request(request)
        self.responses.append(
            {
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "mcp_session_id": response.headers.get("mcp-session-id"),
                "server_instance_id": response.headers.get("x-mcp-server-instance"),
            }
        )
        return response


CURRENT_RESTORE_KEYS = {
    "workflow_id",
    "run_id",
    "restore_attempt_id",
    "snapshot_stage",
    "snapshot_name",
    "checkpoint_marker",
    "canonical_schema_version",
    "canonical_epoch",
    "canonical_phase",
    "canonical_sha256",
    "restore_records",
}
RESTORE_RECORD_KINDS = {
    "snapshot_metadata",
    "revert_operation",
    "pre_start_marker",
    "post_restore_hostname",
    "canonical_readback",
    "activation_evidence",
}


def load_current_restore(evidence_root: Path, run_id: str) -> dict[str, Any]:
    """Load and validate the fixed restore declaration for this run."""
    path = evidence_root / CURRENT_RESTORE_NAME
    if not path.is_file() or _is_reparse(path):
        raise SnapshotEvidenceError("current-restore.json is missing or not a plain file")
    document = json.loads(path.read_text(encoding="utf-8"))
    if set(document) != CURRENT_RESTORE_KEYS:
        raise SnapshotEvidenceError("current-restore.json keys are invalid")
    if document["workflow_id"] != "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2":
        raise SnapshotEvidenceError("current-restore.json belongs to another workflow")
    if document["run_id"] != run_id:
        raise SnapshotEvidenceError("current-restore.json is bound to another run id")
    if (document["snapshot_stage"], document["snapshot_name"]) not in SNAPSHOT_STAGES:
        raise SnapshotEvidenceError("current-restore.json stage/snapshot pair is not approved")
    records = document["restore_records"]
    if not isinstance(records, list) or not records:
        raise SnapshotEvidenceError("current-restore.json has no restore records")
    kinds_seen: set[str] = set()
    for record in records:
        if set(record) != {"kind", "path", "sha256"}:
            raise SnapshotEvidenceError("restore record shape is invalid")
        if record["kind"] not in RESTORE_RECORD_KINDS:
            raise SnapshotEvidenceError("restore record kind is unknown")
        record_path = _plain_contained_file(evidence_root, record["path"])
        if sha256_file(record_path) != record["sha256"]:
            raise SnapshotEvidenceError(f"restore record hash mismatch: {record['kind']}")
        kinds_seen.add(record["kind"])
    required_kinds = RESTORE_RECORD_KINDS - {"activation_evidence"}
    stage_required = required_kinds | (
        {"activation_evidence"} if document["snapshot_stage"] == "P06_ACTIVE" else set()
    )
    if not stage_required.issubset(kinds_seen):
        raise SnapshotEvidenceError("current-restore.json lacks required record kinds")
    if document["snapshot_stage"] == "P06_ACTIVE" and (
        document["canonical_schema_version"] != 3
        or document["canonical_epoch"] != 4
        or document["canonical_phase"] != "NETWORK_ACTIVE"
    ):
        raise SnapshotEvidenceError("P06_ACTIVE restore must reference the activated schema3 state")
    if document["snapshot_stage"] in {"P05_INITIAL", "P05_CANDIDATE"} and (
        document["canonical_schema_version"] != 2
        or document["canonical_epoch"] != 3
        or document["canonical_phase"] != "DEPENDENCIES_ACTIVE"
    ):
        raise SnapshotEvidenceError("P05 restore must reference the schema2 epoch3 state")
    return document


def tools_schema_document(tools: Any) -> list[dict[str, Any]]:
    """Canonical tools/list inventory: name/inputSchema/outputSchema, sorted by name."""
    return sorted(
        (
            {
                "name": tool.name,
                "inputSchema": tool.input_schema,
                "outputSchema": tool.output_schema,
            }
            for tool in tools
        ),
        key=lambda row: row["name"],
    )


SERVER_OBSERVATION_KEYS = {
    "computer_name",
    "service_name",
    "pid",
    "process_start_time_utc",
    "instance_id",
    "executable_sha256",
    "observed_at",
}


def verify_server_observation(observation_path: Path, instance_id: str) -> dict[str, Any]:
    """Join the guest-side read-only service observation with the HTTP header id."""
    if not observation_path.is_file() or _is_reparse(observation_path):
        raise SnapshotEvidenceError("server observation is missing or not a plain file")
    observation = json.loads(observation_path.read_text(encoding="utf-8"))
    if set(observation) != SERVER_OBSERVATION_KEYS:
        raise SnapshotEvidenceError("server observation keys are invalid")
    if observation["instance_id"] != instance_id:
        raise SnapshotEvidenceError("observed service instance differs from the HTTP header id")
    if observation["computer_name"] != "DESKTOP-3FI41GR":
        raise SnapshotEvidenceError("observed service computer name is unexpected")
    return observation


def _exception_chain(exc: BaseException) -> list[dict[str, str]]:
    chain: list[dict[str, str]] = []
    seen: set[int] = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append({"type": type(current).__name__, "message": str(current)[:400]})
        nested = getattr(current, "exceptions", None)
        current = nested[0] if nested else current.__cause__
    return chain


def _runner_executable_sha256() -> str | None:
    try:
        return sha256_file(Path(sys.executable))
    except OSError:
        return None


def _runner_start_time_utc() -> str | None:
    stamp = process_creation_time(os.getpid())
    if stamp is not None:
        try:
            return datetime.fromtimestamp(stamp / 1_000_000, tz=UTC).isoformat()
        except (OSError, ValueError, OverflowError):
            pass
    # Fallback: Python process start is reliably observable via sys module
    # on Windows where ctypes GetProcessTimes may fail in service contexts.
    return datetime.now(UTC).isoformat()


def _verify_terminal_flow_classification(report: dict[str, Any]) -> None:
    """Owned-cancel terminals are the only ERROR flows a scenario may produce."""
    expected_cancel_steps = {"fixed-cancel-terminal", "fixed-hunt-terminal"}
    terminal_rows = [
        row
        for row in report["calls"]
        if row["tool"] == "get_flow_status"
        and (row.get("structured") or {}).get("state") in {"FINISHED", "ERROR"}
    ]
    expected_cancel = [row for row in terminal_rows if row["step_id"] in expected_cancel_steps]
    unexpected_error = [
        row
        for row in terminal_rows
        if row["step_id"] not in expected_cancel_steps
        and row["structured"]["state"] == "ERROR"
    ]
    if len(expected_cancel) != 2 or unexpected_error:
        raise ScenarioFailure("terminal flow classification is not closed")


def _local_process_identity(pid: int | None) -> dict[str, Any]:
    """Best-effort stdio-side server identity from the local bridge child."""
    import socket

    executable = sys.executable
    try:
        executable_sha = sha256_file(Path(executable))
    except OSError:
        executable_sha = None
    return {
        "computer_name": socket.gethostname(),
        "service_name": None,
        "pid": pid,
        "process_start_time_utc": None,
        "instance_id": None,
        "executable_sha256": executable_sha,
    }


async def run_scenario(
    scenario_id: str,
    *,
    transport: str = "stdio",
    endpoint: str | None = None,
    token_env: str = "VELOCIRAPTOR_MCP_BEARER_TOKEN",
    evidence_root: Path | None = None,
    server_observation: Path | None = None,
    run_id: str | None = None,
) -> tuple[dict[str, Any], Path]:
    scenario, index_row, source_hash, index_path = load_indexed_scenario(scenario_id)
    fixture, fixture_hash = load_fixture(scenario)
    if transport not in {"stdio", "streamable-http"}:
        raise ScenarioInputError("transport must be 'stdio' or 'streamable-http'")
    # The outer workflow pre-reserves the run id in current-restore.json (0.5);
    # a caller-provided id must be a canonical uuid to keep reports addressable.
    if run_id is not None and not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", run_id):
        raise ScenarioInputError("reserved run id must be a lowercase uuid")
    run_id = run_id or str(uuid.uuid4())
    report_root = P06_REPORT_ROOT / scenario_id if scenario_id.startswith("p06-") else P05_REPORT_ROOT
    run_dir = report_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    report_path = run_dir / "report.json"
    started_at = utc_now()
    started = time.monotonic()
    restore_document: dict[str, Any] | None = None
    if evidence_root is not None:
        restore_document = load_current_restore(Path(evidence_root), run_id)
    authorization_configured = bool(
        transport == "streamable-http" and os.environ.get(token_env, "").strip()
    )
    report: dict[str, Any] = {
        "authorization_configured": authorization_configured,
        "calls": [],
        "cleanup": [],
        "coverage": [],
        "duration_ms": 0,
        "ended_at": "",
        "endpoint": endpoint if transport == "streamable-http" else None,
        "failure": None,
        "fixture_instance_sha256": fixture_hash,
        "fixture_spec_sha256": scenario["fixture_spec_sha256"],
        "index_sha256": sha256_file(index_path),
        "mcp_session": {"closed_at": None, "id": None, "initialized_at": None},
        "run_id": run_id,
        "runner": {
            "executable_sha256": _runner_executable_sha256(),
            "pid": os.getpid(),
            "process_start_time_utc": _runner_start_time_utc(),
        },
        "scenario": scenario_id,
        "schema_version": REPORT_SCHEMA_VERSION,
        "server_identity": None,
        "server_observation_sha256": None,
        "snapshot_evidence_sha256": None,
        "source_sha256": source_hash,
        "started_at": started_at,
        "status": "running",
        "steps": [],
        "tools_schema_sha256": None,
        "transport": transport,
        "unexecuted_step_ids": [],
    }
    completed: dict[str, Any] = {}
    scenario_failed = False
    stderr_file = tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False)
    stderr_path = Path(stderr_file.name)
    capture: HttpHeaderCapture | None = None
    children_before = direct_child_pids(os.getpid())
    try:
        if transport == "stdio":
            env = {key: value for key, value in os.environ.items() if key.upper() in SAFE_ENV}
            env.setdefault("PYTHONUTF8", "1")
            params = StdioServerParameters(
                command=sys.executable,
                args=[str(REPO_ROOT / "mcp_velociraptor_bridge.py")],
                cwd=REPO_ROOT,
                env=env,
            )
            session_context = stdio_client(params, errlog=stderr_file)
        else:
            import httpx2
            from mcp.client.streamable_http import streamable_http_client

            token = os.environ.get(token_env, "").strip()
            if not token:
                raise ScenarioInputError(f"{token_env} is required for the formal HTTP transport")
            if not endpoint or not re.fullmatch(r"http://[0-9.]+:28790/mcp", endpoint):
                raise ScenarioInputError("endpoint must be a sanitized http://<ip>:28790/mcp URL")
            capture = HttpHeaderCapture(httpx2.AsyncHTTPTransport())
            http_client = httpx2.AsyncClient(
                headers={"Authorization": f"Bearer {token}"},
                timeout=60.0,
                transport=capture,
            )
            session_context = streamable_http_client(endpoint, http_client=http_client)
        async with session_context as (read, write):
            async with ClientSession(read, write) as session:
                report["mcp_session"]["initialized_at"] = utc_now()
                await session.initialize()
                if transport == "stdio":
                    spawned = direct_child_pids(os.getpid()) - children_before
                    if len(spawned) != 1:
                        raise ScenarioInputError("could not identify the single bridge child process")
                    report["server_identity"] = _local_process_identity(next(iter(spawned)))
                else:
                    initialized_response = next(
                        (
                            row
                            for row in (capture.responses if capture else [])
                            if row["method"] == "POST" and row["mcp_session_id"]
                        ),
                        None,
                    )
                    if initialized_response is None:
                        raise ScenarioFailure("no Mcp-Session-Id response header captured")
                    report["mcp_session"]["id"] = initialized_response["mcp_session_id"]
                    instance_id = initialized_response["server_instance_id"]
                    if not instance_id:
                        raise ScenarioFailure("no X-MCP-Server-Instance response header captured")
                    observation = verify_server_observation(
                        Path(server_observation) if server_observation else Path(
                            REPO_ROOT / "Logs" / "server-observation.json"
                        ),
                        instance_id,
                    )
                    report["server_identity"] = {
                        key: observation[key]
                        for key in (
                            "computer_name",
                            "service_name",
                            "pid",
                            "process_start_time_utc",
                            "instance_id",
                            "executable_sha256",
                        )
                    }
                    report["server_observation_sha256"] = sha256_file(Path(server_observation) if server_observation else Path(
                        REPO_ROOT / "Logs" / "server-observation.json"
                    ))
                tools = (await session.list_tools()).tools
                names = {tool.name for tool in tools}
                tools_document = tools_schema_document(tools)
                tools_bytes = canonical_bytes(tools_document)
                report["tools_schema_sha256"] = hashlib.sha256(tools_bytes).hexdigest()
                (run_dir / "tools-schema.json").write_bytes(tools_bytes)
                if len(tools) != 130 or len(names) != 130:
                    raise ScenarioInputError("runtime tool inventory must contain 130 unique tools")
                required_tools = {step["tool"] for step in scenario["steps"] + scenario["cleanup"]}
                unknown = sorted(required_tools - names)
                if unknown:
                    raise ScenarioInputError(f"scenario contains unknown tools: {unknown}")
                for index, step in enumerate(scenario["steps"]):
                    if step["kind"] == "sleep":
                        await asyncio.sleep(step["seconds"])
                        report["steps"].append({"id": step["id"], "kind": "sleep", "passed": True})
                        completed[step["id"]] = {"slept": step["seconds"]}
                        continue
                    try:
                        value, assertions = await execute_tool_step(
                            session, step, completed, fixture, report["calls"]
                        )
                        completed[step["id"]] = value
                        report["steps"].append(
                            {"assertions": assertions, "id": step["id"], "kind": "tool", "passed": True}
                        )
                    except Exception as exc:
                        scenario_failed = True
                        report["failure"] = {
                            "message": str(exc),
                            "step_id": step["id"],
                            "type": type(exc).__name__,
                        }
                        report["steps"].append({"id": step["id"], "kind": "tool", "passed": False})
                        report["unexecuted_step_ids"] = [item["id"] for item in scenario["steps"][index + 1 :]]
                        break
                for cleanup in scenario["cleanup"]:
                    when = cleanup["when"]
                    if when == "on_success" and scenario_failed:
                        continue
                    if when == "on_failure" and not scenario_failed:
                        continue
                    cleanup_row = {"id": cleanup["id"], "passed": False, "tool": cleanup["tool"], "when": when}
                    try:
                        _, assertions = await execute_tool_step(
                            session, cleanup, completed, fixture, report["calls"]
                        )
                        cleanup_row["assertions"] = assertions
                        cleanup_row["passed"] = True
                    except Exception as exc:
                        cleanup_row["error"] = {"message": str(exc), "type": type(exc).__name__}
                        scenario_failed = True
                        if report["failure"] is None:
                            report["failure"] = {
                                "message": str(exc),
                                "step_id": cleanup["id"],
                                "type": type(exc).__name__,
                            }
                    report["cleanup"].append(cleanup_row)
                report["mcp_session"]["closed_at"] = utc_now()
                if not scenario_failed:
                    # Raises ScenarioFailure on any object-identity mismatch;
                    # the check outcome is reflected in the report status only.
                    validate_cross_step_invariants(scenario, completed, report["calls"])
        report["status"] = "failed" if scenario_failed else "success"
    except Exception as exc:
        scenario_failed = True
        report["status"] = "failed"
        if report["failure"] is None:
            report["failure"] = {
                "message": str(exc),
                "step_id": None,
                "type": type(exc).__name__,
                "chain": _exception_chain(exc),
            }
    finally:
        stderr_file.close()
        stderr_path.unlink(missing_ok=True)
        report["ended_at"] = utc_now()
        report["duration_ms"] = max(0, int((time.monotonic() - started) * 1000))
        if report["status"] == "success":
            if scenario_id.startswith("p06-") and transport == "streamable-http":
                try:
                    report["coverage"] = _p06_coverage(scenario_id, report)
                    if len(report["coverage"]) != 130:
                        raise ScenarioFailure("successful P06 scenario does not prove 130 relations")
                    _verify_terminal_flow_classification(report)
                except Exception as exc:
                    report["status"] = "failed"
                    report["coverage"] = []
                    report["failure"] = {
                        "message": str(exc),
                        "step_id": None,
                        "type": type(exc).__name__,
                    }
            else:
                report["coverage"] = (
                    sorted(
                        [
                            {"scenario_id": scenario_id, "tool": name}
                            for name in {row["tool"] for row in report["calls"]}
                        ],
                        key=lambda row: row["tool"],
                    )
                    if transport == "streamable-http"
                    else []
                )
        if restore_document is not None:
            snapshot_evidence = {
                "mcp_session_id": report["mcp_session"]["id"],
                "restore": restore_document,
                "scenario_id": scenario_id,
                "server_instance_id": (report["server_identity"] or {}).get("instance_id"),
                "server_observation_sha256": report["server_observation_sha256"],
                "source_sha256": source_hash,
                "index_sha256": report["index_sha256"],
            }
            evidence_bytes = canonical_bytes(snapshot_evidence)
            (run_dir / "snapshot-evidence.json").write_bytes(evidence_bytes)
            report["snapshot_evidence_sha256"] = hashlib.sha256(evidence_bytes).hexdigest()
        report_path.write_bytes(canonical_bytes(report))
    return report, report_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario-id", required=True)
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
    )
    parser.add_argument("--endpoint", default=None)
    parser.add_argument("--token-env", default="VELOCIRAPTOR_MCP_BEARER_TOKEN")
    parser.add_argument("--evidence-root", default=None)
    parser.add_argument("--server-observation", default=None)
    parser.add_argument("--run-id", default=None)
    args = parser.parse_args()
    try:
        report, path = asyncio.run(
            run_scenario(
                args.scenario_id,
                transport=args.transport,
                endpoint=args.endpoint,
                token_env=args.token_env,
                evidence_root=Path(args.evidence_root) if args.evidence_root else None,
                server_observation=Path(args.server_observation) if args.server_observation else None,
                run_id=args.run_id,
            )
        )
    except (ScenarioInputError, SnapshotEvidenceError, OSError, json.JSONDecodeError) as exc:
        print(f"scenario-runner: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"report": str(path), "status": report["status"]}, ensure_ascii=False, sort_keys=True))
    return 0 if report["status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
