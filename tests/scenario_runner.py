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


REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_ROOT = REPO_ROOT / "tests" / "scenarios"
SCHEMA_PATH = SCENARIO_ROOT / "schema-v1.json"
INDEX_PATH = REPO_ROOT / "tests" / "data" / "p05_scenario_index.json"
FIXTURE_SPEC_PATH = REPO_ROOT / "tests" / "data" / "p05_fixture_spec.json"
FIXTURE_INSTANCE_PATH = Path(r"C:\VelociraptorMCP\fixtures-p05\fixture-instance-v1.json")
REPORT_ROOT = REPO_ROOT / "Logs" / "P05" / "wf-01a05d1d-p05"
REQUIRED_SNAPSHOT = "Snapshot 185-Velociraptor-MCP依赖与情景基线"
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


def load_indexed_scenario(scenario_id: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,63}", scenario_id):
        raise ScenarioInputError("invalid scenario id")
    index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    if set(index) != {"schema_version", "scenarios"} or index["schema_version"] != 1:
        raise ScenarioInputError("invalid scenario index")
    matches = [row for row in index["scenarios"] if row.get("scenario_id") == scenario_id]
    if len(matches) != 1:
        raise ScenarioInputError("scenario id is not uniquely indexed")
    row = matches[0]
    if set(row) != {
        "scenario_id",
        "path",
        "sha256",
        "required_snapshot",
        "fixture_spec_sha256",
    }:
        raise ScenarioInputError("invalid scenario index row")
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
    if scenario["required_snapshot"] != REQUIRED_SNAPSHOT or row["required_snapshot"] != REQUIRED_SNAPSHOT:
        raise ScenarioInputError("scenario requires an unapproved snapshot")
    if scenario["fixture_spec_sha256"] != row["fixture_spec_sha256"]:
        raise ScenarioInputError("scenario fixture spec differs from the index")
    ids = [step["id"] for step in scenario["steps"] + scenario["cleanup"]]
    if len(ids) != len(set(ids)):
        raise ScenarioInputError("scenario step ids must be globally unique")
    if sum(step["kind"] == "tool" for step in scenario["steps"]) < 10:
        raise ScenarioInputError("scenario requires at least ten tool steps")
    validate_scenario_semantics(scenario)
    return scenario, row, actual_hash


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
        if "$fixture" in value or "$ref" in value:
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
    return {
        "actual": None if actual is _MISSING else actual,
        "actual_exists": exists,
        "expected": expected,
        "op": op,
        "passed": passed,
    }


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
        if "$ref" in value or "$fixture" in value:
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


async def run_scenario(scenario_id: str) -> tuple[dict[str, Any], Path]:
    scenario, index_row, source_hash = load_indexed_scenario(scenario_id)
    fixture, fixture_hash = load_fixture(scenario)
    run_id = str(uuid.uuid4())
    report_path = REPORT_ROOT / run_id / "report.json"
    started_at = utc_now()
    started = time.monotonic()
    report: dict[str, Any] = {
        "calls": [],
        "cleanup": [],
        "duration_ms": 0,
        "ended_at": "",
        "failure": None,
        "fixture_instance_sha256": fixture_hash,
        "fixture_spec_sha256": scenario["fixture_spec_sha256"],
        "index_sha256": sha256_file(INDEX_PATH),
        "run_id": run_id,
        "scenario": scenario_id,
        "schema_version": 1,
        "server_pid": None,
        "session_id": str(uuid.uuid4()),
        "source_sha256": source_hash,
        "started_at": started_at,
        "status": "running",
        "steps": [],
        "unexecuted_step_ids": [],
        "coverage": [],
    }
    completed: dict[str, Any] = {}
    scenario_failed = False
    stderr_file = tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False)
    stderr_path = Path(stderr_file.name)
    children_before = direct_child_pids(os.getpid())
    try:
        env = {key: value for key, value in os.environ.items() if key.upper() in SAFE_ENV}
        env.setdefault("PYTHONUTF8", "1")
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(REPO_ROOT / "mcp_velociraptor_bridge.py")],
            cwd=REPO_ROOT,
            env=env,
        )
        async with stdio_client(params, errlog=stderr_file) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                spawned = direct_child_pids(os.getpid()) - children_before
                if len(spawned) != 1:
                    raise ScenarioInputError("could not identify the single bridge child process")
                report["server_pid"] = next(iter(spawned))
                tools = (await session.list_tools()).tools
                names = {tool.name for tool in tools}
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
        report["status"] = "failed" if scenario_failed else "success"
    finally:
        stderr_file.close()
        stderr_path.unlink(missing_ok=True)
        report["ended_at"] = utc_now()
        report["duration_ms"] = max(0, int((time.monotonic() - started) * 1000))
        report["coverage"] = sorted(
            [
                {"scenario_id": scenario_id, "tool": name}
                for name in {row["tool"] for row in report["calls"]}
            ],
            key=lambda row: row["tool"],
        )
        report_path.parent.mkdir(parents=True, exist_ok=False)
        report_path.write_bytes(canonical_bytes(report))
    return report, report_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario-id", required=True)
    args = parser.parse_args()
    try:
        report, path = asyncio.run(run_scenario(args.scenario_id))
    except (ScenarioInputError, OSError, json.JSONDecodeError) as exc:
        print(f"scenario-runner: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"report": str(path), "status": report["status"]}, ensure_ascii=False, sort_keys=True))
    return 0 if report["status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
