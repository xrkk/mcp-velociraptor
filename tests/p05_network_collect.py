"""Produce the frozen P05 PC006 and dual-adapter network originals.

This module records facts only.  It does not restore a VM, choose the PC006
round boundary, activate a snapshot, or reinterpret historical summaries.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import stat
import subprocess
import uuid
from collections.abc import Callable, Mapping
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client import stdio as sdk_stdio
from mcp.shared.message import SessionMessage

from tests import p06_evidence as gate
from tests.p05_sdk_capture import SDKCapture


class CollectionError(RuntimeError):
    """A collection attempt did not produce a publishable evidence graph."""


@dataclass(frozen=True)
class Pc006Artifacts:
    boundary: Path
    bound_source: Path
    dual_port: Path


@dataclass(frozen=True)
class StdioArtifacts:
    launch: Path
    capture: Path
    listing: dict[str, Any]


@dataclass(frozen=True)
class NetworkArtifacts:
    network_evidence: Path
    schema_identity: Path


@dataclass
class _OwnedProcess:
    process: Any
    stdout: bytearray

    @property
    def returncode(self) -> int | None:
        return self.process.returncode


def _utc() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


def _write_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _write_json(path: Path, value: object) -> None:
    _write_new(path, _json_bytes(value))


def _plain_input(root: Path, path: Path, label: str) -> Path:
    root = root.absolute()
    path = path.absolute()
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise CollectionError(f"{label} is outside the approved root") from exc
    try:
        return gate.plain_file(root, relative)
    except gate.EvidenceError as exc:
        raise CollectionError(f"{label} is not a contained plain file: {exc}") from exc


def _new_output_root(approved_root: Path, output_root: Path) -> Path:
    approved_root = approved_root.absolute()
    output_root = output_root.absolute()
    try:
        relative = output_root.relative_to(approved_root)
    except ValueError as exc:
        raise CollectionError("output root is outside the approved root") from exc
    if not relative.parts:
        raise CollectionError("output root must be a new child, not the approved root")
    current = approved_root
    current_info = current.lstat() if current.exists() else None
    if (
        current_info is None
        or not stat.S_ISDIR(current_info.st_mode)
        or stat.S_ISLNK(current_info.st_mode)
        or getattr(current_info, "st_file_attributes", 0) & 0x400
    ):
        raise CollectionError("approved output root is not a plain directory")
    for part in relative.parts[:-1]:
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise CollectionError("output parent does not exist") from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise CollectionError("output path contains a link or non-directory")
    try:
        output_root.mkdir()
    except FileExistsError as exc:
        raise CollectionError("output root already exists; evidence is never overwritten") from exc
    return output_root


def _ref(bundle_root: Path, path: Path) -> dict[str, Any]:
    plain = _plain_input(bundle_root, path, "reference target")
    return {
        "path": plain.relative_to(bundle_root.absolute()).as_posix(),
        "size": plain.stat().st_size,
        "sha256": gate.digest(plain),
    }


def _streams(stdout: str, stderr: str) -> dict[str, Any]:
    stdout_bytes, stderr_bytes = stdout.encode("utf-8"), stderr.encode("utf-8")
    return {
        "stdout": stdout,
        "stdout_size": len(stdout_bytes),
        "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
        "stderr": stderr,
        "stderr_size": len(stderr_bytes),
        "stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest(),
    }


def _failure_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    return value if isinstance(value, bytes) else value.encode("utf-8")


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CollectionError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CollectionError(f"{label} is not a JSON object")
    return value


def _identity(value: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise CollectionError(f"{label} must be non-empty")
    return value


def _default_command_executor(argv: list[str], timeout: float) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv, check=False, capture_output=True, timeout=timeout, shell=False, text=False
    )


def _command_envelope(
    *,
    argv: list[str],
    completed: subprocess.CompletedProcess[bytes],
    started_at: str,
    ended_at: str,
    run_id: str,
    restore_attempt_id: str,
    vmx: str,
    mode: str,
) -> dict[str, Any]:
    if list(completed.args) != argv:
        raise CollectionError("executor returned a result for different argv")
    if type(completed.returncode) is not int:
        raise CollectionError("collector did not return an actual integer exit code")
    try:
        stdout = bytes(completed.stdout or b"").decode("utf-8")
        stderr = bytes(completed.stderr or b"").decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CollectionError("collector stdout/stderr is not UTF-8") from exc
    return {
        "schema_version": 1,
        "kind": gate.PC006_COMMAND_KIND,
        "workflow_id": gate.WORKFLOW_ID,
        "run_id": run_id,
        "restore_attempt_id": restore_attempt_id,
        "operation_id": f"pc006-{mode}-{uuid.uuid4()}",
        "observation": f"pc006-{mode}-collector-execution",
        "vmx": vmx,
        "request": {"argv": argv, "command_line": " ".join(argv)},
        "started_at": started_at,
        "ended_at": ended_at,
        "exit_status": {"code": completed.returncode},
        "response": _streams(stdout, stderr),
    }


def _validate_pc006_envelope(
    envelope: dict[str, Any], mode: str, source: str, comparison_port: int
) -> None:
    facts = gate._pc006_collector_document(
        envelope, f"PC006 {mode}", mode, source, comparison_port
    )
    clock = (
        gate._parse_utc(envelope["started_at"], f"PC006 {mode}.started_at"),
        gate._parse_utc(envelope["ended_at"], f"PC006 {mode}.ended_at"),
    )
    if mode == gate.PC006_BOUND_MODE:
        row = facts["executions"][0]
        gate._pc006_execution_row(row, "PC006 bound", "probe_source", 28790, source, clock=clock)
        gate._pc006_curl_failure_class(row, "PC006 bound")
        return
    expected = {
        ("probe_source", 28790): source,
        ("allowed_source", 28790): "192.168.204.1",
        ("probe_source", comparison_port): source,
        ("allowed_source", comparison_port): "192.168.204.1",
    }
    rows: dict[tuple[str, int], dict[str, Any]] = {}
    for position, row in enumerate(facts["executions"]):
        key = (row.get("role"), row.get("port"))
        if key not in expected or key in rows:
            raise gate.EvidenceError(f"PC006 dual execution {position} identity differs")
        gate._pc006_execution_row(
            row, f"PC006 dual execution {position}", key[0], key[1], expected[key], clock=clock
        )
        rows[key] = row
    if set(rows) != set(expected):
        raise gate.EvidenceError("PC006 dual collector omitted a role/port execution")
    for port in (28790, comparison_port):
        gate._pc006_curl_failure_class(rows[("probe_source", port)], f"PC006 dual {port}")
        gate._pc006_allowed_response(rows[("allowed_source", port)], f"PC006 allowed {port}")


def collect_pc006(
    *,
    approved_root: Path,
    bundle_root: Path,
    output_root: Path,
    ready_path: Path,
    run_id: str,
    restore_attempt_id: str,
    probe_source_address: str,
    comparison_port: int,
    vmx: str,
    timeout: float = 60,
    executor: Callable[[list[str], float], subprocess.CompletedProcess[bytes]] = _default_command_executor,
) -> Pc006Artifacts:
    """Execute both frozen host collectors and publish one PC006 boundary.

    ``executor`` is the explicit isolated-test seam.  Production uses
    ``subprocess.run(..., shell=False)`` with the exact frozen argv.
    """
    run_id = _identity(run_id, "run_id")
    restore_attempt_id = _identity(restore_attempt_id, "restore_attempt_id")
    _identity(vmx, "vmx")
    try:
        source = str(ipaddress.ip_address(probe_source_address))
    except ValueError as exc:
        raise CollectionError("probe source is not an IP address") from exc
    if source in {"192.168.204.1", "192.168.204.232"}:
        raise CollectionError("probe source is not a non-allowed source")
    if (
        type(comparison_port) is not int
        or not 1 <= comparison_port <= 65535
        or comparison_port == 28790
    ):
        raise CollectionError("comparison port is invalid")
    ready_path = _plain_input(approved_root, ready_path, "ready original")
    ready = _load_json(ready_path, "ready original")
    if ready.get("run_id") != run_id or ready.get("restore_attempt_id") != restore_attempt_id:
        raise CollectionError("ready original belongs to another run or restore attempt")
    observations = ready.get("observations")
    if not isinstance(observations, dict) or not isinstance(observations.get("firewall"), dict):
        raise CollectionError("ready original lacks its firewall Ref")
    firewall_ref = dict(observations["firewall"])
    try:
        gate._resolve_ref(bundle_root, firewall_ref, "ready firewall", {})
    except gate.EvidenceError as exc:
        raise CollectionError(f"ready firewall Ref is invalid: {exc}") from exc

    root = _new_output_root(approved_root, output_root)
    failures: list[dict[str, Any]] = []
    paths: dict[str, Path] = {}
    for mode, filename in ((gate.PC006_BOUND_MODE, "bound-source.json"),
                           (gate.PC006_DUAL_MODE, "dual-port.json")):
        argv = gate.pc006_collector_argv(mode, source, comparison_port)
        started_at = _utc()
        try:
            completed = executor(argv, timeout)
            ended_at = _utc()
            envelope = _command_envelope(
                argv=argv, completed=completed, started_at=started_at, ended_at=ended_at,
                run_id=run_id, restore_attempt_id=restore_attempt_id, vmx=vmx, mode=mode,
            )
            path = root / filename
            _write_json(path, envelope)
            paths[mode] = path
            try:
                _validate_pc006_envelope(envelope, mode, source, comparison_port)
            except gate.EvidenceError as exc:
                failures.append({"mode": mode, "error": str(exc), "type": type(exc).__name__})
        except subprocess.TimeoutExpired as exc:
            ended_at = _utc()
            failures.append({
                "mode": mode, "error": "collector timed out", "type": type(exc).__name__,
                "started_at": started_at, "ended_at": ended_at, "argv": argv,
                "stdout_sha256": hashlib.sha256(_failure_bytes(exc.stdout)).hexdigest(),
                "stderr_sha256": hashlib.sha256(_failure_bytes(exc.stderr)).hexdigest(),
            })
        except (CollectionError, OSError) as exc:
            failures.append({"mode": mode, "error": str(exc), "type": type(exc).__name__})

    if failures:
        _write_json(root / "collection-failure.json", {
            "schema_version": 1, "kind": "p05-network-collection-failure-v1",
            "workflow_id": gate.WORKFLOW_ID, "run_id": run_id,
            "restore_attempt_id": restore_attempt_id, "failures": failures,
        })
        raise CollectionError("PC006 collection failed; no boundary was published")

    boundary = {
        "schema_version": 1,
        "kind": gate.PC006_BOUNDARY_KIND,
        "workflow_id": gate.WORKFLOW_ID,
        "run_id": run_id,
        "restore_attempt_id": restore_attempt_id,
        "probe_source_address": source,
        "comparison_port": comparison_port,
        "bound_source_failure": _ref(bundle_root, paths[gate.PC006_BOUND_MODE]),
        "dual_port_control": _ref(bundle_root, paths[gate.PC006_DUAL_MODE]),
        "firewall_rule": firewall_ref,
    }
    boundary_path = root / "pc006.json"
    try:
        gate._verify_pc006_firewall(
            bundle_root,
            {"run_id": run_id, "restore_attempt_id": restore_attempt_id,
             "ready": _ref(bundle_root, ready_path)},
            boundary,
            {},
        )
    except gate.EvidenceError as exc:
        _write_json(root / "collection-failure.json", {
            "schema_version": 1, "kind": "p05-network-collection-failure-v1",
            "workflow_id": gate.WORKFLOW_ID, "run_id": run_id,
            "restore_attempt_id": restore_attempt_id,
            "failures": [{"mode": "firewall", "error": str(exc),
                          "type": type(exc).__name__}],
        })
        raise CollectionError("PC006 firewall original fails the existing gate") from exc
    _write_json(boundary_path, boundary)
    return Pc006Artifacts(boundary_path, paths[gate.PC006_BOUND_MODE], paths[gate.PC006_DUAL_MODE])


@asynccontextmanager
async def _owned_stdio_transport(
    server: StdioServerParameters,
    stderr_file: Any,
    spawn_observer: Callable[[int], None] | None,
):
    """SDK stdio transport with observable ownership and actual exit status."""
    command = sdk_stdio._get_executable_command(server.command)
    process = await sdk_stdio._create_platform_compatible_process(
        command=command,
        args=server.args,
        env=sdk_stdio.get_default_environment() | (server.env or {}),
        errlog=stderr_file,
        cwd=server.cwd,
    )
    if spawn_observer is not None:
        spawn_observer(process.pid)
    read_sender, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](0)
    write_stream, write_receiver = anyio.create_memory_object_stream[SessionMessage](0)
    owner = _OwnedProcess(process, bytearray())
    writer_done = anyio.Event()
    shutting_down = False

    async def stdout_reader() -> None:
        assert process.stdout
        buffer = b""
        try:
            async with read_sender:
                while True:
                    try:
                        chunk = await process.stdout.receive()
                    except anyio.EndOfStream:
                        break
                    owner.stdout.extend(chunk)
                    lines = (buffer + chunk).split(b"\n")
                    buffer = lines.pop()
                    for line in lines:
                        try:
                            text = line.decode(server.encoding, errors=server.encoding_error_handler)
                            await read_sender.send(sdk_stdio._parse_line(text))
                        except (anyio.ClosedResourceError, anyio.BrokenResourceError):
                            return
                if buffer:
                    await read_sender.send(sdk_stdio._parse_line(
                        buffer.decode(server.encoding, errors=server.encoding_error_handler)))
        except (anyio.ClosedResourceError, anyio.BrokenResourceError, ConnectionError, OSError):
            if not shutting_down:
                raise

    async def stdin_writer() -> None:
        assert process.stdin
        try:
            async with write_receiver:
                async for message in write_receiver:
                    payload = message.message.model_dump_json(by_alias=True, exclude_unset=True)
                    await process.stdin.send((payload + "\n").encode(
                        server.encoding, errors=server.encoding_error_handler))
        except (anyio.ClosedResourceError, anyio.BrokenResourceError, OSError):
            await read_sender.aclose()
        finally:
            writer_done.set()

    async with anyio.create_task_group() as tasks:
        tasks.start_soon(stdout_reader)
        tasks.start_soon(stdin_writer)
        try:
            yield read_stream, write_stream, owner
        finally:
            shutting_down = True
            with anyio.CancelScope(shield=True):
                read_stream.close()
                write_stream.close()
                with anyio.move_on_after(sdk_stdio._WRITER_FLUSH_TIMEOUT):
                    await writer_done.wait()
                await sdk_stdio._stop_server_process(process)
                await sdk_stdio._aclose_all(read_stream, write_stream, read_sender, write_receiver)
            tasks.cancel_scope.cancel()
    await anyio.lowlevel.cancel_shielded_checkpoint()


async def collect_stdio(
    *,
    approved_root: Path,
    bundle_root: Path,
    output_root: Path,
    repository_root: Path,
    python_executable: Path,
    bridge_script: Path,
    host_name: str,
    http_run_id: str,
    stdio_run_id: str,
    restore_attempt_id: str,
    expected_http_tools: Path,
    environment: Mapping[str, str] | None = None,
    timeout: float = 60,
    spawn_observer: Callable[[int], None] | None = None,
) -> StdioArtifacts:
    """Launch one owned bridge, capture initialize/tools-list, and reap it."""
    for value, label in ((host_name, "host_name"), (http_run_id, "http_run_id"),
                         (stdio_run_id, "stdio_run_id"),
                         (restore_attempt_id, "restore_attempt_id")):
        _identity(value, label)
    if stdio_run_id == http_run_id:
        raise CollectionError("stdio diagnostic run_id must differ from the HTTP report run_id")
    if host_name != "DESKTOP-3FI41GR":
        raise CollectionError("stdio host is not the approved guest")
    repository_root = repository_root.absolute()
    python_executable = _plain_input(approved_root, python_executable, "stdio interpreter")
    bridge_script = _plain_input(approved_root, bridge_script, "stdio bridge")
    expected_http_tools = _plain_input(approved_root, expected_http_tools, "HTTP tools/list")
    if python_executable != repository_root / ".venv" / "Scripts" / "python.exe":
        raise CollectionError("stdio interpreter is not the selected repository virtualenv python.exe")
    if bridge_script != repository_root / "mcp_velociraptor_bridge.py":
        raise CollectionError("stdio target is not the selected repository bridge script")
    allowed_environment = {
        "SYSTEMROOT", "WINDIR", "COMSPEC", "PATH", "PATHEXT", "TEMP", "TMP",
        "VELOCIRAPTOR_API_CONFIG", "VELOCIRAPTOR_DOWNLOAD_ROOT", "PYTHONUTF8",
        "VELOCIRAPTOR_MCP_TRANSPORT", "PYTHONDONTWRITEBYTECODE",
    }
    env = dict(environment or {})
    if any(key.upper() not in allowed_environment for key in env):
        raise CollectionError("stdio environment contains an unapproved key")
    env["VELOCIRAPTOR_MCP_TRANSPORT"] = "stdio"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    expected_listing = _load_json(expected_http_tools, "HTTP tools/list")
    expected_normalized = gate._normalized_tools_bytes(expected_listing)
    root = _new_output_root(approved_root, output_root)
    capture_path = root / "capture.ndjson"
    stderr_path = root / "stderr.txt"
    launch_path = root / "launch.json"
    failure_path = root / "collection-failure.json"
    capture = SDKCapture(capture_path)
    started_at = _utc()
    owner: _OwnedProcess | None = None
    listing: dict[str, Any] | None = None
    failure: BaseException | None = None
    stderr_file = stderr_path.open("x+", encoding="utf-8", newline="")
    params = StdioServerParameters(
        command=str(python_executable), args=[str(bridge_script)], cwd=repository_root, env=env,
    )
    try:
        with anyio.fail_after(timeout):
            async with _owned_stdio_transport(params, stderr_file, spawn_observer) as (read, write, owned):
                owner = owned
                observed_read, observed_write = capture.wrap(read, write)
                async with ClientSession(observed_read, observed_write) as session:
                    await session.initialize()
                    response = await session.list_tools()
                    listing = response.model_dump(mode="json", by_alias=True, exclude_none=True)
    except BaseException as exc:
        failure = exc
    finally:
        ended_at = _utc()
        with suppress(BaseException):
            capture.close()
        stderr_file.flush()
        os.fsync(stderr_file.fileno())
        stderr_file.seek(0)
        stderr = stderr_file.read()
        stderr_file.close()

    stdout_bytes = bytes(owner.stdout) if owner is not None else b""
    try:
        stdout = stdout_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        failure = failure or exc
        stdout = stdout_bytes.decode("utf-8", errors="replace")
    returncode = owner.returncode if owner is not None else None
    launch = {
        "schema_version": 1,
        "kind": gate.STDIO_LAUNCH_KIND,
        "workflow_id": gate.WORKFLOW_ID,
        "run_id": stdio_run_id,
        "restore_attempt_id": restore_attempt_id,
        "host": {"scope": "guest", "computer_name": host_name},
        "request": {
            "argv": [str(python_executable), str(bridge_script)],
            "command_line": f"{python_executable} {bridge_script}",
        },
        "started_at": started_at,
        "ended_at": ended_at,
        "exit_status": {"code": returncode},
        "response": _streams(stdout, stderr),
    }
    _write_json(launch_path, launch)
    if failure is not None or returncode != 0 or listing is None:
        _write_json(failure_path, {
            "schema_version": 1, "kind": "p05-network-collection-failure-v1",
            "workflow_id": gate.WORKFLOW_ID, "run_id": stdio_run_id,
            "restore_attempt_id": restore_attempt_id,
            "error_type": type(failure).__name__ if failure is not None else "ProcessExit",
            "process_exit_code": returncode,
        })
        if isinstance(failure, anyio.get_cancelled_exc_class()):
            raise failure
        raise CollectionError("stdio collection failed; no schema identity was published") from failure
    if gate._normalized_tools_bytes(listing) != expected_normalized:
        _write_json(failure_path, {
            "schema_version": 1, "kind": "p05-network-collection-failure-v1",
            "workflow_id": gate.WORKFLOW_ID, "run_id": stdio_run_id,
            "restore_attempt_id": restore_attempt_id,
            "error_type": "ToolsListMismatch", "process_exit_code": returncode,
        })
        raise CollectionError("stdio tools/list differs from the HTTP original")
    try:
        rows = gate._verify_stdio_capture(capture_path, expected_normalized)
        gate._verify_stdio_launch(launch_path, {
            "run_id": http_run_id, "restore_attempt_id": restore_attempt_id,
        }, rows)
    except gate.EvidenceError as exc:
        _write_json(failure_path, {
            "schema_version": 1, "kind": "p05-network-collection-failure-v1",
            "workflow_id": gate.WORKFLOW_ID, "run_id": stdio_run_id,
            "restore_attempt_id": restore_attempt_id,
            "error_type": type(exc).__name__, "process_exit_code": returncode,
        })
        raise CollectionError(f"stdio originals fail the existing gate: {exc}") from exc
    return StdioArtifacts(launch_path, capture_path, listing)


def assemble_network_evidence(
    *,
    approved_root: Path,
    bundle_root: Path,
    output_root: Path,
    run_id: str,
    restore_attempt_id: str,
    report_path: Path,
    ready_path: Path,
    http_tools_path: Path,
    http_headers_path: Path,
    service_observation_path: Path,
    pc006_boundary_path: Path,
    stdio_launch_path: Path,
    stdio_capture_path: Path,
) -> NetworkArtifacts:
    """Join already collected originals and run the existing network gate."""
    run_id = _identity(run_id, "run_id")
    restore_attempt_id = _identity(restore_attempt_id, "restore_attempt_id")
    inputs = {
        "report": report_path, "ready": ready_path, "HTTP tools/list": http_tools_path,
        "HTTP headers": http_headers_path, "service observation": service_observation_path,
        "PC006 boundary": pc006_boundary_path, "stdio launch": stdio_launch_path,
        "stdio capture": stdio_capture_path,
    }
    plain = {name: _plain_input(approved_root, path, name) for name, path in inputs.items()}
    report = _load_json(plain["report"], "report")
    ready = _load_json(plain["ready"], "ready")
    pc006 = _load_json(plain["PC006 boundary"], "PC006 boundary")
    launch = _load_json(plain["stdio launch"], "stdio launch")
    service = _load_json(plain["service observation"], "service observation")
    if report.get("run_id") != run_id:
        raise CollectionError("report run_id differs")
    if ready.get("run_id") != run_id or ready.get("restore_attempt_id") != restore_attempt_id:
        raise CollectionError("ready original belongs to another round")
    if pc006.get("run_id") != run_id or pc006.get("restore_attempt_id") != restore_attempt_id:
        raise CollectionError("PC006 original belongs to another round")
    if launch.get("restore_attempt_id") != restore_attempt_id or launch.get("run_id") == run_id:
        raise CollectionError("stdio diagnostic must use a distinct run in the same restore attempt")
    if any(service.get(key) != value for key, value in report.get("server_identity", {}).items()):
        raise CollectionError("service observation does not join the HTTP report")
    if not service.get("observed_at"):
        raise CollectionError("service observation lacks observed_at")
    report_parent = plain["report"].parent
    if plain["HTTP tools/list"] != report_parent / "tools-list.json":
        raise CollectionError("HTTP tools/list is not the report run's tools-list.json")
    if plain["HTTP headers"] != report_parent / "http-headers.json":
        raise CollectionError("HTTP headers are not the report run's http-headers.json")

    root = _new_output_root(approved_root, output_root)
    schema = {
        "schema_version": 1,
        "kind": gate.SCHEMA_IDENTITY_KIND,
        "workflow_id": gate.WORKFLOW_ID,
        "run_id": run_id,
        "restore_attempt_id": restore_attempt_id,
        "http": {
            "transport": "http",
            "headers": _ref(bundle_root, plain["HTTP headers"]),
            "tools_list": _ref(bundle_root, plain["HTTP tools/list"]),
        },
        "stdio": {
            "transport": "stdio",
            "launch": _ref(bundle_root, plain["stdio launch"]),
            "capture": _ref(bundle_root, plain["stdio capture"]),
        },
    }
    schema_path = root / "schema-identity.json"
    _write_json(schema_path, schema)
    network = {
        "schema_version": 1,
        "workflow_id": gate.WORKFLOW_ID,
        "run_id": run_id,
        "restore_attempt_id": restore_attempt_id,
        "non_allowed_source": _ref(bundle_root, plain["PC006 boundary"]),
        "schema_identity": _ref(bundle_root, schema_path),
        "service_observation": _ref(bundle_root, plain["service observation"]),
    }
    network_path = root / "network-evidence.json"
    _write_json(network_path, network)
    phase = {
        "run_id": run_id,
        "restore_attempt_id": restore_attempt_id,
        "report": _ref(bundle_root, plain["report"]),
        "ready": _ref(bundle_root, plain["ready"]),
        "network_evidence": _ref(bundle_root, network_path),
    }
    try:
        gate._verify_network_evidence(bundle_root, phase, {})
    except gate.EvidenceError as exc:
        with suppress(OSError):
            network_path.unlink()
        with suppress(OSError):
            schema_path.unlink()
        _write_json(root / "collection-failure.json", {
            "schema_version": 1, "kind": "p05-network-collection-failure-v1",
            "workflow_id": gate.WORKFLOW_ID, "run_id": run_id,
            "restore_attempt_id": restore_attempt_id,
            "error_type": type(exc).__name__,
        })
        raise CollectionError(f"assembled network evidence fails the existing gate: {exc}") from exc
    return NetworkArtifacts(network_path, schema_path)
