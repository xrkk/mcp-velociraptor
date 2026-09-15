"""Fail-closed parsing for P05 ``ready`` raw originals.

This module deliberately validates *recorded command transcripts*, not a
``passed`` field supplied by a collector.  It does not collect from Windows
and a passing unit-test fixture is not a claim that any Windows observation
has been obtained.  Until the activation validator calls
``verify_ready_raw_evidence`` and the required originals are actually present,
the caller's candidate activation remains blocked.

Collector interface (one UTF-8 JSON file for each named observation):

```
{
  "schema_version": 1,
  "kind": "p05-ready-command-v1",
  "observation": "host_clock | guest_identity | fixture_static | "
                 "fixture_instance | guest_processes | host_processes | "
                 "parent_bindings | dependencies | service | acl | firewall | "
                 "resources",
  "workflow_id": "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2",
  "run_id": "<reserved run id>",
  "restore_attempt_id": "<current restore attempt>",
  "host": {"scope": "host | guest", "computer_name": "<actual name>"},
  "request": {"argv": ["<actual executable>", "..."],
              "command_line": "<complete actual command/request>"},
  "started_at": "<UTC RFC3339>",
  "ended_at": "<UTC RFC3339>",
  "exit_status": {"code": 0},
  "response": {
    "stdout": "<complete, untruncated UTF-8 command output>",
    "stdout_size": 0,
    "stdout_sha256": "<sha256 of stdout UTF-8 bytes>",
    "stderr": "<complete UTF-8 stderr, possibly empty>",
    "stderr_size": 0,
    "stderr_sha256": "<sha256 of stderr UTF-8 bytes>"
  }
}
```

``stdout`` is a single JSON object emitted by the actual fixed read-only
command.  Its exact payload is observation-specific and is parsed below.  In
particular, the fixture transcript is the unmodified UTF-8 contents of
``fixture-instance-v1.json``.  The process snapshots use the field casing
already emitted by ``p05_real_acceptance.process_snapshot`` and
``p05_process_parent``.  A collector must not substitute an ``expected``,
``passed``, or ``ok`` summary for any of those raw responses.

The remaining six observations use the following *raw projection* contracts.
They intentionally retain the observations which the validator consumes; a
collector may select these exact properties from Windows/VQL, but may not
replace them with a Boolean conclusion.

* ``fixture_static`` has exact keys ``fixture_spec_sha256``,
  ``fixture_instance``, ``fixture_root``, ``ownership_marker``, ``files``,
  ``registry``, ``event_rows``, and ``task``.  ``fixture_instance`` is
  ``path/is_reparse_point/file_type/sha256``; ``fixture_root`` is
  ``path/is_reparse_point/file_type``; ``ownership_marker`` is
  ``path/is_reparse_point/file_type/content``; every file row is
  ``path/relative_path/size/sha256/is_reparse_point/file_type``.  Registry,
  event, and task values are the direct Windows readbacks used below.
* ``dependencies`` has exact keys ``dependency_manifest_sha256``,
  ``inventory_rows``, ``probe_rows``, ``local_public_bytes``, ``locked_files``,
  and ``artifact_rows``.  These are the selected inventory_get, inventory,
  local-public byte, locked-file, and artifact-definition rows; artifact
  ``raw`` is retained as returned, not replaced by its hash.
* ``service`` has exact keys ``service_rows``, ``service_process_rows``, and
  ``listeners``.  The single service row retains
  ``name/state/start_name/start_mode/process_id/path_name``; its process row
  retains ``ProcessId/ParentProcessId/Name/ExecutablePath/CreationDate/CommandLine/executable_sha256``;
  listener rows retain ``LocalAddress/LocalPort/State/OwningProcess``.
* ``acl`` has exact keys ``service_account``, ``paths``, and ``code_tree``.
  The account is ``name/sid``.  Each protected path has a real Windows
  security descriptor in ``security_descriptor_base64``, its actual SDDL,
  and a one-for-one binary ACE projection.  Every projected ACE retains
  ``identity/sid/ace_type/ace_flags/access_control_type/access_mask/``
  ``is_inherited/inheritance_flags/propagation_flags/raw_ace_base64``.
  ``code_tree`` is a closed, actual child enumeration of every repository
  node (including the separately classified ``Logs`` subtree); every node
  carries the same raw descriptor projection.  It records no protected-file
  contents, token, or token fingerprint.
* ``firewall`` has exact key ``rules``.  A rule is the direct filter join
  ``name/display_name/direction/action/enabled/protocol/local_port/local_address/remote_address``.
* ``resources`` has exact keys ``owned_flows``, ``owned_hunts``,
  ``historical_flows``, ``historical_hunts``, ``trace``, and
  ``temporary_listeners``.  A current resource row is
  ``resource_id/client_id/state/creator/created_at_utc``; historical rows
  use the same shape.  ``trace`` retains
  ``argv/exit_status/stdout/stderr`` from ``netsh trace show status`` and a
  temporary listener row is ``LocalAddress/LocalPort/State/OwningProcess``.

All timestamps are UTC RFC3339 strings.  Values described as an ``exact``
key set are deliberately versioned collector inputs: an incomplete projection
fails rather than being silently interpreted as a successful observation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
import base64
from pathlib import Path, PureWindowsPath
import re
import stat
import struct
import subprocess
from typing import Any, Mapping


class ReadyEvidenceError(ValueError):
    """A required raw ready observation is missing, malformed, or incompatible."""


WORKFLOW_ID = "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2"
GUEST_COMPUTER_NAME = "DESKTOP-3FI41GR"
WINDOWS_CLIENT_ID = "C.21794325e524a33d"
FIXTURE_ROOT = r"C:\VelociraptorMCP\fixtures-p05"
FIXTURE_SPEC_SOURCE = "source/tests/data/p05_fixture_spec.json"
PROCESS_PARENT_SOURCE = "source/tests/p05_process_parent.py"
DEPENDENCY_MANIFEST_SOURCE = "source/tests/data/p05_dependency_manifest.json"
KILL_ARTIFACT_SOURCE = "source/tests/fixtures/artifacts/Generic.Utils.KillProcess.yaml"
SERVICE_NAME = "mcp-velociraptor"
SERVICE_ACCOUNT = r"NT SERVICE\mcp-velociraptor"
SERVICE_SID = "S-1-5-80-4013063987-319881826-3712505395-1397637294-3432939775"
SERVICE_PYTHON = r"C:\mcp-velociraptor\.venv\Scripts\python.exe"
SERVICE_HOST = r"C:\mcp-velociraptor\tests\p05_service_host.py"
SERVICE_BINARY = f'"{SERVICE_PYTHON}" "{SERVICE_HOST}"'
ACL_PATHS = {
    'code_root': r'C:\mcp-velociraptor',
    'service_python': SERVICE_PYTHON,
    'service_host': SERVICE_HOST,
    'protected_env': r'C:\VelociraptorMCP\secrets\mcp-service.env',
    'api_client_config': r'C:\VelociraptorMCP\secrets\api_client_service.yaml',
    'download_root': r'C:\VelociraptorMCP\downloads',
    'runtime_logs': r'C:\mcp-velociraptor\Logs',
}
SERVICE_PORT = 28790
GUEST_FIXED_ADDRESS = "192.168.204.232"
HOST_FIXED_ADDRESS = "192.168.204.1"
RAW_OBSERVATIONS = frozenset(
    {
        "host_clock",
        "guest_identity",
        "fixture_static",
        "fixture_instance",
        "guest_processes",
        "host_processes",
        "parent_bindings",
        "dependencies",
        "service",
        "acl",
        "firewall",
        "resources",
    }
)
REF_KEYS = {"path", "size", "sha256"}
ENVELOPE_KEYS = {
    "schema_version",
    "kind",
    "observation",
    "workflow_id",
    "run_id",
    "restore_attempt_id",
    "host",
    "request",
    "started_at",
    "ended_at",
    "exit_status",
    "response",
}


@dataclass(frozen=True)
class _Transcript:
    observation: str
    scope: str
    computer_name: str
    started_at: datetime
    ended_at: datetime
    payload: dict[str, Any]
    stdout_bytes: bytes


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest_file(path: Path) -> str:
    return _digest_bytes(path.read_bytes())


def _require_nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReadyEvidenceError(f"{label} must be a non-empty string")
    return value


def _parse_utc(value: Any, label: str) -> datetime:
    text = _require_nonempty(value, label)
    try:
        instant = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReadyEvidenceError(f"{label} is not RFC3339") from exc
    if instant.tzinfo is None or instant.utcoffset() != timedelta(0):
        raise ReadyEvidenceError(f"{label} must be UTC")
    return instant.astimezone(UTC)


def _same_instant(left: Any, right: Any) -> bool:
    return _parse_utc(left, "left timestamp") == _parse_utc(right, "right timestamp")


def _same_millisecond(left: Any, right: Any) -> bool:
    return (
        _parse_utc(left, "left timestamp").isoformat(timespec="milliseconds")
        == _parse_utc(right, "right timestamp").isoformat(timespec="milliseconds")
    )


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _plain_file(root: Path, relative: str) -> Path:
    if (
        not isinstance(relative, str)
        or not relative
        or "\\" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        raise ReadyEvidenceError("ready evidence path must use contained POSIX components")
    relative_path = Path(relative)
    if relative_path.is_absolute() or PureWindowsPath(relative).drive:
        raise ReadyEvidenceError("ready evidence path escapes the activation bundle")
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise ReadyEvidenceError("activation bundle root is unavailable") from exc
    if stat.S_ISLNK(root_info.st_mode) or not root.is_dir():
        raise ReadyEvidenceError("activation bundle root is not a plain directory")
    current = root
    for part in relative_path.parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise ReadyEvidenceError(f"ready evidence is missing: {relative}") from exc
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ReadyEvidenceError("ready evidence contains a link or reparse point")
    if not stat.S_ISREG(current.lstat().st_mode):
        raise ReadyEvidenceError("ready evidence is not a regular file")
    return current


def _resolve_ref(bundle_root: Path, reference: Any, label: str) -> Path:
    if not isinstance(reference, dict) or set(reference) != REF_KEYS:
        raise ReadyEvidenceError(f"{label} must have exact path/size/sha256 keys")
    relative = _require_nonempty(reference.get("path"), f"{label}.path")
    if type(reference.get("size")) is not int or reference["size"] < 0:
        raise ReadyEvidenceError(f"{label}.size must be a non-negative integer")
    if not _valid_sha256(reference.get("sha256")):
        raise ReadyEvidenceError(f"{label}.sha256 is invalid")
    path = _plain_file(bundle_root, relative)
    if path.stat().st_size != reference["size"] or _digest_file(path) != reference["sha256"]:
        raise ReadyEvidenceError(f"{label} byte identity differs")
    return path


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReadyEvidenceError(f"{label} must be UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ReadyEvidenceError(f"{label} must be a JSON object")
    return value


def _forbid_summaries(value: Any, label: str) -> None:
    """Reject field names that turn a raw response into a client self-report."""
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ReadyEvidenceError(f"{label} has a non-string object key")
            if key.casefold() in {"expected", "passed", "ok"}:
                raise ReadyEvidenceError(f"{label} contains a prohibited summary field: {key}")
            _forbid_summaries(nested, f"{label}.{key}")
    elif isinstance(value, list):
        for position, nested in enumerate(value):
            _forbid_summaries(nested, f"{label}[{position}]")


def _load_transcript(
    path: Path,
    observation: str,
    ready: Mapping[str, Any],
    scope: str,
) -> _Transcript:
    document = _read_object(path, f"{observation} transcript")
    if set(document) != ENVELOPE_KEYS:
        raise ReadyEvidenceError(f"{observation} transcript keys are invalid")
    if (
        document.get("schema_version") != 1
        or document.get("kind") != "p05-ready-command-v1"
        or document.get("observation") != observation
        or document.get("workflow_id") != WORKFLOW_ID
        or document.get("run_id") != ready.get("run_id")
        or document.get("restore_attempt_id") != ready.get("restore_attempt_id")
    ):
        raise ReadyEvidenceError(f"{observation} transcript identity differs from ready")
    host = document.get("host")
    if not isinstance(host, dict) or set(host) != {"scope", "computer_name"}:
        raise ReadyEvidenceError(f"{observation} transcript host shape is invalid")
    computer_name = _require_nonempty(host.get("computer_name"), f"{observation}.host.computer_name")
    if host.get("scope") != scope:
        raise ReadyEvidenceError(f"{observation} transcript was collected on the wrong host")
    request = document.get("request")
    if not isinstance(request, dict) or set(request) != {"argv", "command_line"}:
        raise ReadyEvidenceError(f"{observation} request shape is invalid")
    if (
        not isinstance(request["argv"], list)
        or not request["argv"]
        or any(not isinstance(item, str) or not item for item in request["argv"])
    ):
        raise ReadyEvidenceError(f"{observation} request.argv is not a complete command")
    _require_nonempty(request["command_line"], f"{observation}.request.command_line")
    started_at = _parse_utc(document.get("started_at"), f"{observation}.started_at")
    ended_at = _parse_utc(document.get("ended_at"), f"{observation}.ended_at")
    if ended_at < started_at:
        raise ReadyEvidenceError(f"{observation} command ended before it began")
    exit_status = document.get("exit_status")
    if not isinstance(exit_status, dict) or set(exit_status) != {"code"} or type(exit_status["code"]) is not int:
        raise ReadyEvidenceError(f"{observation} lacks an actual command exit code")
    if exit_status["code"] != 0:
        raise ReadyEvidenceError(f"{observation} command exit code is non-zero")
    response = document.get("response")
    response_keys = {
        "stdout",
        "stdout_size",
        "stdout_sha256",
        "stderr",
        "stderr_size",
        "stderr_sha256",
    }
    if not isinstance(response, dict) or set(response) != response_keys:
        raise ReadyEvidenceError(f"{observation} response does not retain complete stdout/stderr")
    for stream in ("stdout", "stderr"):
        value = response.get(stream)
        size = response.get(f"{stream}_size")
        checksum = response.get(f"{stream}_sha256")
        if not isinstance(value, str) or type(size) is not int or size < 0 or not _valid_sha256(checksum):
            raise ReadyEvidenceError(f"{observation} {stream} identity is invalid")
        raw = value.encode("utf-8")
        if len(raw) != size or _digest_bytes(raw) != checksum:
            raise ReadyEvidenceError(f"{observation} {stream} bytes differ from their identity")
    stdout = response["stdout"]
    if not stdout:
        raise ReadyEvidenceError(f"{observation} stdout is empty; it is not a raw observation")
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ReadyEvidenceError(f"{observation} stdout is not the complete JSON response") from exc
    if not isinstance(payload, dict):
        raise ReadyEvidenceError(f"{observation} stdout response must be a JSON object")
    _forbid_summaries(payload, f"{observation}.stdout")
    return _Transcript(
        observation=observation,
        scope=scope,
        computer_name=computer_name,
        started_at=started_at,
        ended_at=ended_at,
        payload=payload,
        stdout_bytes=stdout.encode("utf-8"),
    )


def _windows_path_equal(left: Any, right: Any) -> bool:
    return isinstance(left, str) and isinstance(right, str) and left.replace("/", "\\").casefold() == right.replace("/", "\\").casefold()


def _windows_join(root: str, relative: str) -> str:
    return str(PureWindowsPath(root) / PureWindowsPath(relative.replace("/", "\\")))


def _require_exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ReadyEvidenceError(f"{label} keys are invalid")
    return value


def _verify_guest_identity(transcript: _Transcript) -> tuple[datetime, datetime, datetime]:
    payload = _require_exact_keys(
        transcript.payload,
        {"computer_name", "guest_utc", "api_client_rows"},
        "guest_identity response",
    )
    if payload["computer_name"] != GUEST_COMPUTER_NAME:
        raise ReadyEvidenceError("guest identity hostname differs")
    guest_time = _parse_utc(payload["guest_utc"], "guest identity UTC")
    clients = payload["api_client_rows"]
    if not isinstance(clients, list) or len(clients) != 1:
        raise ReadyEvidenceError("API did not return exactly one Windows client")
    client = _require_exact_keys(clients[0], {"client_id", "os", "hostname"}, "API client row")
    if (
        client["client_id"] != WINDOWS_CLIENT_ID
        or not isinstance(client["os"], str)
        or client["os"].casefold() != "windows"
        or client["hostname"] != GUEST_COMPUTER_NAME
    ):
        raise ReadyEvidenceError("API unique Windows client differs from the frozen guest identity")
    return transcript.started_at, transcript.ended_at, guest_time


def _verify_host_clock(
    transcript: _Transcript,
    guest_started: datetime,
    guest_ended: datetime,
    guest_time: datetime,
) -> None:
    payload = _require_exact_keys(
        transcript.payload,
        {"before_guest_identity_utc", "after_guest_identity_utc"},
        "host_clock response",
    )
    before = _parse_utc(payload["before_guest_identity_utc"], "host clock before")
    after = _parse_utc(payload["after_guest_identity_utc"], "host clock after")
    if not (transcript.started_at <= before <= guest_started <= guest_ended <= after <= transcript.ended_at):
        raise ReadyEvidenceError("host clock does not bracket the actual guest identity request")
    if not (before - timedelta(seconds=120) <= guest_time <= after + timedelta(seconds=120)):
        raise ReadyEvidenceError("guest UTC is outside the host UTC interval extended by 120 seconds")


def _load_fixture_spec(bundle_root: Path) -> tuple[dict[str, Any], str]:
    path = _plain_file(bundle_root, FIXTURE_SPEC_SOURCE)
    raw = path.read_bytes()
    try:
        spec = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadyEvidenceError("frozen fixture spec source is not UTF-8 JSON") from exc
    if not isinstance(spec, dict) or spec.get("schema_version") != 1:
        raise ReadyEvidenceError("frozen fixture spec source shape is invalid")
    return spec, _digest_bytes(raw)


def _verify_fixture_instance(
    transcript: _Transcript,
    spec: Mapping[str, Any],
    spec_sha256: str,
) -> dict[str, Any]:
    instance = transcript.payload
    expected_keys = {
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
    _require_exact_keys(instance, expected_keys, "fixture instance")
    if (
        instance["schema_version"] != 1
        or instance["fixture_spec_sha256"] != spec_sha256
        or instance["workflow_id"] != WORKFLOW_ID
        or not isinstance(instance["attempt_id"], str)
        or not instance["attempt_id"].startswith("p05-")
        or instance["hostname"] != GUEST_COMPUTER_NAME
        or not _windows_path_equal(instance["fixture_root"], FIXTURE_ROOT)
    ):
        raise ReadyEvidenceError("fixture instance root identity differs")
    owner = _require_exact_keys(instance["ownership_marker"], {"path", "workflow_id"}, "fixture owner")
    if owner["workflow_id"] != WORKFLOW_ID or not _windows_path_equal(owner["path"], _windows_join(FIXTURE_ROOT, ".p05-owner.json")):
        raise ReadyEvidenceError("fixture ownership marker differs")
    spec_files = spec.get("files")
    if not isinstance(spec_files, list) or not isinstance(instance["files"], list) or len(spec_files) != len(instance["files"]):
        raise ReadyEvidenceError("fixture files do not retain the frozen spec rows")
    for position, (expected, observed) in enumerate(zip(spec_files, instance["files"], strict=True)):
        if not isinstance(expected, dict):
            raise ReadyEvidenceError("fixture spec file row is invalid")
        row = _require_exact_keys(observed, {"path", "relative_path", "sha256", "size"}, f"fixture file {position}")
        if (
            row["relative_path"] != expected.get("path")
            or row["sha256"] != expected.get("sha256")
            or row["size"] != expected.get("size")
            or not _windows_path_equal(row["path"], _windows_join(FIXTURE_ROOT, str(expected.get("path"))))
        ):
            raise ReadyEvidenceError("fixture instance file differs from frozen spec")
    registry = _require_exact_keys(instance["registry"], {"path", "values"}, "fixture registry")
    expected_registry = spec.get("registry")
    if not isinstance(expected_registry, dict):
        raise ReadyEvidenceError("fixture spec registry is invalid")
    expected_registry_path = str(expected_registry.get("key_template", "")).replace("{workflow_id}", WORKFLOW_ID)
    values = expected_registry.get("values")
    if not isinstance(values, dict) or not isinstance(registry["values"], dict):
        raise ReadyEvidenceError("fixture registry values are invalid")
    expected_values = {
        key: value.replace("{attempt_id}", instance["attempt_id"]).replace("{workflow_id}", WORKFLOW_ID)
        if isinstance(value, str)
        else value
        for key, value in values.items()
    }
    if not _windows_path_equal(registry["path"], expected_registry_path) or registry["values"] != expected_values:
        raise ReadyEvidenceError("fixture registry readback differs from frozen spec")
    event = _require_exact_keys(instance["event"], {"log", "source", "event_id", "message", "record_id"}, "fixture event")
    expected_event = spec.get("event")
    if (
        not isinstance(expected_event, dict)
        or event["log"] != "Application"
        or event["source"] != expected_event.get("source")
        or event["event_id"] != expected_event.get("event_id")
        or event["message"] != str(expected_event.get("message_template", "")).replace("{workflow_id}", WORKFLOW_ID).replace("{attempt_id}", instance["attempt_id"])
        or type(event["record_id"]) is not int
        or event["record_id"] < 0
    ):
        raise ReadyEvidenceError("fixture event readback differs from frozen spec")
    task = _require_exact_keys(instance["task"], {"path", "name", "enabled", "triggers", "execute", "arguments"}, "fixture task")
    expected_task = spec.get("task")
    if (
        not isinstance(expected_task, dict)
        or task["path"] != expected_task.get("path")
        or task["name"] != expected_task.get("name")
        or task["enabled"] is not expected_task.get("enabled")
        or task["triggers"] != expected_task.get("triggers")
        or task["execute"] != r"%SystemRoot%\System32\cmd.exe"
        or task["arguments"] != "/d /c exit 0"
    ):
        raise ReadyEvidenceError("fixture task readback differs from frozen inert task")
    process = _require_exact_keys(
        instance["process"],
        {"pid", "creation_time_utc", "token", "interpreter", "command_line", "sleep_seconds"},
        "fixture process",
    )
    if (
        type(process["pid"]) is not int
        or process["pid"] <= 4
        or process["token"] != f"{WORKFLOW_ID}|{instance['attempt_id']}"
        or not isinstance(process["interpreter"], str)
        or not process["interpreter"].casefold().endswith(r"\.venv\scripts\python.exe")
        or not isinstance(process["command_line"], str)
        or any(token not in process["command_line"] for token in (WORKFLOW_ID, instance["attempt_id"], "import time; time.sleep(86400)"))
        or process["sleep_seconds"] != spec.get("process", {}).get("sleep_seconds")
    ):
        raise ReadyEvidenceError("fixture process instance differs from the fixed Python sleep contract")
    _parse_utc(process["creation_time_utc"], "fixture process creation time")
    return instance


def _parse_guest_processes(transcript: _Transcript) -> tuple[datetime, dict[int, dict[str, Any]]]:
    payload = _require_exact_keys(transcript.payload, {"captured_at_utc", "processes"}, "guest process response")
    captured_at = _parse_utc(payload["captured_at_utc"], "guest process capture time")
    if not (transcript.started_at <= captured_at <= transcript.ended_at):
        raise ReadyEvidenceError("guest process capture time is outside its command interval")
    rows = payload["processes"]
    if not isinstance(rows, list) or not rows:
        raise ReadyEvidenceError("guest process response has no actual process rows")
    fields = {"ProcessId", "ParentProcessId", "Name", "ExecutablePath", "CreationDate", "CommandLine"}
    by_pid: dict[int, dict[str, Any]] = {}
    for position, candidate in enumerate(rows):
        row = _require_exact_keys(candidate, fields, f"guest process row {position}")
        pid, parent = row["ProcessId"], row["ParentProcessId"]
        if type(pid) is not int or pid < 0 or type(parent) is not int or parent < 0 or pid in by_pid:
            raise ReadyEvidenceError("guest process PID is invalid or duplicated")
        if not isinstance(row["Name"], str) or not row["Name"]:
            raise ReadyEvidenceError("guest process name is missing")
        if row["ExecutablePath"] is not None and not isinstance(row["ExecutablePath"], str):
            raise ReadyEvidenceError("guest process executable is invalid")
        if row["CommandLine"] is not None and not isinstance(row["CommandLine"], str):
            raise ReadyEvidenceError("guest process command line is invalid")
        if pid in {0, 4}:
            # Win32_Process reports no creation instant for the kernel Idle
            # process (and some builds' System entry); the spec keeps both in
            # the protected set, so a missing instant is not a defect there.
            if row["CreationDate"] is not None:
                _parse_utc(row["CreationDate"], f"guest process {pid} creation time")
        else:
            _parse_utc(row["CreationDate"], f"guest process {pid} creation time")
        by_pid[pid] = row
    return captured_at, by_pid


def _process_identity_from_record(value: Any, label: str) -> dict[str, Any]:
    return _require_exact_keys(
        value,
        {"ProcessId", "ParentProcessId", "Name", "ExecutablePath", "CommandLine", "CreationDate"},
        label,
    )


def _same_process_identity(
    observed: Mapping[str, Any],
    recorded: Mapping[str, Any],
    label: str,
    *,
    millisecond_creation: bool = False,
) -> None:
    for key in ("ProcessId", "ParentProcessId", "Name", "ExecutablePath", "CommandLine"):
        if observed.get(key) != recorded.get(key):
            raise ReadyEvidenceError(f"{label} differs at {key}; PID reuse or transcript mixing is possible")
    equal = _same_millisecond if millisecond_creation else _same_instant
    if not equal(observed.get("CreationDate"), recorded.get("CreationDate")):
        raise ReadyEvidenceError(f"{label} creation time differs; PID reuse is possible")


def _verify_parent_bindings(
    transcript: _Transcript,
    bundle_root: Path,
    fixture_instance: Mapping[str, Any],
    fixture_stdout: bytes,
    process_rows: Mapping[int, dict[str, Any]],
    process_captured_at: datetime,
) -> set[int]:
    payload = _require_exact_keys(transcript.payload, {"source_sha256", "launch_records"}, "parent binding response")
    source_path = _plain_file(bundle_root, PROCESS_PARENT_SOURCE)
    source_sha256 = _digest_file(source_path)
    if payload["source_sha256"] != source_sha256:
        raise ReadyEvidenceError("parent binding response source hash differs from frozen p05_process_parent")
    records = payload["launch_records"]
    if not isinstance(records, list) or len(records) != 3:
        raise ReadyEvidenceError("parent bindings require the three fixed frontend/client/fixture launch records")
    by_role: dict[str, dict[str, Any]] = {}
    direct_pids: set[int] = set()
    approved_argv_pids: set[int] = {int(fixture_instance["process"]["pid"])}
    for position, candidate in enumerate(records):
        if not isinstance(candidate, dict) or candidate.get("role") not in {"frontend", "client", "fixture"}:
            raise ReadyEvidenceError("parent binding role is invalid")
        role = candidate["role"]
        keys = {
            "role", "parent_pid", "parent_parent_pid", "argv", "started_at", "source_sha256",
            "child_pid", "parent_identity", "child_identity", "identity_observed",
        }
        if role == "fixture":
            keys.add("fixture_binding")
        _require_exact_keys(candidate, keys, f"parent binding {position}")
        if role in by_role or candidate["source_sha256"] != source_sha256 or candidate["identity_observed"] is not True:
            raise ReadyEvidenceError("parent binding role is duplicated or lacks observed frozen-source identity")
        if (
            not isinstance(candidate["argv"], list)
            or not candidate["argv"]
            or any(not isinstance(part, str) or not part for part in candidate["argv"])
            or type(candidate["parent_pid"]) is not int
            or type(candidate["parent_parent_pid"]) is not int
            or type(candidate["child_pid"]) is not int
        ):
            raise ReadyEvidenceError("parent binding launcher fields are invalid")
        started_at = _parse_utc(candidate["started_at"], f"{role} launcher started_at")
        parent = _process_identity_from_record(candidate["parent_identity"], f"{role} parent identity")
        child = _process_identity_from_record(candidate["child_identity"], f"{role} child identity")
        if (
            parent["ProcessId"] != candidate["parent_pid"]
            or parent["ParentProcessId"] != candidate["parent_parent_pid"]
            or child["ProcessId"] != candidate["child_pid"]
            or child["ParentProcessId"] != parent["ProcessId"]
            or child["CommandLine"] != subprocess.list2cmdline(candidate["argv"])
            or _parse_utc(parent["CreationDate"], f"{role} parent creation") > started_at
            or _parse_utc(child["CreationDate"], f"{role} child creation") < started_at
            or _parse_utc(parent["CreationDate"], f"{role} parent creation") > _parse_utc(child["CreationDate"], f"{role} child creation")
        ):
            raise ReadyEvidenceError("parent binding launcher identity or creation order differs")
        if started_at > process_captured_at:
            raise ReadyEvidenceError("parent binding was recorded after the guest process snapshot")
        for identity, identity_label in ((parent, "parent"), (child, "child")):
            pid = identity["ProcessId"]
            if pid in direct_pids or pid not in process_rows:
                raise ReadyEvidenceError("parent binding PID is missing or reused across launch records")
            _same_process_identity(process_rows[pid], identity, f"{role} {identity_label} process")
            direct_pids.add(pid)
            approved_argv_pids.add(pid)
        if parent["ParentProcessId"] not in process_rows:
            raise ReadyEvidenceError("parent binding parent process is absent from the raw guest snapshot")
        if _parse_utc(process_rows[parent["ParentProcessId"]]["CreationDate"], "launcher parent creation") > _parse_utc(parent["CreationDate"], "launcher creation"):
            raise ReadyEvidenceError("parent binding parent creation is newer than the launcher")
        by_role[role] = candidate
    if set(by_role) != {"frontend", "client", "fixture"}:
        raise ReadyEvidenceError("parent bindings omit a fixed role")
    fixture_record = by_role["fixture"]
    binding = _require_exact_keys(
        fixture_record["fixture_binding"],
        {"instance_sha256", "process_identity", "preparer_identity"},
        "fixture parent binding",
    )
    if binding["instance_sha256"] != _digest_bytes(fixture_stdout):
        raise ReadyEvidenceError("fixture parent binding does not bind the raw fixture instance bytes")
    target = _process_identity_from_record(binding["process_identity"], "fixture target identity")
    preparer = _process_identity_from_record(binding["preparer_identity"], "fixture preparer identity")
    fixture_child = _process_identity_from_record(fixture_record["child_identity"], "fixture launcher child")
    if target["ProcessId"] != fixture_instance["process"]["pid"] or target["ParentProcessId"] != fixture_child["ProcessId"]:
        raise ReadyEvidenceError("fixture target is not bound to this PowerShell preparer")
    _same_process_identity(preparer, fixture_child, "fixture preparer startup identity")
    if target["ProcessId"] not in process_rows:
        raise ReadyEvidenceError("fixture target is absent from the raw guest snapshot")
    _same_process_identity(process_rows[target["ProcessId"]], target, "fixture target process", millisecond_creation=True)
    process = fixture_instance["process"]
    if (
        target["CommandLine"] != process["command_line"]
        or not _windows_path_equal(target["ExecutablePath"], process["interpreter"])
        or not _same_millisecond(target["CreationDate"], process["creation_time_utc"])
        or any(token not in target["CommandLine"] for token in (WORKFLOW_ID, fixture_instance["attempt_id"]))
    ):
        raise ReadyEvidenceError("fixture target full argv, interpreter, token, or creation time differs")
    approved_argv_pids.add(target["ProcessId"])
    for pid, row in process_rows.items():
        if row["CommandLine"] is not None and pid not in approved_argv_pids:
            raise ReadyEvidenceError("guest process transcript exposes a non-approved full command line")
    return approved_argv_pids


def _verify_guest_process_semantics(
    fixture_instance: Mapping[str, Any],
    spec: Mapping[str, Any],
    process_rows: Mapping[int, dict[str, Any]],
    captured_at: datetime,
    approved_argv_pids: set[int],
) -> None:
    target_pid = fixture_instance["process"]["pid"]
    protected = {0, 4}
    for pid in approved_argv_pids - {target_pid}:
        protected.add(pid)
        protected.add(process_rows[pid]["ParentProcessId"])
    if target_pid in protected or not protected.issubset(process_rows):
        raise ReadyEvidenceError("guest protected process set is incomplete or includes the kill target")
    for pid in protected - {0}:
        parent = process_rows[pid]["ParentProcessId"]
        if parent not in process_rows:
            raise ReadyEvidenceError("guest protected process lacks an observed parent")
        child_creation = process_rows[pid]["CreationDate"]
        parent_creation = process_rows[parent]["CreationDate"]
        if (
            child_creation is not None
            and parent_creation is not None
            and _parse_utc(parent_creation, "protected parent creation")
            > _parse_utc(child_creation, "protected process creation")
        ):
            raise ReadyEvidenceError("guest protected process parent identity shows possible PID reuse")
    target_creation = _parse_utc(fixture_instance["process"]["creation_time_utc"], "fixture target creation")
    sleep_seconds = spec.get("process", {}).get("sleep_seconds")
    minimum_remaining = spec.get("process", {}).get("minimum_remaining_seconds_at_snapshot")
    if type(sleep_seconds) is not int or type(minimum_remaining) is not int:
        raise ReadyEvidenceError("fixture spec process lifetime fields are invalid")
    if captured_at < target_creation or captured_at > target_creation + timedelta(seconds=sleep_seconds - minimum_remaining):
        raise ReadyEvidenceError("fixture process does not retain the required 7200-second lifetime at ready capture")


def _verify_host_processes(
    transcript: _Transcript,
    report: Mapping[str, Any],
) -> None:
    payload = _require_exact_keys(transcript.payload, {"captured_at_utc", "processes"}, "host process response")
    captured_at = _parse_utc(payload["captured_at_utc"], "host process capture time")
    if not (transcript.started_at <= captured_at <= transcript.ended_at):
        raise ReadyEvidenceError("host process capture time is outside its command interval")
    rows = payload["processes"]
    if not isinstance(rows, list) or len(rows) < 2:
        raise ReadyEvidenceError("host process response lacks runner and parent rows")
    fields = {"pid", "parent_pid", "creation_time_utc", "executable", "executable_sha256", "argv"}
    by_pid: dict[int, dict[str, Any]] = {}
    for position, candidate in enumerate(rows):
        row = _require_exact_keys(candidate, fields, f"host process row {position}")
        if (
            type(row["pid"]) is not int
            or row["pid"] <= 0
            or type(row["parent_pid"]) is not int
            or row["parent_pid"] <= 0
            or row["pid"] in by_pid
            or not isinstance(row["executable"], str)
            or not row["executable"]
            or not _valid_sha256(row["executable_sha256"])
            or not isinstance(row["argv"], str)
            or not row["argv"]
        ):
            raise ReadyEvidenceError("host process identity is invalid")
        _parse_utc(row["creation_time_utc"], f"host process {row['pid']} creation")
        by_pid[row["pid"]] = row
    runner = report.get("runner")
    if not isinstance(runner, dict) or set(runner) != {"pid", "process_start_time_utc", "executable_sha256"}:
        raise ReadyEvidenceError("formal report lacks the exact runner identity needed for raw host joining")
    pid = runner.get("pid")
    if type(pid) is not int or pid not in by_pid:
        raise ReadyEvidenceError("formal report runner PID is absent from host raw processes")
    row = by_pid[pid]
    if (
        row["creation_time_utc"] != runner.get("process_start_time_utc")
        or row["executable_sha256"] != runner.get("executable_sha256")
        or row["parent_pid"] not in by_pid
    ):
        raise ReadyEvidenceError("host runner raw identity differs from the formal report")
    parent = by_pid[row["parent_pid"]]
    if _parse_utc(parent["creation_time_utc"], "host runner parent creation") > _parse_utc(row["creation_time_utc"], "host runner creation"):
        raise ReadyEvidenceError("host runner parent identity shows possible PID reuse")
    if captured_at < _parse_utc(row["creation_time_utc"], "host runner creation"):
        raise ReadyEvidenceError("host runner was not alive at its raw process observation")


def _require_plain_windows_path(value: Any, label: str) -> str:
    path = _require_nonempty(value, label)
    parsed = PureWindowsPath(path)
    canonical = str(parsed)
    if (
        not parsed.drive
        or not parsed.root
        or path.startswith("\\\\")
        or any(character in path for character in ("\x00", "\r", "\n", "\"", "'"))
        or any(part in {".", ".."} for part in parsed.parts)
        or path.rstrip("\\").casefold() != canonical.rstrip("\\").casefold()
    ):
        raise ReadyEvidenceError(f"{label} is not a canonical contained local Windows path")
    return path


def _verify_fixture_static(
    transcript: _Transcript,
    spec: Mapping[str, Any],
    spec_sha256: str,
    fixture: Mapping[str, Any],
    fixture_stdout: bytes,
) -> None:
    payload = _require_exact_keys(
        transcript.payload,
        {
            "fixture_spec_sha256",
            "fixture_instance",
            "fixture_root",
            "ownership_marker",
            "files",
            "registry",
            "event_rows",
            "task",
        },
        "fixture static response",
    )
    if payload["fixture_spec_sha256"] != spec_sha256:
        raise ReadyEvidenceError("fixture static spec hash differs from frozen source")
    instance_file = _require_exact_keys(
        payload["fixture_instance"],
        {"path", "is_reparse_point", "file_type", "sha256"},
        "fixture static instance file",
    )
    if (
        not _windows_path_equal(instance_file["path"], _windows_join(FIXTURE_ROOT, "fixture-instance-v1.json"))
        or instance_file["is_reparse_point"] is not False
        or instance_file["file_type"] != "file"
        or instance_file["sha256"] != _digest_bytes(fixture_stdout)
    ):
        raise ReadyEvidenceError("fixture static instance file identity differs")
    root = _require_exact_keys(
        payload["fixture_root"],
        {"path", "is_reparse_point", "file_type"},
        "fixture static root",
    )
    if (
        not _windows_path_equal(root["path"], FIXTURE_ROOT)
        or root["is_reparse_point"] is not False
        or root["file_type"] != "directory"
    ):
        raise ReadyEvidenceError("fixture static root is not the owned plain directory")
    marker = _require_exact_keys(
        payload["ownership_marker"],
        {"path", "is_reparse_point", "file_type", "content"},
        "fixture static ownership marker",
    )
    if (
        not _windows_path_equal(marker["path"], _windows_join(FIXTURE_ROOT, ".p05-owner.json"))
        or marker["is_reparse_point"] is not False
        or marker["file_type"] != "file"
        or marker["content"] != {"schema_version": 1, "workflow_id": WORKFLOW_ID}
    ):
        raise ReadyEvidenceError("fixture static ownership marker differs")
    files = payload["files"]
    spec_files = spec.get("files")
    instance_files = fixture.get("files")
    if not isinstance(files, list) or not isinstance(spec_files, list) or not isinstance(instance_files, list):
        raise ReadyEvidenceError("fixture static files are not complete rows")
    if len(files) != len(spec_files) or len(files) != len(instance_files):
        raise ReadyEvidenceError("fixture static file count differs from fixture spec")
    for position, (observed, expected, instance_row) in enumerate(zip(files, spec_files, instance_files, strict=True)):
        row = _require_exact_keys(
            observed,
            {"path", "relative_path", "size", "sha256", "is_reparse_point", "file_type"},
            f"fixture static file {position}",
        )
        if not isinstance(expected, dict) or not isinstance(instance_row, dict):
            raise ReadyEvidenceError("fixture static frozen file row is invalid")
        if (
            row["relative_path"] != expected.get("path")
            or row["size"] != expected.get("size")
            or row["sha256"] != expected.get("sha256")
            or row["path"] != instance_row.get("path")
            or row["relative_path"] != instance_row.get("relative_path")
            or row["size"] != instance_row.get("size")
            or row["sha256"] != instance_row.get("sha256")
            or not _windows_path_equal(row["path"], _windows_join(FIXTURE_ROOT, str(expected.get("path"))))
            or row["is_reparse_point"] is not False
            or row["file_type"] != "file"
        ):
            raise ReadyEvidenceError("fixture static file differs from spec, instance, or plain-file contract")
    if payload["registry"] != fixture.get("registry"):
        raise ReadyEvidenceError("fixture static registry readback differs from fixture instance")
    event_rows = payload["event_rows"]
    if not isinstance(event_rows, list) or len(event_rows) != 1 or event_rows[0] != fixture.get("event"):
        raise ReadyEvidenceError("fixture static event is not the one expected raw event row")
    if payload["task"] != fixture.get("task"):
        raise ReadyEvidenceError("fixture static task readback differs from fixture instance")


def _load_dependency_manifest(bundle_root: Path) -> tuple[dict[str, Any], str]:
    path = _plain_file(bundle_root, DEPENDENCY_MANIFEST_SOURCE)
    raw = path.read_bytes()
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadyEvidenceError("frozen dependency manifest source is not UTF-8 JSON") from exc
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "dependencies", "triage_artifact"}:
        raise ReadyEvidenceError("frozen dependency manifest source shape is invalid")
    if manifest["schema_version"] != 1 or not isinstance(manifest["dependencies"], list) or not isinstance(manifest["triage_artifact"], dict):
        raise ReadyEvidenceError("frozen dependency manifest source values are invalid")
    names = {item.get("name") for item in manifest["dependencies"] if isinstance(item, dict)}
    if names != {"Autorun_386", "Autorun_amd64"} or len(manifest["dependencies"]) != 2:
        raise ReadyEvidenceError("frozen dependency manifest does not name the locked tools")
    return manifest, _digest_bytes(raw)


def _manifest_dependency(manifest: Mapping[str, Any], name: str) -> dict[str, Any]:
    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, list):  # already checked, preserves a local error boundary
        raise ReadyEvidenceError("frozen dependency manifest dependencies are invalid")
    matches = [item for item in dependencies if isinstance(item, dict) and item.get("name") == name]
    if len(matches) != 1:
        raise ReadyEvidenceError(f"frozen dependency manifest lacks unique {name}")
    return matches[0]


def _empty_inventory_value(value: Any) -> bool:
    return value in (None, "", [], {})


def _verify_dependencies(
    transcript: _Transcript,
    bundle_root: Path,
) -> None:
    payload = _require_exact_keys(
        transcript.payload,
        {
            "dependency_manifest_sha256",
            "inventory_rows",
            "local_public_bytes",
            "locked_files",
            "artifact_rows",
        },
        "dependencies response",
    )
    manifest, manifest_sha256 = _load_dependency_manifest(bundle_root)
    if payload["dependency_manifest_sha256"] != manifest_sha256:
        raise ReadyEvidenceError("dependencies response manifest hash differs from frozen source")
    inventory_rows = payload["inventory_rows"]
    inventory_fields = {
        "name", "artifact", "filename", "version", "hash", "admin_override",
        "materialize", "serve_locally", "serve_url", "filestore_path", "invalid_hash",
    }
    if not isinstance(inventory_rows, list) or len(inventory_rows) != 4:
        raise ReadyEvidenceError("dependencies inventory response lacks all locked and predecessor rows")
    grouped: dict[str, list[dict[str, Any]]] = {}
    predecessor = {
        "Autorun_386": {"artifact": "Windows.Sysinternals.Autoruns", "filename": "autorunsc.exe", "serve_locally": True},
        "Autorun_amd64": {"artifact": "Notebooks.Demo", "filename": "autorunsc64.exe", "serve_locally": True},
    }
    for position, candidate in enumerate(inventory_rows):
        row = _require_exact_keys(candidate, inventory_fields, f"dependencies inventory row {position}")
        name = row["name"]
        if name not in predecessor or type(row["admin_override"]) is not bool or type(row["materialize"]) is not bool or type(row["serve_locally"]) is not bool:
            raise ReadyEvidenceError("dependencies inventory row has an unknown identity or invalid actual flags")
        grouped.setdefault(name, []).append(row)
    for name, rows in grouped.items():
        if len(rows) != 2:
            raise ReadyEvidenceError("dependencies inventory did not retain one predecessor and one override")
        prior = [row for row in rows if row["admin_override"] is False]
        target = [row for row in rows if row["admin_override"] is True]
        if len(prior) != 1 or len(target) != 1:
            raise ReadyEvidenceError("dependencies inventory override identity is ambiguous")
        old = prior[0]
        expected_old = predecessor[name]
        if (
            any(old[key] != value for key, value in expected_old.items())
            or old["materialize"] is not False
            or any(not _empty_inventory_value(old[key]) for key in ("version", "hash", "invalid_hash"))
            or not isinstance(old["serve_url"], str) or not old["serve_url"]
            or not isinstance(old["filestore_path"], str) or not old["filestore_path"]
        ):
            raise ReadyEvidenceError("dependencies predecessor inventory row differs from the locked baseline")
        expected = _manifest_dependency(manifest, name)
        selected = target[0]
        if (
            selected["version"] != expected.get("version")
            or selected["filename"] != expected.get("filename")
            or selected["hash"] != expected.get("sha256")
            or selected["materialize"] is not False
            or selected["serve_locally"] is not True
            or re.fullmatch(r"https://localhost:8000/public/[0-9a-f]{64}", str(selected["serve_url"])) is None
            or not isinstance(selected["filestore_path"], str)
            or not selected["filestore_path"]
            or not _empty_inventory_value(selected["invalid_hash"])
        ):
            raise ReadyEvidenceError("dependencies selected inventory row differs from the locked manifest")
    if set(grouped) != set(predecessor):
        raise ReadyEvidenceError("dependencies inventory tool set differs from the locked manifest")
    # probe_rows were removed from the collector: inventory_get(probe=TRUE)
    # issues an actual request to the tool's upstream URL (a public GitHub
    # address for the etl2pcapng predecessor), which violates the
    # zero-public-request invariant; tool resolvability is proven by the
    # local_public_bytes rows re-verified below (PLAN-CHANGE-013 A corollary).
    for field, label in (("local_public_bytes", "local public bytes"), ("locked_files", "locked file")):
        rows = payload[field]
        if not isinstance(rows, list) or len(rows) != 2:
            raise ReadyEvidenceError(f"dependencies {label} response lacks all locked tools")
        names: set[str] = set()
        for position, candidate in enumerate(rows):
            keys = {"name", "url", "size", "sha256"} if field == "local_public_bytes" else {"name", "path", "size", "sha256"}
            row = _require_exact_keys(candidate, keys, f"dependencies {label} {position}")
            name = row["name"]
            expected = _manifest_dependency(manifest, name) if isinstance(name, str) and name in predecessor else None
            if expected is None or name in names or row["size"] != expected.get("size") or row["sha256"] != expected.get("sha256"):
                raise ReadyEvidenceError(f"dependencies {label} identity differs from the locked manifest")
            if field == "local_public_bytes":
                # The public URL digest is the server's internal filestore key
                # (the artifact definition's expected hash), not the stored
                # content sha; the bytes themselves are pinned by sha256 below.
                if re.fullmatch(r"https://localhost:8000/public/[0-9a-f]{64}", str(row["url"])) is None:
                    raise ReadyEvidenceError("dependencies local public URL is not the actual locked local source")
            elif not _windows_path_equal(row["path"], _windows_join(r"C:\\VelociraptorMCP\\dependencies\\p05\\locked", str(expected.get("filename")))):
                raise ReadyEvidenceError("dependencies locked file path differs from the fixed locked root")
            names.add(name)
        if names != set(predecessor):
            raise ReadyEvidenceError(f"dependencies {label} tool set differs from the locked manifest")
    artifact_rows = payload["artifact_rows"]
    if not isinstance(artifact_rows, list) or len(artifact_rows) != 2:
        raise ReadyEvidenceError("dependencies artifact response lacks both locked artifact definitions")
    frozen_kill = _plain_file(bundle_root, KILL_ARTIFACT_SOURCE).read_bytes()
    expected_artifacts = {
        "Windows.Triage.Targets": (manifest["triage_artifact"].get("yaml_size"), manifest["triage_artifact"].get("yaml_sha256")),
        "Generic.Utils.KillProcess": (len(frozen_kill), _digest_bytes(frozen_kill)),
    }
    seen_artifacts: set[str] = set()
    for position, candidate in enumerate(artifact_rows):
        row = _require_exact_keys(
            candidate,
            {"name", "type", "raw", "parameters", "sources", "required_permissions"},
            f"dependencies artifact row {position}",
        )
        name = row["name"]
        expected = expected_artifacts.get(name) if isinstance(name, str) else None
        if (
            expected is None
            or name in seen_artifacts
            # The server reports the artifact type in lowercase; the check is
            # about the artifact being a client artifact, not its casing.
            or str(row["type"]).upper() != "CLIENT"
            or not isinstance(row["raw"], str)
            or len(row["raw"].encode("utf-8")) != expected[0]
            or _digest_bytes(row["raw"].encode("utf-8")) != expected[1]
            or not isinstance(row["parameters"], list)
            or not isinstance(row["sources"], list)
            or not isinstance(row["required_permissions"], list)
        ):
            raise ReadyEvidenceError("dependencies artifact raw definition differs from the locked source")
        seen_artifacts.add(name)
    if seen_artifacts != set(expected_artifacts):
        raise ReadyEvidenceError("dependencies artifact set differs from the locked manifest")


def _verify_service(transcript: _Transcript) -> dict[str, Any]:
    payload = _require_exact_keys(transcript.payload, {"service_rows", "service_process_rows", "listeners", "service_python_base"}, "service response")
    rows = payload["service_rows"]
    service_fields = {"name", "state", "start_name", "start_mode", "process_id", "path_name"}
    if not isinstance(rows, list) or len(rows) != 1:
        raise ReadyEvidenceError("service response does not retain one actual service row")
    service = _require_exact_keys(rows[0], service_fields, "service row")
    if (
        service["name"] != SERVICE_NAME
        or service["state"] != "Running"
        or service["start_name"] != SERVICE_ACCOUNT
        or service["start_mode"] not in {"Auto", "Manual"}
        or type(service["process_id"]) is not int
        or service["process_id"] <= 4
        or service["path_name"] != SERVICE_BINARY
    ):
        raise ReadyEvidenceError("service account, state, or process identity differs from the formal service contract")
    processes = payload["service_process_rows"]
    process_fields = {"ProcessId", "ParentProcessId", "Name", "ExecutablePath", "CreationDate", "CommandLine", "executable_sha256"}
    if not isinstance(processes, list) or len(processes) != 1:
        raise ReadyEvidenceError("service response does not retain one actual service process")
    process = _require_exact_keys(processes[0], process_fields, "service process row")
    # The venv python.exe is a launcher: the live service process runs the base
    # interpreter declared in the deployment's pyvenv.cfg. The command line is
    # still pinned to the exact service binary string.
    base_python = payload.get("service_python_base")
    if not isinstance(base_python, str) or not base_python:
        raise ReadyEvidenceError("service response lacks the declared venv base interpreter")
    if (
        process["ProcessId"] != service["process_id"]
        or type(process["ParentProcessId"]) is not int
        or process["ParentProcessId"] < 0
        or not isinstance(process["Name"], str)
        or not process["Name"]
        or not (
            _windows_path_equal(process["ExecutablePath"], SERVICE_PYTHON)
            or _windows_path_equal(process["ExecutablePath"], base_python)
        )
        or process["CommandLine"] != SERVICE_BINARY
        or not _valid_sha256(process["executable_sha256"])
    ):
        raise ReadyEvidenceError("service process identity is incomplete")
    _parse_utc(process["CreationDate"], "service process creation time")
    listeners = payload["listeners"]
    listener_fields = {"LocalAddress", "LocalPort", "State", "OwningProcess"}
    if not isinstance(listeners, list) or len(listeners) != 1:
        raise ReadyEvidenceError("service response does not retain one formal listener")
    listener = _require_exact_keys(listeners[0], listener_fields, "service listener")
    if (
        listener["LocalAddress"] != GUEST_FIXED_ADDRESS
        or listener["LocalPort"] != SERVICE_PORT
        or listener["State"] != "Listen"
        or listener["OwningProcess"] != service["process_id"]
    ):
        raise ReadyEvidenceError("service listener is not the one formal service instance on 28790")
    return {"service_process_id": service["process_id"], "listener": listener}


def _valid_service_sid(value: Any) -> bool:
    return value == SERVICE_SID


_SYSTEM = ("NT AUTHORITY\\SYSTEM", "S-1-5-18")
_ADMINISTRATORS = ("BUILTIN\\Administrators", "S-1-5-32-544")
_CODE_READERS = {
    _SYSTEM,
    _ADMINISTRATORS,
    ("NT AUTHORITY\\Authenticated Users", "S-1-5-11"),
    ("BUILTIN\\Users", "S-1-5-32-545"),
}
_READ_DATA = 0x00000001
_WRITE_DATA = 0x00000002
_APPEND_DATA = 0x00000004
_WRITE_EA = 0x00000010
_DELETE_CHILD = 0x00000040
_WRITE_ATTRIBUTES = 0x00000100
_DELETE = 0x00010000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_GENERIC_ALL = 0x10000000
_GENERIC_WRITE = 0x40000000
_GENERIC_READ = 0x80000000
_WRITE_MASK = _WRITE_DATA | _APPEND_DATA | _WRITE_EA | _DELETE_CHILD | _WRITE_ATTRIBUTES | _DELETE | _WRITE_DAC | _WRITE_OWNER | _GENERIC_ALL | _GENERIC_WRITE
_RUNTIME_SERVICE_ALLOWED = 0x001301BF
_ACE_TYPE_ALLOW = 0
_ACE_TYPE_DENY = 1
_ACE_FLAG_OBJECT_INHERIT = 0x01
_ACE_FLAG_CONTAINER_INHERIT = 0x02
_ACE_FLAG_NO_PROPAGATE = 0x04
_ACE_FLAG_INHERIT_ONLY = 0x08
_ACE_FLAG_INHERITED = 0x10
_ACL_OBJECT_KEYS = {"security_descriptor_base64", "sddl", "access_rules"}
_ACL_RULE_KEYS = {
    "identity", "sid", "ace_type", "ace_flags", "access_control_type",
    "access_mask", "is_inherited", "inheritance_flags", "propagation_flags",
    "raw_ace_base64",
}
_SDDL_SIDS = {
    "SY": "S-1-5-18",
    "BA": "S-1-5-32-544",
    "AU": "S-1-5-11",
    "BU": "S-1-5-32-545",
    # Windows adds an implicit OWNER RIGHTS ACE on directories created by a
    # non-admin owner; it is the creator SID itself, not a foreign principal.
    "OW": "S-1-3-4",
}
_SDDL_RIGHTS = {
    "GA": _GENERIC_ALL,
    "GR": _GENERIC_READ,
    "GW": _GENERIC_WRITE,
    "GX": 0x20000000,
    "FA": 0x001F01FF,
    "FR": 0x00120089,
    "FW": 0x00120116,
    "FX": 0x001200A0,
    "RC": 0x00020000,
    "SD": _DELETE,
    "WD": _WRITE_DAC,
    "WO": _WRITE_OWNER,
    "SY": 0x00100000,
}


def _mask_has_read(mask: int) -> bool:
    return bool(mask & (_READ_DATA | _GENERIC_READ | _GENERIC_ALL))


def _mask_has_write(mask: int) -> bool:
    return bool(mask & _WRITE_MASK)


def _decode_sid(raw: bytes, offset: int, limit: int, label: str) -> tuple[str, int]:
    if offset + 8 > limit:
        raise ReadyEvidenceError(f"{label} SID is truncated")
    revision, count = raw[offset], raw[offset + 1]
    if revision != 1 or count > 15:
        raise ReadyEvidenceError(f"{label} SID has an unsupported revision or length")
    end = offset + 8 + count * 4
    if end > limit:
        raise ReadyEvidenceError(f"{label} SID exceeds its ACE boundary")
    authority = int.from_bytes(raw[offset + 2:offset + 8], "big")
    subauthorities = struct.unpack_from("<" + "I" * count, raw, offset + 8) if count else ()
    return "S-1-" + str(authority) + "".join(f"-{item}" for item in subauthorities), end


def _parse_binary_descriptor(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, str) or not value:
        raise ReadyEvidenceError(f"{label} lacks the real binary security descriptor")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ReadyEvidenceError(f"{label} binary security descriptor is not base64") from exc
    if len(raw) < 20:
        raise ReadyEvidenceError(f"{label} binary security descriptor is truncated")
    revision, _, control, _, _, _, dacl_offset = struct.unpack_from("<BBHLLLL", raw)
    if revision != 1 or not control & 0x8000 or not control & 0x0004 or dacl_offset == 0:
        raise ReadyEvidenceError(f"{label} does not contain a self-relative DACL")
    if dacl_offset + 8 > len(raw):
        raise ReadyEvidenceError(f"{label} DACL is outside its binary descriptor")
    _, _, acl_size, ace_count, _ = struct.unpack_from("<BBHHH", raw, dacl_offset)
    acl_end = dacl_offset + acl_size
    if acl_size < 8 or acl_end > len(raw):
        raise ReadyEvidenceError(f"{label} DACL length is invalid")
    cursor = dacl_offset + 8
    result: list[dict[str, Any]] = []
    for position in range(ace_count):
        if cursor + 4 > acl_end:
            raise ReadyEvidenceError(f"{label} ACE {position} is truncated")
        ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", raw, cursor)
        ace_end = cursor + ace_size
        if ace_size < 8 or ace_end > acl_end:
            raise ReadyEvidenceError(f"{label} ACE {position} length is invalid")
        if ace_type not in {_ACE_TYPE_ALLOW, _ACE_TYPE_DENY}:
            raise ReadyEvidenceError(f"{label} ACE {position} has an unsupported non-file allow/deny type")
        access_mask = struct.unpack_from("<I", raw, cursor + 4)[0]
        sid, sid_end = _decode_sid(raw, cursor + 8, ace_end, f"{label} ACE {position}")
        if sid_end != ace_end:
            raise ReadyEvidenceError(f"{label} ACE {position} has unprojected binary data")
        ace = raw[cursor:ace_end]
        result.append({
            "sid": sid,
            "ace_type": ace_type,
            "ace_flags": ace_flags,
            "access_mask": access_mask,
            "raw_ace_base64": base64.b64encode(ace).decode("ascii"),
        })
        cursor = ace_end
    if cursor != acl_end:
        raise ReadyEvidenceError(f"{label} DACL has bytes outside the declared ACE projection")
    return result


def _sddl_rights(value: str, label: str) -> int:
    if re.fullmatch(r"0[xX][0-9A-Fa-f]{1,8}", value):
        return int(value, 16)
    cursor, mask = 0, 0
    while cursor < len(value):
        token = value[cursor:cursor + 2]
        if token not in _SDDL_RIGHTS:
            raise ReadyEvidenceError(f"{label} has an unsupported symbolic SDDL right")
        mask |= _SDDL_RIGHTS[token]
        cursor += 2
    return mask


def _sddl_flags(value: str, label: str) -> int:
    tokens = {
        "OI": _ACE_FLAG_OBJECT_INHERIT,
        "CI": _ACE_FLAG_CONTAINER_INHERIT,
        "NP": _ACE_FLAG_NO_PROPAGATE,
        "IO": _ACE_FLAG_INHERIT_ONLY,
        "ID": _ACE_FLAG_INHERITED,
    }
    cursor, flags = 0, 0
    while cursor < len(value):
        token = value[cursor:cursor + 2]
        if token not in tokens:
            raise ReadyEvidenceError(f"{label} has an unsupported SDDL ACE flag")
        flags |= tokens[token]
        cursor += 2
    return flags


def _sddl_sid(value: str, label: str) -> str:
    sid = _SDDL_SIDS.get(value, value)
    if not re.fullmatch(r"S-1-[0-9]+(?:-[0-9]+)+", sid):
        raise ReadyEvidenceError(f"{label} has an unsupported SDDL account SID")
    return sid


def _parse_sddl_dacl(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, str) or not value:
        raise ReadyEvidenceError(f"{label} lacks its actual SDDL")
    start = value.find("D:")
    if start < 0:
        raise ReadyEvidenceError(f"{label} SDDL has no DACL")
    end = value.find("S:", start + 2)
    dacl = value[start + 2:] if end < 0 else value[start + 2:end]
    first_ace = dacl.find("(")
    if first_ace < 0:
        raise ReadyEvidenceError(f"{label} SDDL has no DACL ACEs")
    control = dacl[:first_ace]
    remaining = control
    while remaining:
        for token in ("NO_ACCESS_CONTROL", "AI", "AR", "P"):
            if remaining.startswith(token):
                remaining = remaining[len(token):]
                break
        else:
            raise ReadyEvidenceError(f"{label} SDDL has unsupported DACL control flags")
    rows: list[dict[str, Any]] = []
    cursor = first_ace
    while cursor < len(dacl):
        if dacl[cursor] != "(":
            raise ReadyEvidenceError(f"{label} SDDL has data outside DACL ACEs")
        close = dacl.find(")", cursor + 1)
        if close < 0:
            raise ReadyEvidenceError(f"{label} SDDL has an unterminated DACL ACE")
        fields = dacl[cursor + 1:close].split(";")
        if len(fields) != 6 or fields[3] or fields[4]:
            raise ReadyEvidenceError(f"{label} SDDL ACE is not a plain filesystem access ACE")
        type_name, flags, rights, _, _, account = fields
        if type_name not in {"A", "D"}:
            raise ReadyEvidenceError(f"{label} SDDL ACE type is unsupported")
        rows.append({
            "ace_type": _ACE_TYPE_ALLOW if type_name == "A" else _ACE_TYPE_DENY,
            "ace_flags": _sddl_flags(flags, label),
            "access_mask": _sddl_rights(rights, label),
            "sid": _sddl_sid(account, label),
        })
        cursor = close + 1
    return rows


def _acl_masks(
    acl: Mapping[str, Any],
    label: str,
) -> tuple[dict[tuple[str, str], int], dict[tuple[str, str], int]]:
    _require_exact_keys(acl, _ACL_OBJECT_KEYS, label)
    binary = _parse_binary_descriptor(acl["security_descriptor_base64"], label)
    sddl = _parse_sddl_dacl(acl["sddl"], label)
    rules = acl["access_rules"]
    if not isinstance(rules, list) or not rules or len(rules) != len(binary) or len(sddl) != len(binary):
        raise ReadyEvidenceError(f"{label} does not retain every real DACL ACE")
    masks: dict[tuple[str, str], int] = {}
    effective_masks: dict[tuple[str, str], int] = {}
    for position, (raw_rule, binary_ace, sddl_ace) in enumerate(zip(rules, binary, sddl, strict=True)):
        rule = _require_exact_keys(raw_rule, _ACL_RULE_KEYS, f"{label} rule {position}")
        if (
            not isinstance(rule["identity"], str)
            or not rule["identity"]
            or not isinstance(rule["sid"], str)
            or not rule["sid"]
            or type(rule["ace_type"]) is not int
            or type(rule["ace_flags"]) is not int
            or rule["access_control_type"] not in {"Allow", "Deny"}
            or type(rule["access_mask"]) is not int
            or not 0 <= rule["access_mask"] <= 0xFFFFFFFF
            or type(rule["is_inherited"]) is not bool
            or type(rule["inheritance_flags"]) is not int
            or type(rule["propagation_flags"]) is not int
            or not isinstance(rule["raw_ace_base64"], str)
        ):
            raise ReadyEvidenceError(f"{label} ACE {position} projection is malformed")
        expected_inheritance = (
            (_ACE_FLAG_OBJECT_INHERIT if binary_ace["ace_flags"] & _ACE_FLAG_OBJECT_INHERIT else 0)
            | (_ACE_FLAG_CONTAINER_INHERIT if binary_ace["ace_flags"] & _ACE_FLAG_CONTAINER_INHERIT else 0)
        )
        expected_propagation = (
            (1 if binary_ace["ace_flags"] & _ACE_FLAG_NO_PROPAGATE else 0)
            | (2 if binary_ace["ace_flags"] & _ACE_FLAG_INHERIT_ONLY else 0)
        )
        if (
            rule["sid"] != binary_ace["sid"]
            or rule["ace_type"] != binary_ace["ace_type"]
            or rule["ace_flags"] != binary_ace["ace_flags"]
            or rule["access_mask"] != binary_ace["access_mask"]
            or rule["raw_ace_base64"] != binary_ace["raw_ace_base64"]
            or rule["is_inherited"] != bool(binary_ace["ace_flags"] & _ACE_FLAG_INHERITED)
            or rule["inheritance_flags"] != expected_inheritance
            or rule["propagation_flags"] != expected_propagation
            or rule["access_control_type"] != ("Allow" if binary_ace["ace_type"] == _ACE_TYPE_ALLOW else "Deny")
            or {key: binary_ace[key] for key in ("sid", "ace_type", "ace_flags", "access_mask")} != sddl_ace
        ):
            raise ReadyEvidenceError(f"{label} SDDL, binary descriptor, and ACE projection disagree")
        if rule["ace_type"] != _ACE_TYPE_ALLOW:
            raise ReadyEvidenceError(f"{label} includes a deny ACE; effective Windows rights cannot be safely inferred")
        key = (rule["identity"], rule["sid"])
        masks[key] = masks.get(key, 0) | rule["access_mask"]
        if not rule["propagation_flags"] & 2:
            effective_masks[key] = effective_masks.get(key, 0) | rule["access_mask"]
    return masks, effective_masks


def _assert_acl_policy(
    acl: Mapping[str, Any],
    *,
    policy: str,
    service_key: tuple[str, str],
    label: str,
) -> None:
    masks, effective_masks = _acl_masks(acl, label)
    if service_key not in masks:
        raise ReadyEvidenceError(f"{label} does not retain a dedicated-service ACE")
    permitted = {_SYSTEM, _ADMINISTRATORS, service_key, ("OWNER RIGHTS", "S-1-3-4")}
    if policy == "code":
        permitted |= _CODE_READERS
    if any(key not in permitted for key in masks):
        raise ReadyEvidenceError(f"{label} grants an unapproved ordinary or service identity")
    if not (_SYSTEM in masks and _ADMINISTRATORS in masks):
        raise ReadyEvidenceError(f"{label} lacks necessary administrator and system management ACEs")
    service_mask = effective_masks.get(service_key, 0)
    if not _mask_has_read(service_mask):
        raise ReadyEvidenceError(f"{label} service ACE does not apply read access to this object")
    if policy in {"download", "runtime_logs"}:
        if not service_mask & (_WRITE_DATA | _APPEND_DATA):
            raise ReadyEvidenceError(f"{label} lacks the service's necessary runtime write access")
        if (
            service_mask & (_WRITE_DAC | _WRITE_OWNER | _GENERIC_ALL | _GENERIC_WRITE)
            or service_mask & ~_RUNTIME_SERVICE_ALLOWED
        ):
            raise ReadyEvidenceError(f"{label} grants the service excess runtime or permission-management rights")
        if any(
            _mask_has_write(mask)
            for key, mask in masks.items()
            if key not in {_SYSTEM, _ADMINISTRATORS, service_key, ("OWNER RIGHTS", "S-1-3-4")}
        ):
            raise ReadyEvidenceError(f"{label} grants runtime write access outside the service identity")
    elif _mask_has_write(service_mask):
        raise ReadyEvidenceError(f"{label} grants the service write access outside its runtime roots")
    if policy == "code" and any(
        _mask_has_write(mask) for key, mask in masks.items() if key not in {_SYSTEM, _ADMINISTRATORS}
    ):
        raise ReadyEvidenceError(f"{label} grants an ordinary or service identity write access to service code")
    if policy == "secret" and set(masks) != {_SYSTEM, _ADMINISTRATORS, service_key}:
        raise ReadyEvidenceError(f"{label} protected configuration permits an identity other than service and necessary administrators")


def _windows_within(path: str, root: str) -> bool:
    candidate = PureWindowsPath(path)
    base = PureWindowsPath(root)
    return (
        candidate.drive.casefold() == base.drive.casefold()
        and len(candidate.parts) >= len(base.parts)
        and all(left.casefold() == right.casefold() for left, right in zip(candidate.parts, base.parts, strict=False))
    )


def _windows_immediate_child(path: str, parent: str) -> bool:
    candidate = PureWindowsPath(path)
    base = PureWindowsPath(parent)
    return _windows_within(path, parent) and len(candidate.parts) == len(base.parts) + 1


def _path_acl_view(row: Mapping[str, Any]) -> dict[str, Any]:
    return {key: row[key] for key in _ACL_OBJECT_KEYS}


def _verify_code_tree(
    value: Any,
    *,
    path_rows: Mapping[str, Mapping[str, Any]],
    service_key: tuple[str, str],
) -> None:
    tree = _require_exact_keys(value, {"root", "runtime_logs_root", "nodes"}, "ACL code-tree response")
    if not _windows_path_equal(tree["root"], ACL_PATHS["code_root"]) or not _windows_path_equal(tree["runtime_logs_root"], ACL_PATHS["runtime_logs"]):
        raise ReadyEvidenceError("ACL code-tree roots differ from the absolute service paths")
    nodes = tree["nodes"]
    if not isinstance(nodes, list) or not nodes:
        raise ReadyEvidenceError("ACL code-tree has no actual enumerated nodes")
    by_path: dict[str, dict[str, Any]] = {}
    parent_counts: dict[str, int] = {}
    for position, candidate in enumerate(nodes):
        row = _require_exact_keys(candidate, {"path", "is_reparse_point", "file_type", "scope", "children", "acl"}, f"ACL code-tree node {position}")
        path = _require_plain_windows_path(row["path"], f"ACL code-tree node {position} path")
        key = path.casefold()
        if key in by_path or not _windows_within(path, tree["root"]):
            raise ReadyEvidenceError("ACL code-tree has a duplicate node or an escaping path")
        if row["is_reparse_point"] is not False or row["file_type"] not in {"file", "directory"} or row["scope"] not in {"code", "runtime_logs"} or not isinstance(row["children"], list):
            raise ReadyEvidenceError("ACL code-tree node metadata is incomplete or unsafe")
        if row["file_type"] == "file" and row["children"]:
            raise ReadyEvidenceError("ACL code-tree file has unexpected child entries")
        is_log = _windows_within(path, tree["runtime_logs_root"])
        if (row["scope"] == "runtime_logs") != is_log:
            raise ReadyEvidenceError("ACL code-tree does not classify the complete Logs subtree")
        _assert_acl_policy(row["acl"], policy=row["scope"], service_key=service_key, label=f"ACL code-tree node {position}")
        by_path[key] = row
    root_key = str(PureWindowsPath(tree["root"])).casefold()
    logs_key = str(PureWindowsPath(tree["runtime_logs_root"])).casefold()
    if root_key not in by_path or logs_key not in by_path or by_path[logs_key]["file_type"] != "directory":
        raise ReadyEvidenceError("ACL code-tree omits its repository root or Logs directory")
    for key, row in by_path.items():
        seen_children: set[str] = set()
        for child in row["children"]:
            child_path = _require_plain_windows_path(child, "ACL code-tree child path")
            child_key = child_path.casefold()
            if child_key in seen_children or child_key not in by_path or not _windows_immediate_child(child_path, row["path"]):
                raise ReadyEvidenceError("ACL code-tree children are not a closed direct enumeration")
            seen_children.add(child_key)
            parent_counts[child_key] = parent_counts.get(child_key, 0) + 1
        if row["file_type"] == "directory" and any(not _windows_within(child, row["path"]) for child in row["children"]):
            raise ReadyEvidenceError("ACL code-tree directory child escapes its parent")
    if parent_counts.get(root_key, 0):
        raise ReadyEvidenceError("ACL code-tree root has a parent")
    for key in by_path:
        if key != root_key and parent_counts.get(key, 0) != 1:
            raise ReadyEvidenceError("ACL code-tree node is missing or has multiple actual parents")
    for role in ("code_root", "runtime_logs", "service_python", "service_host"):
        expected = path_rows[role]
        node = by_path.get(str(PureWindowsPath(expected["path"])).casefold())
        if node is None or node["is_reparse_point"] is not expected["is_reparse_point"] or node["file_type"] != expected["file_type"] or node["acl"] != _path_acl_view(expected):
            raise ReadyEvidenceError(f"ACL code-tree does not bind the {role} role to its enumerated node")


def _verify_acl(transcript: _Transcript) -> None:
    payload = _require_exact_keys(transcript.payload, {"service_account", "paths", "code_tree"}, "ACL response")
    account = _require_exact_keys(payload["service_account"], {"name", "sid"}, "ACL service account")
    if account["name"] != SERVICE_ACCOUNT or not _valid_service_sid(account["sid"]):
        raise ReadyEvidenceError("ACL response does not retain the dedicated service account identity")
    paths = payload["paths"]
    required_roles = set(ACL_PATHS)
    if not isinstance(paths, list) or len(paths) != len(required_roles):
        raise ReadyEvidenceError("ACL response lacks the complete protected path set")
    rows: dict[str, dict[str, Any]] = {}
    service_key = (SERVICE_ACCOUNT, account["sid"])
    for position, candidate in enumerate(paths):
        row = _require_exact_keys(
            candidate,
            {"role", "path", "is_reparse_point", "file_type", *_ACL_OBJECT_KEYS},
            f"ACL path {position}",
        )
        role = row["role"]
        if role not in required_roles or role in rows:
            raise ReadyEvidenceError("ACL role is unknown or duplicated")
        _require_plain_windows_path(row["path"], f"ACL {role} path")
        expected_type = "directory" if role in {"code_root", "download_root", "runtime_logs"} else "file"
        if (
            not _windows_path_equal(row["path"], ACL_PATHS[role])
            or row["is_reparse_point"] is not False
            or row["file_type"] != expected_type
        ):
            raise ReadyEvidenceError("ACL role is not its expected plain absolute filesystem object")
        policy = (
            "code" if role in {"code_root", "service_python", "service_host"}
            else "secret" if role in {"protected_env", "api_client_config"}
            else "download" if role == "download_root" else "runtime_logs"
        )
        _assert_acl_policy(_path_acl_view(row), policy=policy, service_key=service_key, label=f"ACL {role}")
        rows[role] = row
    if set(rows) != required_roles:
        raise ReadyEvidenceError("ACL role set differs from the protected service contract")
    _verify_code_tree(payload["code_tree"], path_rows=rows, service_key=service_key)


def _verify_firewall(transcript: _Transcript, service: Mapping[str, Any]) -> None:
    payload = _require_exact_keys(transcript.payload, {"rules"}, "firewall response")
    rules = payload["rules"]
    fields = {"name", "display_name", "direction", "action", "enabled", "protocol", "local_port", "local_address", "remote_address"}
    if not isinstance(rules, list) or len(rules) != 1:
        raise ReadyEvidenceError("firewall response does not retain one exact rule")
    rule = _require_exact_keys(rules[0], fields, "firewall rule")
    if (
        rule["name"] != "mcp-velociraptor-28790"
        or rule["display_name"] != "mcp-velociraptor-28790"
        or rule["direction"] != "Inbound"
        or rule["action"] != "Allow"
        or rule["enabled"] is not True
        or rule["protocol"] not in {"TCP", "6"}
        or rule["local_port"] != SERVICE_PORT
        or rule["local_address"] != GUEST_FIXED_ADDRESS
        or rule["remote_address"] != HOST_FIXED_ADDRESS
        or rule["local_port"] != service["listener"]["LocalPort"]
        or rule["local_address"] != service["listener"]["LocalAddress"]
    ):
        raise ReadyEvidenceError("firewall rule differs from the unique exact 28790 host-only boundary")


def _verify_resources(transcript: _Transcript) -> None:
    payload = _require_exact_keys(
        transcript.payload,
        {"owned_flows", "owned_hunts", "historical_flows", "historical_hunts", "trace", "temporary_listeners"},
        "resources response",
    )
    resource_fields = {"resource_id", "client_id", "state", "creator", "created_at_utc"}
    seen: dict[str, set[str]] = {"flows": set(), "hunts": set()}
    terminal_flow_states = {"FINISHED", "ERROR", "CANCELLED"}
    for field, kind, allowed_states, historical in (
        ("owned_flows", "flows", terminal_flow_states, False),
        ("owned_hunts", "hunts", {"FINISHED", "ERROR", "CANCELLED"}, False),
        ("historical_flows", "flows", {"PAUSED", "STOPPED"}, True),
        ("historical_hunts", "hunts", {"PAUSED", "STOPPED"}, True),
    ):
        rows = payload[field]
        if not isinstance(rows, list):
            raise ReadyEvidenceError(f"resources {field} is not an actual resource row list")
        for position, candidate in enumerate(rows):
            row = _require_exact_keys(candidate, resource_fields, f"resources {field} row {position}")
            resource_id = _require_nonempty(row["resource_id"], f"resources {field} resource_id")
            # Historical PAUSED/STOPPED leftovers are listed for context
            # only; a memberless leftover hunt carries no observed client
            # binding, while owned rows must bind the one Windows client.
            client_bound = row["client_id"] == WINDOWS_CLIENT_ID or (historical and row["client_id"] is None)
            if resource_id in seen[kind] or not client_bound or row["state"] not in allowed_states or not isinstance(row["creator"], str) or not row["creator"]:
                raise ReadyEvidenceError("resources current and historical rows do not prove separated inactive owned resources")
            _parse_utc(row["created_at_utc"], f"resources {field} creation time")
            seen[kind].add(resource_id)
    trace = _require_exact_keys(payload["trace"], {"argv", "exit_status", "stdout", "stderr"}, "resources trace")
    if (
        trace["argv"] != ["netsh.exe", "trace", "show", "status"]
        or type(trace["exit_status"]) is not int
        or trace["exit_status"] not in {0, 1}
        or not isinstance(trace["stdout"], str)
        or not isinstance(trace["stderr"], str)
    ):
        raise ReadyEvidenceError("resources trace observation is incomplete")
    trace_text = "\n".join((trace["stdout"], trace["stderr"]))
    if not trace_text or not (
        "not running" in trace_text.casefold()
        or "no trace session currently in progress" in trace_text.casefold()
        or "没有运行" in trace_text
        or "未运行" in trace_text
    ):
        raise ReadyEvidenceError("resources raw trace status is not inactive")
    listeners = payload["temporary_listeners"]
    listener_fields = {"LocalAddress", "LocalPort", "State", "OwningProcess"}
    if not isinstance(listeners, list):
        raise ReadyEvidenceError("resources temporary listener response is not a raw row list")
    for position, candidate in enumerate(listeners):
        _require_exact_keys(candidate, listener_fields, f"resources temporary listener {position}")
    if listeners:
        raise ReadyEvidenceError("resources retains an active temporary listener")


def verify_ready_raw_evidence(
    ready: Mapping[str, Any],
    *,
    bundle_root: Path,
    report: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify all twelve implemented §0.7 ready raw observation predicates.

    ``bundle_root`` is the activation-evidence parent directory.  The caller
    must still validate the encompassing ready Ref.  This function rechecks
    every consumed Ref byte identity itself, reads frozen source copies from
    ``source/``, and returns only derived facts.  It validates recorded raw
    observations, not a claim that this host executed a Windows collection.
    """
    if not isinstance(ready, Mapping) or ready.get("workflow_id") != WORKFLOW_ID:
        raise ReadyEvidenceError("ready workflow identity is invalid")
    if report.get("run_id") != ready.get("run_id"):
        raise ReadyEvidenceError("ready and formal report run IDs differ")
    observations = ready.get("observations")
    if not isinstance(observations, Mapping) or set(observations) != RAW_OBSERVATIONS:
        raise ReadyEvidenceError("ready observations do not have the exact twelve raw references")
    paths: dict[str, Path] = {}
    used_paths: set[str] = set()
    for observation in RAW_OBSERVATIONS:
        reference = observations[observation]
        path = _resolve_ref(bundle_root, reference, f"ready.observations.{observation}")
        if reference["path"] in used_paths:
            raise ReadyEvidenceError("one raw transcript cannot stand in for two ready observations")
        used_paths.add(reference["path"])
        paths[observation] = path
    host_clock = _load_transcript(paths["host_clock"], "host_clock", ready, "host")
    guest_identity = _load_transcript(paths["guest_identity"], "guest_identity", ready, "guest")
    fixture_static = _load_transcript(paths["fixture_static"], "fixture_static", ready, "guest")
    fixture_transcript = _load_transcript(paths["fixture_instance"], "fixture_instance", ready, "guest")
    guest_processes = _load_transcript(paths["guest_processes"], "guest_processes", ready, "guest")
    host_processes = _load_transcript(paths["host_processes"], "host_processes", ready, "host")
    parent_bindings = _load_transcript(paths["parent_bindings"], "parent_bindings", ready, "guest")
    dependencies = _load_transcript(paths["dependencies"], "dependencies", ready, "guest")
    service = _load_transcript(paths["service"], "service", ready, "guest")
    acl = _load_transcript(paths["acl"], "acl", ready, "guest")
    firewall = _load_transcript(paths["firewall"], "firewall", ready, "guest")
    resources = _load_transcript(paths["resources"], "resources", ready, "guest")
    if host_clock.computer_name != host_processes.computer_name:
        raise ReadyEvidenceError("host clock and host process evidence belong to different hosts")
    if any(
        transcript.computer_name != GUEST_COMPUTER_NAME
        for transcript in (
            guest_identity,
            fixture_static,
            fixture_transcript,
            guest_processes,
            parent_bindings,
            dependencies,
            service,
            acl,
            firewall,
            resources,
        )
    ):
        raise ReadyEvidenceError("guest raw evidence belongs to the wrong Windows hostname")
    guest_started, guest_ended, guest_time = _verify_guest_identity(guest_identity)
    _verify_host_clock(host_clock, guest_started, guest_ended, guest_time)
    spec, spec_sha256 = _load_fixture_spec(bundle_root)
    fixture = _verify_fixture_instance(fixture_transcript, spec, spec_sha256)
    _verify_fixture_static(fixture_static, spec, spec_sha256, fixture, fixture_transcript.stdout_bytes)
    captured_at, guest_rows = _parse_guest_processes(guest_processes)
    approved_argv_pids = _verify_parent_bindings(
        parent_bindings,
        bundle_root,
        fixture,
        fixture_transcript.stdout_bytes,
        guest_rows,
        captured_at,
    )
    _verify_guest_process_semantics(fixture, spec, guest_rows, captured_at, approved_argv_pids)
    _verify_host_processes(host_processes, report)
    _verify_dependencies(dependencies, bundle_root)
    service_facts = _verify_service(service)
    _verify_acl(acl)
    _verify_firewall(firewall, service_facts)
    _verify_resources(resources)
    return {
        "host_computer_name": host_clock.computer_name,
        "guest_computer_name": GUEST_COMPUTER_NAME,
        "fixture_pid": fixture["process"]["pid"],
        "fixture_creation_time_utc": fixture["process"]["creation_time_utc"],
        "approved_guest_argv_pids": sorted(approved_argv_pids),
        "service_process_id": service_facts["service_process_id"],
        "formal_listener": dict(service_facts["listener"]),
    }
