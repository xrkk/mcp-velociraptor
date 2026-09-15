"""Raw, fail-closed HTTP evidence for the P05 §0.7 entry gate.

This is a *new* collector format for future Windows acceptance runs.  It does
not reinterpret ``p05_external_acceptance`` summaries, historical HTTP header
logs, or any retained P05/P06 reports as raw evidence.  The collector uses
``http.client`` directly because the ``missing_host`` case has to omit Host at
the wire-construction layer; high-level clients normally re-add it.

``counter_reader`` is intentionally an outer integration seam, not a local
counter or a test double disguised as a service observation.  Its read-only
SDK hook is still owned by the caller.  For every read it must return this
complete, self-verifying original (all keys are required):

.. code-block:: json

  {
    "schema_version": 1,
    "kind": "p05-http-handler-counter-v1",
    "workflow_id": "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2",
    "run_id": "<reserved run>",
    "restore_attempt_id": "<current restore>",
    "count": 0,
    "instance": "<actual server instance>",
    "time": "<UTC RFC3339 observation time>",
    "command": {
      "argv": ["<actual read-only executable>", "..."],
      "command_line": "<complete actual command line>",
      "exit_status": {"code": 0}
    },
    "output": {
      "stdout": "<complete UTF-8 output>",
      "stdout_size": 0,
      "stdout_sha256": "<sha256 of UTF-8 stdout>",
      "stderr": "<complete UTF-8 stderr>",
      "stderr_size": 0,
      "stderr_sha256": "<sha256 of UTF-8 stderr>"
    }
  }

The callback receives no credential and is called with no arguments.  A
missing field, a non-zero command, a bad output hash, instance drift, or a
timestamp that does not bracket the HTTP request makes collection fail closed.
``tests.p05_service_observation.make_http_counter_reader`` is the designated
adapter for the deployment's SDK dispatch record.  Its outer PowerShell
executor remains an injected, read-only Windows evidence capability; it does
not prevent this module from collecting, preserving, and parsing the seven
HTTP exchanges.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any
from urllib.parse import urlsplit
import uuid


WORKFLOW_ID = "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2"
GUEST_HOST = "192.168.204.232"
SERVICE_PORT = 28790
MCP_PATH = "/mcp"
EXPECTED_ENDPOINT = f"http://{GUEST_HOST}:{SERVICE_PORT}{MCP_PATH}"
REJECTED_HOST = "rebind.example"
REJECTED_ORIGIN = "https://not-allowed.example"

ENTRY_GATE_KEYS = {"schema_version", "workflow_id", "run_id", "restore_attempt_id", "cases"}
REF_KEYS = {"path", "size", "sha256"}
CASE_NAMES = (
    "no_origin",
    "allowed_origin",
    "missing_bearer",
    "wrong_bearer",
    "missing_host",
    "wrong_host",
    "wrong_origin",
)
CASE_KEYS = {
    "schema_version", "kind", "workflow_id", "run_id", "restore_attempt_id", "case",
    "request", "response", "counter_before", "counter_after",
}
REQUEST_KEYS = {
    "method", "target", "http_version", "headers", "authorization_configured", "body",
    "first_utc", "last_utc",
}
RESPONSE_KEYS = {"status", "reason", "headers", "body"}
BODY_KEYS = {"encoding", "text", "size", "sha256"}
HEADER_KEYS = {"name", "value"}
COUNTER_KEYS = {
    "schema_version", "kind", "workflow_id", "run_id", "restore_attempt_id", "count",
    "instance", "time", "command", "output",
}
COUNTER_COMMAND_KEYS = {"argv", "command_line", "exit_status"}
COUNTER_EXIT_KEYS = {"code"}
COUNTER_OUTPUT_KEYS = {
    "stdout", "stdout_size", "stdout_sha256", "stderr", "stderr_size", "stderr_sha256",
}


class EntryGateEvidenceError(ValueError):
    """A raw entry-gate original is incomplete, unsafe, or does not prove its predicate."""

    def __init__(
        self,
        message: str,
        *,
        evidence_dir: Path | None = None,
        raw_counter_original: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.evidence_dir = evidence_dir
        self.raw_counter_original = dict(raw_counter_original) if raw_counter_original is not None else None


class _SecretInResponse(EntryGateEvidenceError):
    """Stop before a response or callback original can persist the bearer token."""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EntryGateEvidenceError(f"{label} must be a non-empty string")
    return value


def _parse_utc(value: Any, label: str) -> datetime:
    text = _require_nonempty(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EntryGateEvidenceError(f"{label} is not RFC3339") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise EntryGateEvidenceError(f"{label} must be UTC")
    return parsed.astimezone(UTC)


def _json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EntryGateEvidenceError("raw evidence is not JSON serializable") from exc


def _ensure_token_absent(value: Any, token: str, *, label: str) -> None:
    """Detect the actual token without ever deriving a persistent substitute."""
    try:
        encoded = _json_bytes(value)
    except EntryGateEvidenceError:
        raise
    if token.encode("utf-8") in encoded:
        raise _SecretInResponse(f"{label} contains the configured bearer token")


def _validate_endpoint(endpoint: str) -> None:
    if not isinstance(endpoint, str):
        raise EntryGateEvidenceError("endpoint must be a string")
    parsed = urlsplit(endpoint)
    if (
        endpoint != EXPECTED_ENDPOINT
        or parsed.scheme != "http"
        or parsed.hostname != GUEST_HOST
        or parsed.port != SERVICE_PORT
        or parsed.path != MCP_PATH
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise EntryGateEvidenceError(
            f"endpoint must be the established guest entry {EXPECTED_ENDPOINT}"
        )


def _validate_allowed_origin(allowed_origin: str) -> None:
    origin = _require_nonempty(allowed_origin, "allowed_origin")
    if any(character in origin for character in "\r\n\x00"):
        raise EntryGateEvidenceError("allowed_origin contains an unsafe character")
    parsed = urlsplit(origin)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise EntryGateEvidenceError("allowed_origin must be an origin, not a URL path")
    if origin.casefold() == REJECTED_ORIGIN.casefold():
        raise EntryGateEvidenceError("allowed_origin collides with the fixed rejected-origin probe")


def _validate_output_root(output_root: Path) -> Path:
    root = Path(output_root)
    try:
        info = root.lstat()
    except FileNotFoundError as exc:
        raise EntryGateEvidenceError("output_root must already exist") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise EntryGateEvidenceError("output_root must be a non-link directory")
    return root


def _new_evidence_dir(root: Path) -> Path:
    parent = root / "entry-gate"
    if parent.exists():
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise EntryGateEvidenceError("entry-gate evidence parent is not a non-link directory")
    else:
        parent.mkdir()
    for _ in range(8):
        candidate = parent / str(uuid.uuid4())
        try:
            candidate.mkdir()
            (candidate / "cases").mkdir()
            return candidate
        except FileExistsError:
            continue
    raise EntryGateEvidenceError("could not reserve a new exclusive evidence UUID directory")


def _write_new_json(path: Path, value: Any, token: str) -> None:
    _ensure_token_absent(value, token, label="persisted evidence")
    encoded = _json_bytes(value)
    try:
        with path.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise EntryGateEvidenceError(f"refusing to overwrite existing evidence {path.name}") from exc


def _reference(root: Path, path: Path) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    content = path.read_bytes()
    return {"path": relative, "size": len(content), "sha256": _sha256_bytes(content)}


def _body_record(value: bytes) -> dict[str, Any]:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EntryGateEvidenceError("HTTP response body is not UTF-8 text") from exc
    return {
        "encoding": "utf-8",
        "text": text,
        "size": len(value),
        "sha256": _sha256_bytes(value),
    }


def _header_records(headers: list[tuple[str, str]], *, reject_duplicates: bool) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for name, value in headers:
        if not isinstance(name, str) or not isinstance(value, str):
            raise EntryGateEvidenceError("HTTP header name and value must be text")
        normal = name.casefold()
        if not normal or any(character in name for character in "\r\n\x00"):
            raise EntryGateEvidenceError("HTTP header name is unsafe")
        if any(character in value for character in "\r\n\x00"):
            raise EntryGateEvidenceError("HTTP header value is unsafe")
        if reject_duplicates and normal in seen:
            raise EntryGateEvidenceError(f"duplicate HTTP header {normal!r} is not permitted")
        seen.add(normal)
        records.append({"name": normal, "value": value})
    return records


def _initialize_payload(case_name: str) -> tuple[str, bytes]:
    request_id = f"entry-gate:{case_name}"
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "p05-http-evidence", "version": "1"},
        },
    }
    return request_id, _json_bytes(payload).rstrip(b"\n")


def _request_metadata(
    body: bytes,
    headers: list[tuple[str, str]],
    *,
    authorization_configured: bool,
) -> dict[str, Any]:
    # Authorization deliberately is not represented in the persisted headers.
    safe_headers = [(name, value) for name, value in headers if name.casefold() != "authorization"]
    return {
        "method": "POST",
        "target": MCP_PATH,
        "http_version": "HTTP/1.1",
        "headers": _header_records(safe_headers, reject_duplicates=True),
        "authorization_configured": authorization_configured,
        "body": _body_record(body),
        "first_utc": "",
        "last_utc": "",
    }


def _perform_http_request(
    endpoint: str,
    request: dict[str, Any],
    wire_headers: list[tuple[str, str]],
    body: bytes,
) -> dict[str, Any]:
    parsed = urlsplit(endpoint)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=30.0)
    request["first_utc"] = _utc_now()
    try:
        # ``skip_host=True`` is essential even when Host is present: we add the
        # one permitted Host ourselves.  For missing_host no Host is added at all.
        connection.putrequest("POST", MCP_PATH, skip_host=True, skip_accept_encoding=True)
        for name, value in wire_headers:
            connection.putheader(name, value)
        connection.endheaders(body)
        response = connection.getresponse()
        body_bytes = response.read()
        response_headers = _header_records(list(response.getheaders()), reject_duplicates=False)
        return {
            "status": response.status,
            "reason": response.reason or "",
            "headers": response_headers,
            "body": _body_record(body_bytes),
        }
    finally:
        request["last_utc"] = _utc_now()
        connection.close()


def _validate_counter(counter: Any, *, run_id: str, restore_attempt_id: str) -> dict[str, Any]:
    if not isinstance(counter, Mapping) or set(counter) != COUNTER_KEYS:
        raise EntryGateEvidenceError("counter_reader did not return the required raw counter keys")
    if (
        counter.get("schema_version") != 1
        or counter.get("kind") != "p05-http-handler-counter-v1"
        or counter.get("workflow_id") != WORKFLOW_ID
        or counter.get("run_id") != run_id
        or counter.get("restore_attempt_id") != restore_attempt_id
    ):
        raise EntryGateEvidenceError("counter original identity is invalid")
    count = counter.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise EntryGateEvidenceError("counter count must be a non-negative integer")
    _require_nonempty(counter.get("instance"), "counter.instance")
    _parse_utc(counter.get("time"), "counter.time")
    command = counter.get("command")
    if not isinstance(command, Mapping) or set(command) != COUNTER_COMMAND_KEYS:
        raise EntryGateEvidenceError("counter command original is incomplete")
    if (
        not isinstance(command.get("argv"), list)
        or not command["argv"]
        or not all(isinstance(item, str) and item for item in command["argv"])
        or not isinstance(command.get("command_line"), str)
        or not command["command_line"]
        or not isinstance(command.get("exit_status"), Mapping)
        or set(command["exit_status"]) != COUNTER_EXIT_KEYS
        or command["exit_status"].get("code") != 0
    ):
        raise EntryGateEvidenceError("counter command did not retain a successful complete read-only command")
    output = counter.get("output")
    if not isinstance(output, Mapping) or set(output) != COUNTER_OUTPUT_KEYS:
        raise EntryGateEvidenceError("counter output original is incomplete")
    for stream in ("stdout", "stderr"):
        text = output.get(stream)
        if not isinstance(text, str):
            raise EntryGateEvidenceError(f"counter {stream} must be complete UTF-8 text")
        encoded = text.encode("utf-8")
        if output.get(f"{stream}_size") != len(encoded) or output.get(f"{stream}_sha256") != _sha256_bytes(encoded):
            raise EntryGateEvidenceError(f"counter {stream} size or hash is invalid")
    # A plain dict makes the persisted original independent of a callback-owned mapping.
    return json.loads(_json_bytes(counter))


def _read_counter(
    counter_reader: Callable[[], Mapping[str, Any]],
    *,
    run_id: str,
    restore_attempt_id: str,
    token: str,
) -> dict[str, Any]:
    if not callable(counter_reader):
        raise EntryGateEvidenceError("counter_reader must be a read-only callback")
    try:
        original = counter_reader()
    except Exception as exc:  # No SDK exception text is trusted with a credential.
        raw_original = getattr(exc, "raw_original", None)
        if isinstance(raw_original, Mapping):
            _ensure_token_absent(raw_original, token, label="failed counter discovery original")
        raise EntryGateEvidenceError(
            f"counter_reader failed with {type(exc).__name__}",
            raw_counter_original=raw_original if isinstance(raw_original, Mapping) else None,
        ) from exc
    validated = _validate_counter(original, run_id=run_id, restore_attempt_id=restore_attempt_id)
    _ensure_token_absent(validated, token, label="counter original")
    return validated


def _safe_failure(error: BaseException, token: str) -> dict[str, str]:
    message = str(error).replace(token, "[REDACTED]") if token else str(error)
    return {"type": type(error).__name__, "message": message}


def _write_failure(
    evidence_dir: Path,
    root: Path,
    token: str,
    *,
    run_id: str,
    restore_attempt_id: str,
    case_name: str,
    error: BaseException,
    request: Mapping[str, Any] | None = None,
    counter_before: Mapping[str, Any] | None = None,
    counter_after: Mapping[str, Any] | None = None,
    counter_failure: Mapping[str, Any] | None = None,
    case_references: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    """Persist safe, partial originals without making an entry-gate success document."""
    failure: dict[str, Any] = {
        "schema_version": 1,
        "kind": "p05-entry-gate-probe-failure-v1",
        "workflow_id": WORKFLOW_ID,
        "run_id": run_id,
        "restore_attempt_id": restore_attempt_id,
        "case": case_name,
        "recorded_at": _utc_now(),
        "failure": _safe_failure(error, token),
    }
    if request is not None:
        failure["request"] = dict(request)
    if counter_before is not None:
        failure["counter_before"] = dict(counter_before)
    if counter_after is not None:
        failure["counter_after"] = dict(counter_after)
    if counter_failure is not None:
        failure["counter_failure"] = dict(counter_failure)
    if case_references:
        failure["completed_cases"] = dict(case_references)
    _write_new_json(evidence_dir / "entry-gate-probe-failure.json", failure, token)
    # Referencing root makes accidental writes outside the new UUID impossible.
    del root


def _wire_headers(
    *,
    include_host: bool,
    host_value: str | None,
    origin: str | None,
    authorization: str | None,
    body: bytes,
) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = [
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
        ("Content-Length", str(len(body))),
    ]
    if include_host:
        if host_value is None:
            raise EntryGateEvidenceError("host probe configuration is incomplete")
        headers.append(("Host", host_value))
    if origin is not None:
        headers.append(("Origin", origin))
    if authorization is not None:
        headers.append(("Authorization", authorization))
    _header_records(headers, reject_duplicates=True)
    return headers


def _case_configuration(
    case_name: str,
    token: str,
    allowed_origin: str,
    body: bytes,
) -> tuple[list[tuple[str, str]], bool]:
    authorization: str | None = f"Bearer {token}"
    include_host, host_value, origin = True, f"{GUEST_HOST}:{SERVICE_PORT}", None
    if case_name == "allowed_origin":
        origin = allowed_origin
    elif case_name == "missing_bearer":
        authorization = None
    elif case_name == "wrong_bearer":
        wrong = "p05-deliberately-invalid-bearer"
        if wrong == token:
            wrong = "p05-deliberately-invalid-bearer-2"
        authorization = f"Bearer {wrong}"
    elif case_name == "missing_host":
        include_host, host_value = False, None
    elif case_name == "wrong_host":
        host_value = REJECTED_HOST
    elif case_name == "wrong_origin":
        origin = REJECTED_ORIGIN
    elif case_name != "no_origin":
        raise EntryGateEvidenceError(f"unknown entry-gate case {case_name!r}")
    return _wire_headers(
        include_host=include_host,
        host_value=host_value,
        origin=origin,
        authorization=authorization,
        body=body,
    ), authorization is not None


def probe_entry_gate(
    endpoint: str,
    token: str,
    allowed_origin: str,
    counter_reader: Callable[[], Mapping[str, Any]],
    run_id: str,
    restore_attempt_id: str,
    output_root: Path,
) -> dict[str, Any]:
    """Collect all seven real entry exchanges into one new UUID evidence directory.

    The function returns only paths, a Ref, and facts recomputed by
    :func:`verify_entry_gate_raw`; it never returns or writes the bearer.  A
    failure writes whatever safe raw originals were obtained in the new UUID
    directory and raises ``EntryGateEvidenceError``.  It never manufactures a
    ``passed`` value.
    """
    _validate_endpoint(endpoint)
    if (
        not isinstance(token, str)
        or len(token.encode("utf-8")) < 32
        or any(character.isspace() or character in "\x00" for character in token)
    ):
        raise EntryGateEvidenceError("token must be an in-memory bearer value of at least 32 non-whitespace bytes")
    _validate_allowed_origin(allowed_origin)
    _require_nonempty(run_id, "run_id")
    _require_nonempty(restore_attempt_id, "restore_attempt_id")
    root = _validate_output_root(Path(output_root))
    evidence_dir = _new_evidence_dir(root)
    case_references: dict[str, dict[str, Any]] = {}
    counter_instance: str | None = None

    for case_name in CASE_NAMES:
        request_id, body = _initialize_payload(case_name)
        del request_id  # The verifier derives the expected ID from the stored case name.
        wire_headers, authorization_configured = _case_configuration(
            case_name, token, allowed_origin, body
        )
        request = _request_metadata(
            body, wire_headers, authorization_configured=authorization_configured
        )
        counter_before: dict[str, Any] | None = None
        counter_after: dict[str, Any] | None = None
        try:
            counter_before = _read_counter(
                counter_reader, run_id=run_id, restore_attempt_id=restore_attempt_id, token=token
            )
            response = _perform_http_request(endpoint, request, wire_headers, body)
            _ensure_token_absent(response, token, label="HTTP response")
            counter_after = _read_counter(
                counter_reader, run_id=run_id, restore_attempt_id=restore_attempt_id, token=token
            )
            instance = counter_before["instance"]
            if counter_after["instance"] != instance:
                raise EntryGateEvidenceError("handler-counter instance drifted within one request")
            if counter_instance is None:
                counter_instance = instance
            elif counter_instance != instance:
                raise EntryGateEvidenceError("handler-counter instance drifted across entry-gate cases")
            case_document = {
                "schema_version": 1,
                "kind": "p05-entry-gate-case-v1",
                "workflow_id": WORKFLOW_ID,
                "run_id": run_id,
                "restore_attempt_id": restore_attempt_id,
                "case": case_name,
                "request": request,
                "response": response,
                "counter_before": counter_before,
                "counter_after": counter_after,
            }
            case_path = evidence_dir / "cases" / f"{case_name}.json"
            _write_new_json(case_path, case_document, token)
            case_references[case_name] = _reference(root, case_path)
        except Exception as exc:
            counter_failure = getattr(exc, "raw_counter_original", None)
            _write_failure(
                evidence_dir,
                root,
                token,
                run_id=run_id,
                restore_attempt_id=restore_attempt_id,
                case_name=case_name,
                error=exc,
                request=request,
                counter_before=counter_before,
                counter_after=counter_after,
                counter_failure=counter_failure if isinstance(counter_failure, Mapping) else None,
                case_references=case_references,
            )
            if isinstance(exc, EntryGateEvidenceError):
                exc.evidence_dir = evidence_dir
                raise
            raise EntryGateEvidenceError(
                f"HTTP entry-gate collection failed in {case_name}: {type(exc).__name__}",
                evidence_dir=evidence_dir,
            ) from exc

    entry_gate = {
        "schema_version": 1,
        "workflow_id": WORKFLOW_ID,
        "run_id": run_id,
        "restore_attempt_id": restore_attempt_id,
        "cases": case_references,
    }
    entry_path = evidence_dir / "entry-gate.json"
    _write_new_json(entry_path, entry_gate, token)
    try:
        checked = verify_entry_gate_raw(
            entry_path,
            bundle_root=root,
            run_id=run_id,
            restore_attempt_id=restore_attempt_id,
            endpoint=endpoint,
            allowed_origin=allowed_origin,
        )
    except EntryGateEvidenceError as exc:
        _write_failure(
            evidence_dir,
            root,
            token,
            run_id=run_id,
            restore_attempt_id=restore_attempt_id,
            case_name="verification",
            error=exc,
            case_references=case_references,
        )
        exc.evidence_dir = evidence_dir
        raise
    return {
        "evidence_dir": evidence_dir,
        "entry_gate_path": entry_path,
        "entry_gate_ref": _reference(root, entry_path),
        "verified": checked,
    }


def _plain_file(root: Path, relative: str, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise EntryGateEvidenceError(f"{label}.path must be a non-empty POSIX relative path")
    path = PurePosixPath(relative)
    if path.is_absolute() or "\\" in relative or any(part in {"", ".", ".."} for part in path.parts):
        raise EntryGateEvidenceError(f"{label}.path is not a contained POSIX path")
    current = root
    for part in path.parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError as exc:
            raise EntryGateEvidenceError(f"{label}.path is missing") from exc
        if stat.S_ISLNK(info.st_mode):
            raise EntryGateEvidenceError(f"{label}.path traverses a link")
    if not stat.S_ISREG(current.lstat().st_mode):
        raise EntryGateEvidenceError(f"{label}.path is not a regular file")
    return current


def _resolve_ref(
    root: Path,
    reference: Any,
    label: str,
    seen: set[str],
) -> Path:
    if not isinstance(reference, Mapping) or set(reference) != REF_KEYS:
        raise EntryGateEvidenceError(f"{label} is not an exact Ref")
    size, digest = reference.get("size"), reference.get("sha256")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0 or not _is_sha256(digest):
        raise EntryGateEvidenceError(f"{label} Ref size or sha256 is invalid")
    path = _plain_file(root, reference.get("path"), label)
    relative = path.relative_to(root).as_posix()
    if relative in seen:
        raise EntryGateEvidenceError(f"{label} repeats a case original")
    seen.add(relative)
    content = path.read_bytes()
    if len(content) != size or _sha256_bytes(content) != digest:
        raise EntryGateEvidenceError(f"{label} Ref byte identity differs")
    return path


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EntryGateEvidenceError(f"{label} is not a UTF-8 JSON original") from exc
    if not isinstance(value, dict):
        raise EntryGateEvidenceError(f"{label} must be a JSON object")
    return value


def _headers_by_name(headers: Any, label: str, *, reject_duplicates: bool) -> dict[str, list[str]]:
    if not isinstance(headers, list):
        raise EntryGateEvidenceError(f"{label} headers must be a list")
    found: dict[str, list[str]] = {}
    for index, header in enumerate(headers):
        if not isinstance(header, Mapping) or set(header) != HEADER_KEYS:
            raise EntryGateEvidenceError(f"{label}.headers[{index}] is invalid")
        name, value = header.get("name"), header.get("value")
        if not isinstance(name, str) or not name or name != name.casefold() or not isinstance(value, str):
            raise EntryGateEvidenceError(f"{label}.headers[{index}] is not normalized text")
        if any(character in name + value for character in "\r\n\x00"):
            raise EntryGateEvidenceError(f"{label}.headers[{index}] contains an unsafe character")
        if reject_duplicates and name in found:
            raise EntryGateEvidenceError(f"{label} repeats normalized header {name!r}")
        found.setdefault(name, []).append(value)
    return found


def _validate_body(value: Any, label: str) -> str:
    if not isinstance(value, Mapping) or set(value) != BODY_KEYS:
        raise EntryGateEvidenceError(f"{label} body shape is invalid")
    text = value.get("text")
    if value.get("encoding") != "utf-8" or not isinstance(text, str):
        raise EntryGateEvidenceError(f"{label} body must retain UTF-8 text")
    encoded = text.encode("utf-8")
    if value.get("size") != len(encoded) or value.get("sha256") != _sha256_bytes(encoded):
        raise EntryGateEvidenceError(f"{label} body size or hash differs")
    return text


def _validate_counter_bracket(
    before: Any,
    after: Any,
    request: Mapping[str, Any],
    *,
    run_id: str,
    restore_attempt_id: str,
) -> tuple[int, str]:
    before_checked = _validate_counter(before, run_id=run_id, restore_attempt_id=restore_attempt_id)
    after_checked = _validate_counter(after, run_id=run_id, restore_attempt_id=restore_attempt_id)
    if before_checked["instance"] != after_checked["instance"]:
        raise EntryGateEvidenceError("handler-counter instance drifted within a recorded case")
    first = _parse_utc(request.get("first_utc"), "request.first_utc")
    last = _parse_utc(request.get("last_utc"), "request.last_utc")
    if first > last:
        raise EntryGateEvidenceError("request timestamps are reversed")
    if _parse_utc(before_checked["time"], "counter_before.time") > first:
        raise EntryGateEvidenceError("counter_before does not bracket request start")
    if _parse_utc(after_checked["time"], "counter_after.time") < last:
        raise EntryGateEvidenceError("counter_after does not bracket request end")
    return after_checked["count"] - before_checked["count"], before_checked["instance"]


def _parse_initialize_response(body: str, request_id: str) -> None:
    messages: list[Any]
    try:
        parsed = json.loads(body)
        messages = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        messages = []
        event_data: list[str] = []
        for line in body.splitlines():
            if not line:
                if event_data:
                    try:
                        messages.append(json.loads("\n".join(event_data)))
                    except json.JSONDecodeError as exc:
                        raise EntryGateEvidenceError("SSE response contains non-JSON data") from exc
                    event_data = []
                continue
            if line.startswith("data:"):
                event_data.append(line[5:].lstrip(" "))
        if event_data:
            try:
                messages.append(json.loads("\n".join(event_data)))
            except json.JSONDecodeError as exc:
                raise EntryGateEvidenceError("SSE response contains non-JSON data") from exc
        if not messages:
            raise EntryGateEvidenceError("initialize response is neither JSON nor JSON SSE")
    matches = [message for message in messages if isinstance(message, Mapping) and message.get("id") == request_id]
    if len(matches) != 1:
        raise EntryGateEvidenceError("initialize response does not contain exactly one matching JSON-RPC id")
    message = matches[0]
    result = message.get("result")
    if (
        message.get("jsonrpc") != "2.0"
        or "error" in message
        or not isinstance(result, Mapping)
        or not isinstance(result.get("protocolVersion"), str)
        or not result["protocolVersion"]
        or not isinstance(result.get("capabilities"), Mapping)
        or not isinstance(result.get("serverInfo"), Mapping)
    ):
        raise EntryGateEvidenceError("matching initialize response lacks protocolVersion/capabilities/serverInfo")


def _validate_request(
    request: Any,
    *,
    case_name: str,
    allowed_origin: str,
) -> tuple[Mapping[str, Any], dict[str, list[str]]]:
    if not isinstance(request, Mapping) or set(request) != REQUEST_KEYS:
        raise EntryGateEvidenceError(f"{case_name} request shape is invalid")
    if request.get("method") != "POST" or request.get("target") != MCP_PATH or request.get("http_version") != "HTTP/1.1":
        raise EntryGateEvidenceError(f"{case_name} request does not target the fixed MCP entry")
    headers = _headers_by_name(request.get("headers"), f"{case_name} request", reject_duplicates=True)
    if "authorization" in headers or "proxy-authorization" in headers:
        raise EntryGateEvidenceError(f"{case_name} persisted an Authorization header")
    body = _validate_body(request.get("body"), f"{case_name} request")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise EntryGateEvidenceError(f"{case_name} request body is not JSON") from exc
    expected_id = f"entry-gate:{case_name}"
    if (
        not isinstance(payload, Mapping)
        or payload.get("jsonrpc") != "2.0"
        or payload.get("id") != expected_id
        or payload.get("method") != "initialize"
        or not isinstance(payload.get("params"), Mapping)
        or not isinstance(payload["params"].get("protocolVersion"), str)
        or not isinstance(payload["params"].get("capabilities"), Mapping)
        or not isinstance(payload["params"].get("clientInfo"), Mapping)
    ):
        raise EntryGateEvidenceError(f"{case_name} is not the required initialize request")
    expected_headers = {
        "content-type": ["application/json"],
        "accept": ["application/json, text/event-stream"],
        "content-length": [str(len(body.encode("utf-8")))],
    }
    if case_name != "missing_host":
        expected_headers["host"] = [REJECTED_HOST if case_name == "wrong_host" else f"{GUEST_HOST}:{SERVICE_PORT}"]
    if case_name == "allowed_origin":
        expected_headers["origin"] = [allowed_origin]
    elif case_name == "wrong_origin":
        expected_headers["origin"] = [REJECTED_ORIGIN]
    if headers != expected_headers:
        raise EntryGateEvidenceError(f"{case_name} request headers are not the exact normalized probe")
    expected_auth = case_name != "missing_bearer"
    if request.get("authorization_configured") is not expected_auth:
        raise EntryGateEvidenceError(f"{case_name} authorization metadata is invalid")
    return request, headers


def _validate_case(
    document: Mapping[str, Any],
    *,
    case_name: str,
    run_id: str,
    restore_attempt_id: str,
    allowed_origin: str,
) -> tuple[int, str, str | None, str | None]:
    if (
        set(document) != CASE_KEYS
        or document.get("schema_version") != 1
        or document.get("kind") != "p05-entry-gate-case-v1"
        or document.get("workflow_id") != WORKFLOW_ID
        or document.get("run_id") != run_id
        or document.get("restore_attempt_id") != restore_attempt_id
        or document.get("case") != case_name
    ):
        raise EntryGateEvidenceError(f"{case_name} original shape or identity is invalid")
    request, _ = _validate_request(document.get("request"), case_name=case_name, allowed_origin=allowed_origin)
    response = document.get("response")
    if not isinstance(response, Mapping) or set(response) != RESPONSE_KEYS:
        raise EntryGateEvidenceError(f"{case_name} response shape is invalid")
    status = response.get("status")
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599 or not isinstance(response.get("reason"), str):
        raise EntryGateEvidenceError(f"{case_name} response status is invalid")
    response_headers = _headers_by_name(response.get("headers"), f"{case_name} response", reject_duplicates=False)
    response_body = _validate_body(response.get("body"), f"{case_name} response")
    delta, instance = _validate_counter_bracket(
        document.get("counter_before"), document.get("counter_after"), request,
        run_id=run_id, restore_attempt_id=restore_attempt_id,
    )
    session_ids = response_headers.get("mcp-session-id", [])
    instance_ids = response_headers.get("x-mcp-server-instance", [])
    if case_name in {"no_origin", "allowed_origin"}:
        if status != 200 or delta != 1:
            raise EntryGateEvidenceError(f"{case_name} did not have 200 and exactly one handler call")
        if len(session_ids) != 1 or not session_ids[0] or len(instance_ids) != 1 or not instance_ids[0]:
            raise EntryGateEvidenceError(f"{case_name} success lacks exactly one session and instance header")
        if instance_ids[0] != instance:
            raise EntryGateEvidenceError(
                f"{case_name} response instance does not match the handler-counter instance"
            )
        _parse_initialize_response(response_body, f"entry-gate:{case_name}")
        return delta, instance, session_ids[0], instance_ids[0]
    expected_status: int | tuple[int, ...]
    if case_name in {"missing_bearer", "wrong_bearer"}:
        expected_status = 401
    elif case_name == "missing_host":
        expected_status = (400, 421)
    elif case_name == "wrong_host":
        expected_status = 421
    elif case_name == "wrong_origin":
        expected_status = 403
    else:  # pragma: no cover - protected by CASE_NAMES
        raise EntryGateEvidenceError(f"unknown case {case_name!r}")
    if status not in (expected_status if isinstance(expected_status, tuple) else (expected_status,)) or delta != 0:
        raise EntryGateEvidenceError(f"{case_name} response status or handler delta is invalid")
    return delta, instance, None, None


def verify_entry_gate_raw(
    document: Mapping[str, Any] | Path | str,
    *,
    bundle_root: Path,
    run_id: str,
    restore_attempt_id: str,
    endpoint: str,
    allowed_origin: str,
) -> dict[str, Any]:
    """Recompute the seven P05 §0.7 predicates from case Refs and raw originals.

    There is deliberately no accepted ``passed`` field.  This parser checks
    Ref byte identity, every stored response, parsed JSON/SSE initialize
    semantics, handler-counter bracket/delta, and header normalization.
    """
    _validate_endpoint(endpoint)
    _validate_allowed_origin(allowed_origin)
    _require_nonempty(run_id, "run_id")
    _require_nonempty(restore_attempt_id, "restore_attempt_id")
    root = _validate_output_root(Path(bundle_root))
    if isinstance(document, (str, Path)):
        candidate = Path(document)
        try:
            relative = candidate.relative_to(root).as_posix()
        except ValueError as exc:
            raise EntryGateEvidenceError("entry-gate document is outside the evidence package") from exc
        candidate = _plain_file(root, relative, "entry-gate document")
        entry_gate = _read_json(candidate, "entry gate")
    elif isinstance(document, Mapping):
        entry_gate = dict(document)
    else:
        raise EntryGateEvidenceError("entry-gate document must be a mapping or JSON file")
    if (
        set(entry_gate) != ENTRY_GATE_KEYS
        or entry_gate.get("schema_version") != 1
        or entry_gate.get("workflow_id") != WORKFLOW_ID
        or entry_gate.get("run_id") != run_id
        or entry_gate.get("restore_attempt_id") != restore_attempt_id
        or not isinstance(entry_gate.get("cases"), Mapping)
        or set(entry_gate["cases"]) != set(CASE_NAMES)
    ):
        raise EntryGateEvidenceError("entry-gate exact keys or phase identity is invalid")
    seen: set[str] = set()
    observed_counter_instance: str | None = None
    sessions: dict[str, str] = {}
    response_instances: dict[str, str] = {}
    for case_name in CASE_NAMES:
        case_path = _resolve_ref(root, entry_gate["cases"][case_name], f"entry_gate.cases.{case_name}", seen)
        delta, counter_instance, session, response_instance = _validate_case(
            _read_json(case_path, f"{case_name} case"),
            case_name=case_name,
            run_id=run_id,
            restore_attempt_id=restore_attempt_id,
            allowed_origin=allowed_origin,
        )
        del delta
        if observed_counter_instance is None:
            observed_counter_instance = counter_instance
        elif observed_counter_instance != counter_instance:
            raise EntryGateEvidenceError("handler-counter instance drifted across recorded cases")
        if session is not None and response_instance is not None:
            sessions[case_name] = session
            response_instances[case_name] = response_instance
    return {
        "case_count": len(CASE_NAMES),
        "handler_instance": observed_counter_instance,
        "initialize_sessions": sessions,
        "initialize_response_instances": response_instances,
    }
