"""Deployment-only observation of the existing SDK POST handler.

No HTTP route, authentication exception, or second MCP server is introduced.
The version/source-guarded wrapper delegates to the original SDK method once.
Only public process/instance identity and an integer counter reach disk.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
import base64
import ctypes
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.metadata
import inspect
import json
import os
from pathlib import Path, PureWindowsPath
import stat
import sys
import threading
from typing import Any
import uuid


SDK_ENTRY_SHA256 = 'ace631d016dcfc1083bfdb47cd6048aa3c7ad7f39d542c4e8ac2ffdaeb687150'
SDK_SECURITY_SHA256 = '8b6eed18be27a6b6465e5b2313dc2a036a48455bcd51771c3dbda63598c426c0'
SERVICE_NAME = 'mcp-velociraptor'
DISPATCH_COUNTER_KEYS = {
    'schema_version', 'kind', 'counter_id', 'server_instance_id', 'pid',
    'process_start_time_utc', 'executable_sha256', 'count', 'observed_at',
}
SERVICE_SNAPSHOT_KEYS = {'name', 'pid', 'process_start_time_utc', 'executable_sha256'}
EXECUTION_KEYS = {
    'argv', 'command_line', 'started_at', 'ended_at', 'exit_status', 'stdout', 'stderr',
}
DISCOVERY_KEYS = {'service_before', 'candidates', 'excluded', 'service_after'}
CANDIDATE_KEYS = {'path', 'size', 'sha256', 'body_base64'}
EXCLUDED_KEYS = {'path', 'name', 'reason'}
_LOCK = threading.Lock()


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _process_identity() -> dict:
    if os.name != 'nt':
        raise RuntimeError('Service observation requires the Windows deployment')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_ulonglong)] * 4
    kernel.GetProcessTimes.restype = ctypes.c_int
    created, exited, system, user = (ctypes.c_ulonglong() for _ in range(4))
    if not kernel.GetProcessTimes(kernel.GetCurrentProcess(), ctypes.byref(created),
                                  ctypes.byref(exited), ctypes.byref(system), ctypes.byref(user)):
        raise RuntimeError('Service process creation time could not be observed')
    instant = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=created.value // 10)
    return {
        'pid': os.getpid(), 'process_start_time_utc': instant.isoformat().replace('+00:00', 'Z'),
        'executable_sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
    }


def _plain_directory(path: Path) -> None:
    for item in (path, *path.parents):
        info = item.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info, 'st_file_attributes', 0) & 0x400):
            raise RuntimeError('Service observation directory is not plain')


class DispatchCounter:
    """One process-owned mutable observation; immutable captures live elsewhere."""
    def __init__(self, logs_root: Path, identity: dict):
        if not logs_root.exists():
            _plain_directory(logs_root.parent)
            logs_root.mkdir()
        _plain_directory(logs_root)
        directory = logs_root / 'p05-dispatch'
        directory.mkdir(exist_ok=True)
        _plain_directory(directory)
        self.counter_id = str(uuid.uuid4())
        self.path = directory / (self.counter_id + '.json')
        self.identity = dict(identity)
        self.instance_id = None
        self.count = 0
        self.previous = None

    def bind_instance(self, instance_id: str) -> None:
        if self.instance_id is not None or not isinstance(instance_id, str) or not instance_id:
            raise RuntimeError('Service observation requires exactly one server instance')
        self.instance_id = instance_id
        self._write()

    def increment(self) -> None:
        if self.instance_id is None:
            raise RuntimeError('Service handler ran without its instance observation')
        self.count += 1
        self._write()

    def _write(self) -> None:
        payload = (json.dumps({
            'schema_version': 1, 'kind': 'p05-service-dispatch-counter-v1',
            'counter_id': self.counter_id, 'server_instance_id': self.instance_id,
            **self.identity, 'count': self.count, 'observed_at': _utc(),
        }, sort_keys=True, separators=(',', ':')) + '\n').encode()
        if self.previous is None:
            with self.path.open('xb') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        else:
            info = self.path.lstat()
            if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or getattr(info, 'st_file_attributes', 0) & 0x400
                    or self.path.read_bytes() != self.previous):
                raise RuntimeError('Service observation ownership or bytes changed')
            next_path = self.path.with_suffix('.next')
            with next_path.open('xb') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(next_path, self.path)
        self.previous = payload


def _parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise RuntimeError(f'{label} must be a non-empty UTC RFC3339 value')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise RuntimeError(f'{label} is not RFC3339') from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise RuntimeError(f'{label} must be UTC')
    return parsed.astimezone(timezone.utc)


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str) and len(value) == 64
        and all(character in '0123456789abcdef' for character in value)
    )


def _canonical_uuid(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise RuntimeError(f'{label} must be a UUID string')
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise RuntimeError(f'{label} must be a UUID string') from exc
    if str(parsed) != value:
        raise RuntimeError(f'{label} must be a canonical UUID')
    return value


def _service_snapshot(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != SERVICE_SNAPSHOT_KEYS:
        raise RuntimeError(f'{label} has invalid service identity keys')
    identity = dict(value)
    if identity['name'] != SERVICE_NAME:
        raise RuntimeError(f'{label} service name is invalid')
    if not isinstance(identity['pid'], int) or isinstance(identity['pid'], bool) or identity['pid'] <= 0:
        raise RuntimeError(f'{label} service PID is invalid')
    _parse_utc(identity['process_start_time_utc'], f'{label} process start')
    if not _valid_sha256(identity['executable_sha256']):
        raise RuntimeError(f'{label} service executable hash is invalid')
    return identity


def _dispatch_directory(value: str) -> str:
    if not isinstance(value, str) or any(character in value for character in '\r\n\x00\'`'):
        raise RuntimeError('dispatch directory is unsafe')
    path = PureWindowsPath(value)
    if (
        not path.is_absolute() or not path.drive
        or path.name.casefold() != 'p05-dispatch'
        or path.parent.name.casefold() != 'logs'
        or any(part in {'.', '..'} for part in path.parts)
    ):
        raise RuntimeError('dispatch directory must be the fixed Logs/p05-dispatch directory')
    return str(path)


def _powershell_script(dispatch_directory: str) -> str:
    """Read every ordinary UUID counter without using mtime or newest-file logic."""
    literal = dispatch_directory.replace("'", "''")
    return "\n".join((
        "$ErrorActionPreference = 'Stop'",
        # Walk every ancestor with Get-Item: a .Parent-derived .NET instance
        # does not carry the provider-added PSProvider property, so the
        # explicit per-ancestor provider read is the only reliable form.
        "function Assert-P05PlainPath([string]$Path) {",
        "  $full = [IO.Path]::GetFullPath($Path)",
        "  if ($full -notmatch '^[A-Za-z]:\\\\') { throw 'non-filesystem or non-local path' }",
        "  $segments = @($full -split '\\\\' | Where-Object { $_ -ne '' })",
        "  $prefix = $segments[0]",
        "  for ($i = 1; $i -lt $segments.Count; $i++) {",
        "    $prefix = \"$prefix\\$($segments[$i])\"",
        "    $item = Get-Item -Force -LiteralPath $prefix -ErrorAction Stop",
        "    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw \"reparse point on path or ancestry: $prefix\" }",
        "  }",
        "}",
        "function Get-P05ServiceIdentity {",
        f"  $service = Get-CimInstance -ClassName Win32_Service -Filter \"Name='{SERVICE_NAME}'\"",
        "  if ($null -eq $service -or [int]$service.ProcessId -le 0) { throw 'service process unavailable' }",
        "  $process = Get-Process -Id ([int]$service.ProcessId) -ErrorAction Stop",
        "  if ([string]::IsNullOrWhiteSpace($process.Path)) { throw 'service executable unavailable' }",
        "  $hash = (Get-FileHash -LiteralPath $process.Path -Algorithm SHA256).Hash.ToLowerInvariant()",
        "  return [ordered]@{ name = [string]$service.Name; pid = [int]$process.Id; process_start_time_utc = $process.StartTime.ToUniversalTime().ToString('o'); executable_sha256 = $hash }",
        "}",
        f"$directory = Get-Item -Force -LiteralPath '{literal}' -ErrorAction Stop",
        "Assert-P05PlainPath $directory.FullName",
        "if (-not $directory.PSIsContainer) { throw 'dispatch path is not a directory' }",
        "$before = Get-P05ServiceIdentity",
        "$candidates = @()",
        "$excluded = @()",
        "foreach ($item in @(Get-ChildItem -Force -LiteralPath $directory.FullName -ErrorAction Stop)) {",
        "  $name = [string]$item.Name",
        "  $path = [string]$item.FullName",
        "  if ($item.PSIsContainer) { $excluded += [ordered]@{ path = $path; name = $name; reason = 'not_regular_file' }; continue }",
        "  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $excluded += [ordered]@{ path = $path; name = $name; reason = 'reparse_point' }; continue }",
        "  if (-not ($item -is [System.IO.FileInfo])) { $excluded += [ordered]@{ path = $path; name = $name; reason = 'not_regular_file' }; continue }",
        "  if ($name -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.json$') { $excluded += [ordered]@{ path = $path; name = $name; reason = 'not_canonical_uuid_json' }; continue }",
        "  Assert-P05PlainPath $item.FullName",
        "  $bytes = [IO.File]::ReadAllBytes($item.FullName)",
        "  Assert-P05PlainPath (Get-Item -Force -LiteralPath $item.FullName -ErrorAction Stop).FullName",
        "  $sha = New-Object Security.Cryptography.SHA256Managed",
        "  try { $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }",
        "  $candidates += [ordered]@{ path = $path; size = [int64]$bytes.Length; sha256 = $hash; body_base64 = [Convert]::ToBase64String($bytes) }",
        "}",
        "$after = Get-P05ServiceIdentity",
        "[ordered]@{ service_before = $before; candidates = $candidates; excluded = $excluded; service_after = $after } | ConvertTo-Json -Compress -Depth 8",
    ))


def _execution_original(value: Any, expected_argv: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != EXECUTION_KEYS:
        raise RuntimeError('PowerShell callback did not return a complete execution original')
    original = dict(value)
    if original['argv'] != list(expected_argv) or not isinstance(original['command_line'], str) or not original['command_line']:
        raise RuntimeError('PowerShell callback command differs from the fixed read-only projection')
    if (
        not isinstance(original['exit_status'], Mapping)
        or set(original['exit_status']) != {'code'}
        or original['exit_status'].get('code') != 0
        or not isinstance(original['stdout'], str)
        or not isinstance(original['stderr'], str)
    ):
        raise RuntimeError('PowerShell callback did not retain a successful complete command output')
    started = _parse_utc(original['started_at'], 'PowerShell command start')
    ended = _parse_utc(original['ended_at'], 'PowerShell command end')
    if started > ended:
        raise RuntimeError('PowerShell command timestamps are reversed')
    return original


def _discovery_original_from_execution(
    value: Any,
    *,
    expected_argv: tuple[str, ...],
    run_id: str,
    restore_attempt_id: str,
) -> dict[str, Any] | None:
    """Retain a complete command attempt even when its selection must fail."""
    if not isinstance(value, Mapping) or set(value) != EXECUTION_KEYS:
        return None
    original = dict(value)
    if (
        original.get('argv') != list(expected_argv)
        or not isinstance(original.get('command_line'), str)
        or not original['command_line']
        or not isinstance(original.get('exit_status'), Mapping)
        or set(original['exit_status']) != {'code'}
        or not isinstance(original['exit_status'].get('code'), int)
        or isinstance(original['exit_status'].get('code'), bool)
        or not isinstance(original.get('stdout'), str)
        or not isinstance(original.get('stderr'), str)
    ):
        return None
    try:
        _parse_utc(original.get('started_at'), 'PowerShell command start')
        _parse_utc(original.get('ended_at'), 'PowerShell command end')
    except RuntimeError:
        return None
    return {
        'schema_version': 1,
        'kind': 'p05-service-dispatch-discovery-v1',
        'workflow_id': 'wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2',
        'run_id': run_id,
        'restore_attempt_id': restore_attempt_id,
        'command': {
            'argv': original['argv'], 'command_line': original['command_line'],
            'started_at': original['started_at'], 'ended_at': original['ended_at'],
            'exit_status': dict(original['exit_status']),
        },
        'output': {
            'stdout': original['stdout'],
            'stdout_size': len(original['stdout'].encode('utf-8')),
            'stdout_sha256': hashlib.sha256(original['stdout'].encode('utf-8')).hexdigest(),
            'stderr': original['stderr'],
            'stderr_size': len(original['stderr'].encode('utf-8')),
            'stderr_sha256': hashlib.sha256(original['stderr'].encode('utf-8')).hexdigest(),
        },
    }


class DispatchCounterSelectionError(RuntimeError):
    """Discovery retained an original but could not identify one live counter."""

    def __init__(self, message: str, raw_original: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.raw_original = dict(raw_original)


def _counter_bytes(value: Any, directory: PureWindowsPath) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != CANDIDATE_KEYS:
        raise RuntimeError('dispatch candidate has invalid raw-file keys')
    path = PureWindowsPath(value.get('path')) if isinstance(value.get('path'), str) else None
    if (
        path is None or path.parent != directory or not path.name
        or str(path) != value.get('path') or any(part in {'.', '..'} for part in path.parts)
    ):
        raise RuntimeError('dispatch candidate path is not one direct fixed-directory child')
    counter_id = _canonical_uuid(path.stem, 'dispatch candidate filename')
    if path.name != f'{counter_id}.json':
        raise RuntimeError('dispatch candidate filename is not canonical')
    size, digest, encoded = value.get('size'), value.get('sha256'), value.get('body_base64')
    if not isinstance(size, int) or isinstance(size, bool) or size < 0 or not _valid_sha256(digest) or not isinstance(encoded, str):
        raise RuntimeError('dispatch candidate raw byte identity is invalid')
    try:
        content = base64.b64decode(encoded.encode('ascii'), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise RuntimeError('dispatch candidate bytes are not valid base64') from exc
    if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
        raise RuntimeError('dispatch candidate byte identity differs')
    try:
        document = json.loads(content.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError('dispatch candidate is not UTF-8 JSON') from exc
    if not isinstance(document, Mapping):
        raise RuntimeError('dispatch candidate JSON must be an object')
    return dict(document), dict(value)


def _dispatch_payload(
    value: Any,
    *,
    directory: str,
) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
    """Return the one live counter, its exact raw path, and excluded facts.

    The path is deliberately taken from the byte-identified candidate, rather
    than reconstructed from an ID or chosen by file time.  The factory below
    consumes the selection immediately; its externally visible callback keeps
    the already-frozen HTTP-counter shape, whose complete command stdout is
    the durable record containing every candidate and each old identity.
    """
    if not isinstance(value, Mapping) or set(value) != DISCOVERY_KEYS:
        raise RuntimeError('PowerShell discovery projection has invalid keys')
    before = _service_snapshot(value.get('service_before'), 'service_before')
    after = _service_snapshot(value.get('service_after'), 'service_after')
    if (
        before['pid'] != after['pid']
        or before['executable_sha256'] != after['executable_sha256']
        or _parse_utc(before['process_start_time_utc'], 'service_before process start')
        != _parse_utc(after['process_start_time_utc'], 'service_after process start')
    ):
        raise RuntimeError('service identity changed while dispatch counters were read')
    candidates, excluded = value.get('candidates'), value.get('excluded')
    if not isinstance(candidates, list) or not isinstance(excluded, list):
        raise RuntimeError('PowerShell discovery candidates or exclusions are not lists')
    if excluded:
        for entry in excluded:
            if not isinstance(entry, Mapping) or set(entry) != EXCLUDED_KEYS or not all(isinstance(entry.get(key), str) and entry[key] for key in EXCLUDED_KEYS):
                raise RuntimeError('PowerShell discovery exclusion is malformed')
        if any(entry['reason'] == 'reparse_point' for entry in excluded):
            raise RuntimeError('dispatch directory contains a reparse-point child')
    selected: list[tuple[dict[str, Any], str]] = []
    exclusion_facts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    fixed_directory = PureWindowsPath(directory)
    for raw_candidate in candidates:
        counter, raw = _counter_bytes(raw_candidate, fixed_directory)
        if raw['path'] in seen_paths:
            raise RuntimeError('PowerShell discovery repeated a candidate path')
        seen_paths.add(raw['path'])
        if not isinstance(counter, Mapping) or set(counter) != DISPATCH_COUNTER_KEYS:
            raise RuntimeError('dispatch counter has invalid keys')
        if (
            counter.get('schema_version') != 1
            or counter.get('kind') != 'p05-service-dispatch-counter-v1'
            or counter.get('counter_id') != PureWindowsPath(raw['path']).stem
            or not isinstance(counter.get('count'), int)
            or isinstance(counter.get('count'), bool)
            or counter['count'] < 0
            or not isinstance(counter.get('server_instance_id'), str)
            or not counter['server_instance_id']
            or not isinstance(counter.get('pid'), int)
            or isinstance(counter.get('pid'), bool)
            or counter['pid'] <= 0
            or not _valid_sha256(counter.get('executable_sha256'))
        ):
            raise RuntimeError('dispatch counter values are invalid')
        _parse_utc(counter.get('process_start_time_utc'), 'counter process start')
        _parse_utc(counter.get('observed_at'), 'counter observed time')
        same_process = (
            counter['pid'] == before['pid']
            and counter['executable_sha256'] == before['executable_sha256']
            and _parse_utc(counter['process_start_time_utc'], 'counter process start')
            == _parse_utc(before['process_start_time_utc'], 'service_before process start')
        )
        if same_process:
            selected.append((dict(counter), raw['path']))
        else:
            exclusion_facts.append({
                'counter_id': counter['counter_id'], 'path': raw['path'],
                'reason': 'process_identity_mismatch',
            })
    if len(selected) != 1:
        raise RuntimeError(
            f'dispatch discovery requires exactly one current service counter, found {len(selected)}'
        )
    counter, counter_path = selected[0]
    return counter, counter_path, exclusion_facts


def make_http_counter_reader(
    execute_powershell: Callable[[tuple[str, ...]], Mapping[str, Any]],
    *,
    dispatch_directory: str,
    run_id: str,
    restore_attempt_id: str,
) -> Callable[[], dict[str, Any]]:
    """Discover one live service counter for ``probe_entry_gate``'s callback.

    ``execute_powershell`` is supplied by the outer Windows evidence collector;
    this function starts neither a VM nor a service and never selects by mtime
    or newest file.  Every ordinary canonical UUID counter under the fixed
    dispatch directory is raw-read, then one is selected only if its PID,
    creation time, and executable hash exactly match the live SCM process.
    The HTTP verifier separately joins its instance to the actual response
    header.  The result is the raw ``p05-http-handler-counter-v1`` expected by
    :func:`tests.p05_http_evidence.probe_entry_gate`.
    """
    if not callable(execute_powershell):
        raise RuntimeError('execute_powershell must be a command callback')
    selected_directory = _dispatch_directory(dispatch_directory)
    if not isinstance(run_id, str) or not run_id or not isinstance(restore_attempt_id, str) or not restore_attempt_id:
        raise RuntimeError('counter reader run and restore identifiers are required')
    script = _powershell_script(selected_directory)
    argv = ('powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script)

    def read_counter() -> dict[str, Any]:
        try:
            callback_result = execute_powershell(argv)
        except Exception as exc:
            raw_original = getattr(exc, 'raw_original', None)
            if isinstance(raw_original, Mapping):
                raise DispatchCounterSelectionError(
                    f'PowerShell counter read failed: {type(exc).__name__}', raw_original
                ) from exc
            raise RuntimeError(f'PowerShell counter read failed: {type(exc).__name__}') from exc
        raw_original = _discovery_original_from_execution(
            callback_result,
            expected_argv=argv,
            run_id=run_id,
            restore_attempt_id=restore_attempt_id,
        )
        try:
            execution = _execution_original(callback_result, argv)
        except Exception as exc:
            if raw_original is not None:
                raise DispatchCounterSelectionError(
                    f'dispatch counter command rejected: {type(exc).__name__}', raw_original
                ) from exc
            raise RuntimeError(f'PowerShell counter read failed: {type(exc).__name__}') from exc
        if raw_original is None:  # protected by _execution_original, retained for type safety
            raise RuntimeError('PowerShell counter read has no complete raw original')
        try:
            projection = json.loads(execution['stdout'])
        except json.JSONDecodeError as exc:
            raise DispatchCounterSelectionError(
                'dispatch counter discovery stdout is not JSON', raw_original
            ) from exc
        try:
            counter, counter_path, exclusion_facts = _dispatch_payload(
                projection, directory=selected_directory
            )
        except Exception as exc:
            raise DispatchCounterSelectionError(
                f'dispatch counter discovery rejected: {type(exc).__name__}', raw_original
            ) from exc
        # The exact selected ID/path are the adapter's internal output.  The
        # strict p05-http-handler-counter-v1 contract must not grow fields
        # that would turn derived selection data into a claimed command
        # original.  Full candidates (and therefore these exclusion facts)
        # remain byte-for-byte in the retained stdout.
        if counter['counter_id'] != PureWindowsPath(counter_path).stem:
            raise RuntimeError('selected dispatch counter path and ID drifted')
        del exclusion_facts
        stdout = execution['stdout']
        stderr = execution['stderr']
        return {
            'schema_version': 1,
            'kind': 'p05-http-handler-counter-v1',
            'workflow_id': 'wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2',
            'run_id': run_id,
            'restore_attempt_id': restore_attempt_id,
            'count': counter['count'],
            'instance': counter['server_instance_id'],
            'time': execution['ended_at'],
            'command': {
                'argv': execution['argv'],
                'command_line': execution['command_line'],
                'exit_status': dict(execution['exit_status']),
            },
            'output': {
                'stdout': stdout,
                'stdout_size': len(stdout.encode('utf-8')),
                'stdout_sha256': hashlib.sha256(stdout.encode('utf-8')).hexdigest(),
                'stderr': stderr,
                'stderr_size': len(stderr.encode('utf-8')),
                'stderr_sha256': hashlib.sha256(stderr.encode('utf-8')).hexdigest(),
            },
        }

    return read_counter


def _verify_sdk(entry, security) -> None:
    if importlib.metadata.version('mcp') != '2.1.1':
        raise RuntimeError('The service observation SDK version needs requalification')
    for function, expected in ((entry, SDK_ENTRY_SHA256), (security, SDK_SECURITY_SHA256)):
        if hashlib.sha256(inspect.getsource(function).encode()).hexdigest() != expected:
            raise RuntimeError('The observed SDK security/dispatch boundary has changed')


@contextmanager
def observe_dispatch(logs_root: Path):
    """Observe only calls reaching POST dispatch after SDK Host/Origin checks."""
    from mcp.server.streamable_http import StreamableHTTPServerTransport
    from mcp.server.transport_security import TransportSecurityMiddleware
    import velociraptor_transport

    if not _LOCK.acquire(blocking=False):
        raise RuntimeError('Another service observation is already installed')
    original_post = StreamableHTTPServerTransport._handle_post_request
    original_instance = velociraptor_transport.new_server_instance_id
    installed = False
    try:
        _verify_sdk(StreamableHTTPServerTransport.handle_request,
                    TransportSecurityMiddleware.validate_request)
        if list(inspect.signature(original_post).parameters) != ['self', 'scope', 'request', 'receive', 'send']:
            raise RuntimeError('The SDK POST dispatch signature has changed')
        counter = DispatchCounter(logs_root, _process_identity())

        def identify_instance():
            value = original_instance()
            counter.bind_instance(value)
            return value

        async def observed_post(transport, scope, request, receive, send):
            counter.increment()
            return await original_post(transport, scope, request, receive, send)

        StreamableHTTPServerTransport._handle_post_request = observed_post
        velociraptor_transport.new_server_instance_id = identify_instance
        installed = True
        yield counter
    finally:
        if installed:
            StreamableHTTPServerTransport._handle_post_request = original_post
            velociraptor_transport.new_server_instance_id = original_instance
        _LOCK.release()
