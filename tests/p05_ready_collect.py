"""Read-only guest-side raw originals for the P05 ``ready`` validator.

This module is deliberately an integration seam, not a product CLI.  The
outer restore workflow supplies the reserved run and restore identities and
copies the reviewed ``source/`` tree into the activation bundle.  It supplies
the two host observations separately: guest code must never invent host clock
or host process evidence.

Only fixed PowerShell/CIM/netsh reads, root-org read-only VQL, and the
reviewed localhost-only dependency byte read are used.  A collection failure
writes the command transcript that caused it to a freshly created evidence
directory and raises; it never changes a failed observation to an
``ok``/``passed`` summary.  In particular, this module does not start or stop
services, alter ACLs or firewall rules, make non-local HTTP requests, create
flows or hunts, or read protected configuration contents.

The dependency byte witness uses the reviewed, existing localhost-only HTTPS
reader in ``p05_dependency_acceptance.verify_local_public_bytes``.  It runs
only when this collector is invoked in the approved guest.  Development and
static tests never invoke it.  The resulting URL, byte length, and SHA-256
are observed values, never copied from the manifest.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import subprocess
import sys
from typing import Any, Mapping, Sequence


WORKFLOW_ID = "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2"
GUEST_NAME = "DESKTOP-3FI41GR"
CLIENT_ID = "C.21794325e524a33d"
FIXTURE_ROOT = r"C:\VelociraptorMCP\fixtures-p05"
FIXTURE_INSTANCE = FIXTURE_ROOT + r"\fixture-instance-v1.json"
SERVICE_NAME = "mcp-velociraptor"
SERVICE_ACCOUNT = r"NT SERVICE\mcp-velociraptor"
SERVICE_PORT = 28790
GUEST_ADDRESS = "192.168.204.232"
HOST_ADDRESS = "192.168.204.1"
DEPENDENCY_NAMES = ("Autorun_386", "Autorun_amd64")
OBSERVATIONS = (
    "guest_identity",
    "fixture_instance",
    "fixture_static",
    "parent_bindings",
    "guest_processes",
    "dependencies",
    "service",
    "acl",
    "firewall",
    "resources",
)


class ReadyCollectionError(RuntimeError):
    """A guest raw original could not be safely collected."""


class CollectionGap(ReadyCollectionError):
    """The required fact has no approved read-only observation interface."""


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    stdout: str
    stderr: str
    exit_code: int
    started_at: str
    ended_at: str


@dataclass(frozen=True)
class SourceBundle:
    """Fixed guest paths selected by the outer, reviewed source bundle."""

    guest_repo_root: str

    def __post_init__(self) -> None:
        path = PureWindowsPath(self.guest_repo_root)
        if (
            not path.drive
            or not path.root
            or self.guest_repo_root.startswith("\\\\")
            or any(part in {".", ".."} for part in path.parts)
            or any(character in self.guest_repo_root for character in ("\x00", "\r", "\n", "'"))
        ):
            raise ValueError("guest_repo_root must be a local absolute Windows path")

    @property
    def fixture_spec(self) -> str:
        return str(PureWindowsPath(self.guest_repo_root) / "tests" / "data" / "p05_fixture_spec.json")

    @property
    def dependency_manifest(self) -> str:
        return str(PureWindowsPath(self.guest_repo_root) / "tests" / "data" / "p05_dependency_manifest.json")

    @property
    def parent_source(self) -> str:
        return str(PureWindowsPath(self.guest_repo_root) / "tests" / "p05_process_parent.py")

    @property
    def kill_artifact(self) -> str:
        return str(PureWindowsPath(self.guest_repo_root) / "tests" / "fixtures" / "artifacts" / "Generic.Utils.KillProcess.yaml")

    @property
    def parent_records(self) -> str:
        return str(PureWindowsPath(self.guest_repo_root) / "Logs" / "P05" / "process-parents")


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def command_line(argv: Sequence[str]) -> str:
    """Return the Windows command line actually supplied to subprocess."""
    return subprocess.list2cmdline(list(argv))


def _decode_utf8(value: bytes, stream: str) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReadyCollectionError(f"{stream} was not UTF-8; no valid raw transcript can be made") from exc


def run_command(argv: Sequence[str], *, timeout: int = 90) -> CommandResult:
    """Run one fixed guest read command without a shell or inherited output."""
    if not argv or any(not isinstance(item, str) or not item for item in argv):
        raise ValueError("command argv must contain non-empty strings")
    started_at = utc_now()
    try:
        completed = subprocess.run(
            list(argv),
            check=False,
            capture_output=True,
            shell=False,
            timeout=timeout,
        )
        stdout, stderr = _decode_utf8(completed.stdout, "stdout"), _decode_utf8(completed.stderr, "stderr")
        code = completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = _decode_utf8(exc.stdout or b"", "timeout stdout")
        stderr = _decode_utf8(exc.stderr or b"", "timeout stderr") + f"\ncollector timeout after {timeout} seconds"
        code = 124
    except OSError as exc:
        stdout, stderr, code = "", f"{type(exc).__name__}: {exc}", 127
    return CommandResult(tuple(argv), stdout, stderr, code, started_at, utc_now())


def powershell(script: str, *, timeout: int = 90) -> CommandResult:
    """Execute a fixed read-only PowerShell projection with UTF-8 output."""
    prologue = (
        "$ErrorActionPreference='Stop';"
        "$OutputEncoding=[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false);"
    )
    return run_command(
        ("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prologue + script),
        timeout=timeout,
    )


def _json_stdout(value: Mapping[str, Any] | list[Any]) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _vql_quote(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReadyCollectionError("a read-only VQL identity must be a non-empty string")
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _vql_result(query: str) -> CommandResult:
    """Record a root-org VQL request without exposing the configured API secret."""
    started_at = utc_now()
    argv = ("velociraptor_api.run_vql_query", query)
    try:
        from velociraptor_api import init_stub, run_vql_query

        init_stub()
        result = run_vql_query(query, root_org=True)
        stdout, stderr, code = _json_stdout(result), "", 0
    except BaseException as exc:  # retain the actual backend error as failure evidence
        stdout, stderr, code = "", f"{type(exc).__name__}: {exc}", 1
    return CommandResult(argv, stdout, stderr, code, started_at, utc_now())


def _require_identity(run: Mapping[str, Any], restoreidentity: Mapping[str, Any]) -> tuple[str, str]:
    if run.get("workflow_id") != WORKFLOW_ID or not isinstance(run.get("run_id"), str) or not run["run_id"]:
        raise ValueError("run must have the fixed workflow_id and a reserved run_id")
    if not isinstance(restoreidentity.get("restore_attempt_id"), str) or not restoreidentity["restore_attempt_id"]:
        raise ValueError("restoreidentity must have a non-empty restore_attempt_id")
    return run["run_id"], restoreidentity["restore_attempt_id"]


def _envelope(observation: str, run_id: str, restore_attempt_id: str, result: CommandResult) -> dict[str, Any]:
    stdout_bytes, stderr_bytes = result.stdout.encode("utf-8"), result.stderr.encode("utf-8")
    return {
        "schema_version": 1,
        "kind": "p05-ready-command-v1",
        "observation": observation,
        "workflow_id": WORKFLOW_ID,
        "run_id": run_id,
        "restore_attempt_id": restore_attempt_id,
        "host": {"scope": "guest", "computer_name": GUEST_NAME},
        "request": {"argv": list(result.argv), "command_line": command_line(result.argv)},
        "started_at": result.started_at,
        "ended_at": result.ended_at,
        "exit_status": {"code": result.exit_code},
        "response": {
            "stdout": result.stdout,
            "stdout_size": len(stdout_bytes),
            "stdout_sha256": sha256(stdout_bytes),
            "stderr": result.stderr,
            "stderr_size": len(stderr_bytes),
            "stderr_sha256": sha256(stderr_bytes),
        },
    }


def _write_exclusive(path: Path, document: Mapping[str, Any]) -> None:
    raw = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _record(
    evidence_dir: Path,
    observation: str,
    run_id: str,
    restore_attempt_id: str,
    result: CommandResult,
) -> Path:
    path = evidence_dir / f"{observation}.json"
    _write_exclusive(path, _envelope(observation, run_id, restore_attempt_id, result))
    if result.exit_code != 0:
        raise ReadyCollectionError(f"{observation} command failed with exit code {result.exit_code}; raw={path}")
    return path


def _parse_object(result: CommandResult, observation: str) -> dict[str, Any]:
    if result.exit_code != 0:
        raise ReadyCollectionError(f"{observation} command failed before JSON parsing")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ReadyCollectionError(f"{observation} did not emit a complete JSON object") from exc
    if not isinstance(value, dict):
        raise ReadyCollectionError(f"{observation} did not emit a JSON object")
    return value


def _read_fixture_instance() -> CommandResult:
    # sys.executable is the actual guest interpreter.  buffer.write preserves
    # the fixture original byte-for-byte, as required by p05_ready_evidence.
    script = "from pathlib import Path;import sys;sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes())"
    return run_command((sys.executable, "-c", script, FIXTURE_INSTANCE))


def _parent_bindings(bundle: SourceBundle) -> CommandResult:
    root = bundle.parent_records.replace("'", "''")
    source = bundle.parent_source.replace("'", "''")
    script = rf"""
$root='{root}';$source='{source}'
$records=@(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop |
  ForEach-Object {{
    $started=Join-Path $_.FullName 'started.json';$exited=Join-Path $_.FullName 'exited.json'
    if((Test-Path -LiteralPath $started -PathType Leaf) -and -not (Test-Path -LiteralPath $exited -PathType Leaf)) {{
      Get-Content -LiteralPath $started -Raw -Encoding UTF8 | ConvertFrom-Json
    }}
  }})
[ordered]@{{source_sha256=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant();launch_records=@($records)}} | ConvertTo-Json -Depth 16 -Compress
"""
    return powershell(script)


def _guest_processes(instance: Mapping[str, Any], bindings: Mapping[str, Any]) -> CommandResult:
    try:
        fixture_pid = instance["process"]["pid"]
        records = bindings["launch_records"]
        approved = {int(fixture_pid)}
        for record in records:
            approved.add(int(record["parent_identity"]["ProcessId"]))
            approved.add(int(record["child_identity"]["ProcessId"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ReadyCollectionError("cannot safely determine approved guest command-line PIDs") from exc
    ids = ",".join(str(pid) for pid in sorted(approved))
    script = rf"""
$approved=@({ids})
$rows=@(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,
  @{{N='CreationDate';E={{if($null -ne $_.CreationDate){{$_.CreationDate.ToUniversalTime().ToString('o')}}else{{$null}}}}}},
  @{{N='CommandLine';E={{if($approved -contains $_.ProcessId){{$_.CommandLine}}else{{$null}}}}}})
[ordered]@{{captured_at_utc=(Get-Date).ToUniversalTime().ToString('o');processes=@($rows)}} | ConvertTo-Json -Depth 8 -Compress
"""
    return powershell(script)


def _fixture_static(bundle: SourceBundle, instance: Mapping[str, Any]) -> CommandResult:
    # The instance contributes only its approved fixture paths/attempt; all
    # file hashes, registry values, event and task values are read back here.
    attempt = str(instance.get("attempt_id", "")).replace("'", "''")
    spec = bundle.fixture_spec.replace("'", "''")
    script = rf"""
$root='{FIXTURE_ROOT}';$instance=Join-Path $root 'fixture-instance-v1.json';$marker=Join-Path $root '.p05-owner.json';$specPath='{spec}';$attempt='{attempt}'
function Assert-ReparseFree([string]$path){{
  $full=[IO.Path]::GetFullPath($path)
  $segments=@($full -split '[\\/]' | Where-Object {{$_ -ne ''}})
  if($segments.Count -lt 2){{throw "fixture path is not absolute: $path"}}
  $prefix=$segments[0]
  for($i=1;$i -lt $segments.Count;$i++){{
    $prefix="$prefix\$($segments[$i])"
    $item=Get-Item -LiteralPath $prefix -Force -ErrorAction Stop
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){{throw "reparse ancestor before fixture read: $prefix"}}
  }}
}}
Assert-ReparseFree $root;Assert-ReparseFree $instance;Assert-ReparseFree $marker;Assert-ReparseFree $specPath
function Row($path) {{ $i=Get-Item -LiteralPath $path -Force -ErrorAction Stop;[ordered]@{{path=$i.FullName;is_reparse_point=(($i.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0);file_type=$(if($i.PSIsContainer){{'directory'}}else{{'file'}})}} }}
$specValue=Get-Content -LiteralPath $specPath -Raw -Encoding UTF8 | ConvertFrom-Json
$files=@($specValue.files | ForEach-Object {{ $p=Join-Path $root ([string]$_.path).Replace('/','\\');Assert-ReparseFree $p;$i=Get-Item -LiteralPath $p -Force -ErrorAction Stop;[ordered]@{{path=$i.FullName;relative_path=[string]$_.path;size=[int64]$i.Length;sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant();is_reparse_point=(($i.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0);file_type='file'}} }})
$reg="HKLM:\SOFTWARE\VelociraptorMCP\P05\{WORKFLOW_ID}";$rv=Get-ItemProperty -LiteralPath $reg -ErrorAction Stop
$eventMessage='{WORKFLOW_ID}|'+$attempt+'|fixture-v1';$events=@(Get-WinEvent -FilterHashtable @{{LogName='Application';ProviderName='VelociraptorMCP-P05';Id=42005}} -ErrorAction Stop | Where-Object {{$_.Message -eq $eventMessage}} | ForEach-Object {{[ordered]@{{log='Application';source=$_.ProviderName;event_id=[int]$_.Id;message=$_.Message;record_id=[int64]$_.RecordId}}}})
$task=Get-ScheduledTask -TaskPath '\VelociraptorMCP\' -TaskName 'P05-Fixture' -ErrorAction Stop;if(@($task.Actions).Count -ne 1){{throw 'Fixture task must have exactly one observed action'}};$action=@($task.Actions)[0]
[ordered]@{{fixture_spec_sha256=(Get-FileHash -LiteralPath $specPath -Algorithm SHA256).Hash.ToLowerInvariant();fixture_instance=@{{path=(Row $instance).path;is_reparse_point=(Row $instance).is_reparse_point;file_type=(Row $instance).file_type;sha256=(Get-FileHash -LiteralPath $instance -Algorithm SHA256).Hash.ToLowerInvariant()}};fixture_root=(Row $root);ownership_marker=@{{path=(Row $marker).path;is_reparse_point=(Row $marker).is_reparse_point;file_type=(Row $marker).file_type;content=(Get-Content -LiteralPath $marker -Raw -Encoding UTF8|ConvertFrom-Json)}};files=@($files);registry=@{{path=$reg;values=@{{Owner=$rv.Owner;Attempt=$rv.Attempt;FixtureVersion=[int]$rv.FixtureVersion}}}};event_rows=@($events);task=@{{path='\VelociraptorMCP\';name='P05-Fixture';enabled=($task.State -ne 'Disabled');triggers=@($task.Triggers|Where-Object {{$null -ne $_}});execute=$($action.Execute -replace [regex]::Escape($env:SystemRoot+'\System32\cmd.exe'),'%SystemRoot%\System32\cmd.exe');arguments=$action.Arguments}}}} | ConvertTo-Json -Depth 16 -Compress
"""
    return powershell(script)


def _guest_identity() -> CommandResult:
    # Both observations are real reads: current guest time and root API client
    # rows.  The request vector records the exact fixed VQL alongside the CIM
    # command so a reviewer can reproduce the compound raw projection.
    command = powershell("[ordered]@{computer_name=$env:COMPUTERNAME;guest_utc=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress")
    query = (
        "SELECT client_id, os_info.system AS os, os_info.hostname AS hostname "
        "FROM clients() WHERE os_info.system = 'windows'"
    )
    vql = _vql_result(query)
    if command.exit_code or vql.exit_code:
        return CommandResult(command.argv + vql.argv, command.stdout or vql.stdout, command.stderr + vql.stderr, command.exit_code or vql.exit_code, command.started_at, vql.ended_at)
    value = _parse_object(command, "guest_identity")
    try:
        rows = json.loads(vql.stdout)
    except json.JSONDecodeError as exc:
        return CommandResult(command.argv + vql.argv, "", f"VQL JSON parse error: {exc}", 1, command.started_at, vql.ended_at)
    return CommandResult(command.argv + vql.argv, _json_stdout({**value, "api_client_rows": rows}), command.stderr + vql.stderr, 0, command.started_at, vql.ended_at)


def _dependencies(bundle: SourceBundle) -> CommandResult:
    inventory_query = (
        "SELECT name, artifact, filename, version, hash, admin_override, materialize, "
        "serve_locally, serve_url, filestore_path, invalid_hash FROM inventory() "
        "WHERE name =~ '^(Autorun_386|Autorun_amd64)$' ORDER BY name"
    )
    started = utc_now()
    inventory = _vql_result(inventory_query)
    manifest_path = bundle.dependency_manifest.replace("'", "''")
    locked = powershell(rf"""
$manifest=Get-Content -LiteralPath '{manifest_path}' -Raw -Encoding UTF8 | ConvertFrom-Json
$root='C:\VelociraptorMCP\dependencies\p05\locked'
[ordered]@{{dependency_manifest_sha256=(Get-FileHash -LiteralPath '{manifest_path}' -Algorithm SHA256).Hash.ToLowerInvariant();locked_files=@($manifest.dependencies | ForEach-Object {{$p=Join-Path $root $_.filename;$i=Get-Item -LiteralPath $p -ErrorAction Stop;[ordered]@{{name=$_.name;path=$i.FullName;size=[int64]$i.Length;sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}}}})}} | ConvertTo-Json -Depth 8 -Compress
""")
    artifacts: list[dict[str, Any]] = []
    local_public_bytes: list[dict[str, Any]] = []
    request_argv: list[str] = ["velociraptor_api.run_vql_query", inventory_query]
    request_argv.extend(locked.argv)
    errors = [item for item in (inventory.stderr if inventory.exit_code else "", locked.stderr if locked.exit_code else "") if item]
    # inventory_get(probe=TRUE) sends an actual request to the tool's upstream
    # URL: for the etl2pcapng predecessor that is a public GitHub address,
    # violating the zero-public-request invariant on every collection. The
    # probe was already adjudicated evidentially vacuous (PLAN-CHANGE-013 A);
    # it is therefore not issued at all and probe_rows are not recorded.
    if inventory.exit_code == 0:
        for name in ("Windows.Triage.Targets", "Generic.Utils.KillProcess"):
            result = _vql_result(
                "SELECT name, type, raw, parameters, sources, required_permissions "
                f"FROM artifact_definitions() WHERE name = '{name}'"
            )
            request_argv.extend(result.argv)
            if result.exit_code:
                errors.append(result.stderr)
            else:
                artifacts.extend(json.loads(result.stdout))
    if errors:
        return CommandResult(tuple(request_argv), inventory.stdout, "\n".join(errors), 1, started, utc_now())

    try:
        manifest = json.loads(Path(bundle.dependency_manifest).read_text(encoding="utf-8"))
        rows = json.loads(inventory.stdout)
        from tests.p05_dependency_acceptance import verify_local_public_bytes

        for name in DEPENDENCY_NAMES:
            selected = [row for row in rows if row.get("name") == name and row.get("admin_override") is True]
            if len(selected) != 1:
                raise ReadyCollectionError(f"dependency {name} does not have one actual selected inventory row")
            observed = verify_local_public_bytes(name, selected[0], manifest)
            local_public_bytes.append({"name": name, **observed})
            request_argv.extend(("urllib.request.urlopen", observed["url"]))
    except BaseException as exc:
        partial = {
            "dependency_manifest_sha256": json.loads(locked.stdout)["dependency_manifest_sha256"],
            "inventory_rows": json.loads(inventory.stdout),
            "locked_files": json.loads(locked.stdout)["locked_files"],
            "artifact_rows": artifacts,
        }
        return CommandResult(tuple(request_argv), _json_stdout(partial), f"{type(exc).__name__}: {exc}", 1, started, utc_now())
    payload = {
        "dependency_manifest_sha256": json.loads(locked.stdout)["dependency_manifest_sha256"],
        "inventory_rows": rows,
        "local_public_bytes": local_public_bytes,
        "locked_files": json.loads(locked.stdout)["locked_files"],
        "artifact_rows": artifacts,
    }
    return CommandResult(tuple(request_argv), _json_stdout(payload), "", 0, started, utc_now())


def _service() -> CommandResult:
    script = rf"""
$svc=Get-CimInstance Win32_Service -Filter "Name='{SERVICE_NAME}'" -ErrorAction Stop
$proc=Get-CimInstance Win32_Process -Filter "ProcessId=$($svc.ProcessId)" -ErrorAction Stop
$listeners=@(Get-NetTCPConnection -State Listen -LocalPort {SERVICE_PORT} -ErrorAction Stop | Select-Object LocalAddress,LocalPort,@{{N='State';E={{[string]$_.State}}}},OwningProcess)
# The venv python.exe is a shim: the live process's ExecutablePath is the base
# interpreter declared in pyvenv.cfg, not the shim itself.
$venvHome=$null
$cfgPath='C:\mcp-velociraptor\.venv\pyvenv.cfg'
if (Test-Path -LiteralPath $cfgPath) {{ $line=(Get-Content -LiteralPath $cfgPath | Where-Object {{$_ -match '^\s*home\s*='}} | Select-Object -First 1); if ($line) {{ $venvHome=($line -replace '^\s*home\s*=\s*','').Trim() + '\python.exe' }} }}
[ordered]@{{service_python_base=$venvHome;service_rows=@([ordered]@{{name=$svc.Name;state=[string]$svc.State;start_name=$svc.StartName;start_mode=$svc.StartMode;process_id=[int]$svc.ProcessId;path_name=$svc.PathName}});service_process_rows=@([ordered]@{{ProcessId=[int]$proc.ProcessId;ParentProcessId=[int]$proc.ParentProcessId;Name=$proc.Name;ExecutablePath=$proc.ExecutablePath;CreationDate=$(if($null -ne $proc.CreationDate){{$proc.CreationDate.ToUniversalTime().ToString('o')}}else{{$null}});CommandLine=$proc.CommandLine;executable_sha256=(Get-FileHash -LiteralPath $proc.ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant()}});listeners=@($listeners)}} | ConvertTo-Json -Depth 10 -Compress
"""
    return powershell(script)


def _acl(bundle: SourceBundle) -> CommandResult:
    repo = bundle.guest_repo_root.replace("'", "''")
    script = rf"""
$sid=@((sc.exe showsid '{SERVICE_NAME}') | Select-String -AllMatches 'S-1-5-80-(?:[0-9]+-){{4}}[0-9]+' | ForEach-Object {{$_.Matches.Value}} | Select-Object -Unique)
if(@($sid).Count -ne 1){{throw 'service SID is absent or ambiguous'}}
$logs=Join-Path '{repo}' 'Logs'
function ItemRow($path){{
  $i=Get-Item -LiteralPath $path -Force -ErrorAction Stop
  [ordered]@{{path=$i.FullName;is_reparse_point=(($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0);file_type=$(if($i.PSIsContainer){{'directory'}}else{{'file'}})}}
}}
function AclProjection($path){{
  $a=Get-Acl -LiteralPath $path -ErrorAction Stop
  $binary=$a.GetSecurityDescriptorBinaryForm()
  $raw=New-Object Security.AccessControl.RawSecurityDescriptor($binary,0)
  if($null -eq $raw.DiscretionaryAcl){{throw 'DACL is absent'}}
  $rules=@($raw.DiscretionaryAcl|ForEach-Object{{
    if(-not ($_ -is [Security.AccessControl.QualifiedAce])){{throw 'ACL ACE is not a qualified filesystem ACE'}}
    $ace=$_;$aceBytes=New-Object byte[] $ace.BinaryLength;$ace.GetBinaryForm($aceBytes,0)
    $type=[int]$ace.AceType
    $access=$(if($type -eq 0){{'Allow'}}elseif($type -eq 1){{'Deny'}}else{{[string]$ace.AceType}})
    $name=$ace.SecurityIdentifier.Translate([Security.Principal.NTAccount]).Value
    $flags=[int]$ace.AceFlags
    [ordered]@{{identity=$name;sid=$ace.SecurityIdentifier.Value;ace_type=$type;ace_flags=$flags;access_control_type=$access;access_mask=[uint32]([int64]$ace.AccessMask -band [int64]4294967295);is_inherited=(($flags -band 16) -ne 0);inheritance_flags=(($flags -band 1) -bor ($(if(($flags -band 2) -ne 0){{2}}else{{0}})));propagation_flags=(($(if(($flags -band 4) -ne 0){{1}}else{{0}})) -bor ($(if(($flags -band 8) -ne 0){{2}}else{{0}})));raw_ace_base64=[Convert]::ToBase64String($aceBytes)}}
  }})
  [ordered]@{{security_descriptor_base64=[Convert]::ToBase64String($binary);sddl=$a.Sddl;access_rules=@($rules)}}
}}
function AclRow($role,$path){{ $i=ItemRow $path;$acl=AclProjection $path;[ordered]@{{role=$role;path=$i.path;is_reparse_point=$i.is_reparse_point;file_type=$i.file_type;security_descriptor_base64=$acl.security_descriptor_base64;sddl=$acl.sddl;access_rules=@($acl.access_rules)}} }}
function TreeNode($path,$scope){{
  $i=ItemRow $path;$children=@()
  if($i.is_reparse_point){{throw 'Code tree contains a reparse point; enumeration stopped before following it'}}
  if($i.file_type -eq 'directory'){{$children=@(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop|Sort-Object -Property FullName)}}
  $acl=AclProjection $path
  [ordered]@{{row=[ordered]@{{path=$i.path;is_reparse_point=$i.is_reparse_point;file_type=$i.file_type;scope=$scope;children=@($children|ForEach-Object{{$_.FullName}});acl=$acl}};child_objects=@($children)}}
}}
$pending=[Collections.Generic.Queue[object]]::new();$pending.Enqueue([ordered]@{{path='{repo}';scope='code'}})
$nodes=[Collections.Generic.List[object]]::new()
while($pending.Count -gt 0){{
  $current=$pending.Dequeue();$made=TreeNode $current.path $current.scope;$node=$made.row
  $children=@($made.child_objects);$nodes.Add($node)
  if($node.is_reparse_point){{continue}}
  foreach($child in $children){{
    $scope=$(if($current.scope -eq 'runtime_logs' -or $child.FullName -ieq $logs){{'runtime_logs'}}else{{'code'}})
    $pending.Enqueue([ordered]@{{path=$child.FullName;scope=$scope}})
  }}
}}
[ordered]@{{service_account=@{{name='{SERVICE_ACCOUNT}';sid=$sid[0]}};paths=@((AclRow 'code_root' '{repo}'),(AclRow 'service_python' '{repo}\.venv\Scripts\python.exe'),(AclRow 'service_host' '{repo}\tests\p05_service_host.py'),(AclRow 'protected_env' 'C:\VelociraptorMCP\secrets\mcp-service.env'),(AclRow 'api_client_config' 'C:\VelociraptorMCP\secrets\api_client_service.yaml'),(AclRow 'download_root' 'C:\VelociraptorMCP\downloads'),(AclRow 'runtime_logs' $logs));code_tree=@{{root='{repo}';runtime_logs_root=$logs;nodes=@($nodes)}}}} | ConvertTo-Json -Depth 20 -Compress
"""
    return powershell(script, timeout=300)


def _firewall() -> CommandResult:
    script = rf"""
$rules=@(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {{$_.Name -eq 'mcp-velociraptor-28790' -or $_.DisplayName -eq 'mcp-velociraptor-28790'}} | ForEach-Object {{$r=$_;$p=@($r|Get-NetFirewallPortFilter);$a=@($r|Get-NetFirewallAddressFilter);if($p.Count -ne 1 -or $a.Count -ne 1){{throw 'firewall filter join is ambiguous'}};[ordered]@{{name=$r.Name;display_name=$r.DisplayName;direction=[string]$r.Direction;action=[string]$r.Action;enabled=($r.Enabled -eq 'True');protocol=[string]$p[0].Protocol;local_port=$(if(@($p[0].LocalPort).Count -eq 1){{$p[0].LocalPort}}else{{throw 'local port ambiguous'}});local_address=$(if(@($a[0].LocalAddress).Count -eq 1){{$a[0].LocalAddress}}else{{throw 'local address ambiguous'}});remote_address=$(if(@($a[0].RemoteAddress).Count -eq 1){{$a[0].RemoteAddress}}else{{throw 'remote address ambiguous'}})}} }})
foreach($rule in $rules){{
  if([string]$rule.local_port -notmatch '^[0-9]+$'){{throw 'Firewall local port is not one numeric port'}}
  $rule.local_port=[int]$rule.local_port
}}
[ordered]@{{rules=@($rules)}} | ConvertTo-Json -Depth 8 -Compress
"""
    return powershell(script)


def _resource_creators(run: Mapping[str, Any]) -> tuple[str, ...]:
    values = run.get("resource_creators")
    if not isinstance(values, list) or not values or any(not isinstance(value, str) or not value for value in values):
        raise CollectionGap("run.resource_creators must name the actual P05 resource creators")
    if len(set(values)) != len(values):
        raise CollectionGap("run.resource_creators contains a duplicate creator")
    return tuple(values)


def _resource_time(value: Any) -> str:
    if type(value) is not int or value < 0:
        raise ReadyCollectionError("backend resource create_time was not a non-negative microsecond epoch")
    return datetime.fromtimestamp(value / 1_000_000, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _resources(run: Mapping[str, Any]) -> CommandResult:
    """Use existing flows()/hunts()/hunt_flows() shapes without guessed rows."""
    try:
        creators = _resource_creators(run)
    except ReadyCollectionError as exc:
        return CommandResult(("resource-creator-input",), "", str(exc), 78, utc_now(), utc_now())
    trace = powershell("& netsh.exe trace show status; exit $LASTEXITCODE")
    # netsh exits 1 for a benign "no trace session currently in progress";
    # that is the required inactive state, not a failed observation.
    trace_exit = 0 if (trace.exit_code in (0, 1) and "no trace session" in trace.stdout.lower()) else trace.exit_code
    listener = powershell("[ordered]@{rows=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {$_.LocalPort -eq 28786} | Select-Object LocalAddress,LocalPort,State,OwningProcess)} | ConvertTo-Json -Depth 5 -Compress")
    flow_query = (
        "SELECT session_id AS resource_id, request.client_id AS client_id, state, "
        "request.creator AS creator, create_time "
        f"FROM flows(client_id='{CLIENT_ID}')"
    )
    hunt_query = "SELECT hunt_id AS resource_id, state, start_request.creator AS creator, create_time FROM hunts()"
    flows, hunts = _vql_result(flow_query), _vql_result(hunt_query)
    requests = list(trace.argv + listener.argv + flows.argv + hunts.argv)
    errors = [result.stderr for result, code in ((trace, trace_exit), (listener, listener.exit_code), (flows, flows.exit_code), (hunts, hunts.exit_code)) if code]
    try:
        temporary_listeners = json.loads(listener.stdout)["rows"]
        flow_rows = [row for row in json.loads(flows.stdout) if row.get("creator") in creators]
        hunt_rows = [row for row in json.loads(hunts.stdout) if row.get("creator") in creators]
        normalized_flows = [
            {"resource_id": row.get("resource_id"), "client_id": row.get("client_id"), "state": row.get("state"), "creator": row.get("creator"), "created_at_utc": _resource_time(row.get("create_time"))}
            for row in flow_rows
        ]
        normalized_hunts: list[dict[str, Any]] = []
        for row in hunt_rows:
            hunt_id = row.get("resource_id")
            if not isinstance(hunt_id, str) or not hunt_id:
                raise ReadyCollectionError("owned hunt has no actual hunt_id")
            membership = _vql_result(
                "SELECT HuntId, ClientId FROM hunt_flows(hunt_id=" + _vql_quote(hunt_id) + ")"
            )
            requests.extend(membership.argv)
            if membership.exit_code:
                errors.append(membership.stderr)
                continue
            members = json.loads(membership.stdout)
            state = row.get("state")
            # PAUSED/STOPPED hunts are historical leftovers from earlier
            # epochs; they are listed separately and may carry zero or many
            # client bindings. Only a live owned hunt must bind exactly once.
            if state not in {"PAUSED", "STOPPED"} and len(members) != 1:
                raise ReadyCollectionError(f"owned hunt {hunt_id} does not have one actual client binding")
            normalized_hunts.append({"resource_id": hunt_id, "client_id": members[0].get("ClientId") if members else None, "state": state, "creator": row.get("creator"), "created_at_utc": _resource_time(row.get("create_time"))})
        payload = {
            "owned_flows": [row for row in normalized_flows if row["state"] not in {"PAUSED", "STOPPED"}],
            "owned_hunts": [row for row in normalized_hunts if row["state"] not in {"PAUSED", "STOPPED"}],
            "historical_flows": [row for row in normalized_flows if row["state"] in {"PAUSED", "STOPPED"}],
            "historical_hunts": [row for row in normalized_hunts if row["state"] in {"PAUSED", "STOPPED"}],
            "trace": {"argv": ["netsh.exe", "trace", "show", "status"], "exit_status": trace_exit, "stdout": trace.stdout, "stderr": trace.stderr},
            "temporary_listeners": temporary_listeners,
        }
    except BaseException as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
        payload = {"trace": {"argv": ["netsh.exe", "trace", "show", "status"], "exit_status": trace_exit, "stdout": trace.stdout, "stderr": trace.stderr}}
    return CommandResult(tuple(requests), _json_stdout(payload), "\n".join(errors), 1 if errors else 0, trace.started_at, utc_now())


def collect_guest_ready(
    *,
    run: Mapping[str, Any],
    restoreidentity: Mapping[str, Any],
    sourcebundle: SourceBundle,
    evidence_directory: Path,
) -> dict[str, Path]:
    """Collect guest originals into one new, exclusive evidence directory.

    It is intentionally not executable as a production command-line program.
    The returned paths cover only guest observations; the outer host workflow
    must add host_clock and host_processes before invoking the ready validator.
    """
    if os.name != "nt" or os.environ.get("COMPUTERNAME", "").upper() != GUEST_NAME:
        raise ReadyCollectionError("guest ready collection may run only in the approved Windows VM")
    run_id, restore_attempt_id = _require_identity(run, restoreidentity)
    evidence_directory.mkdir(parents=True, exist_ok=False)
    results: dict[str, Path] = {}
    failures: list[str] = []

    def capture(observation: str, result: CommandResult) -> bool:
        try:
            results[observation] = _record(evidence_directory, observation, run_id, restore_attempt_id, result)
        except ReadyCollectionError as exc:
            failures.append(str(exc))
            return False
        return True

    try:
        identity = _guest_identity()
        capture("guest_identity", identity)

        fixture_raw = _read_fixture_instance()
        fixture_ok = capture("fixture_instance", fixture_raw)
        fixture = _parse_object(fixture_raw, "fixture_instance") if fixture_ok else None

        bindings = _parent_bindings(sourcebundle)
        binding_ok = capture("parent_bindings", bindings)
        binding_object = _parse_object(bindings, "parent_bindings") if binding_ok else None

        if fixture is not None:
            capture("fixture_static", _fixture_static(sourcebundle, fixture))
        else:
            failures.append("fixture_static was not attempted because fixture_instance did not produce raw JSON")
        if fixture is not None and binding_object is not None:
            capture("guest_processes", _guest_processes(fixture, binding_object))
        else:
            failures.append("guest_processes was not attempted because approved process identities are unavailable")

        # These are read-only. Known missing semantics projections are written
        # with non-zero raw transcripts, but independent observations continue.
        dependencies = _dependencies(sourcebundle)
        capture("dependencies", dependencies)
        service = _service()
        capture("service", service)
        acl = _acl(sourcebundle)
        capture("acl", acl)
        firewall = _firewall()
        capture("firewall", firewall)
        resources = _resources(run)
        capture("resources", resources)
        if failures:
            raise ReadyCollectionError("guest ready raw collection is incomplete: " + "; ".join(failures))
    except ReadyCollectionError:
        raise
    except BaseException as exc:
        raise ReadyCollectionError(f"guest ready collection aborted without a successful ready claim: {exc}") from exc
    return results
