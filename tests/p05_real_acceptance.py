from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from tests.p05_sdk_capture import SDKCapture


WORKFLOW_ID = "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2"
FIXTURE_INSTANCE = Path(r"C:\VelociraptorMCP\fixtures-p05\fixture-instance-v1.json")
OUT_ROOT = REPO_ROOT / "Logs" / "P05" / "wf-01a05d1d-p05"
TERMINAL = {"FINISHED", "ERROR"}
POWERSHELL_PREFIX = ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]
PS_PROCESS_IDENTITY = (
    "$p=Get-CimInstance Win32_Process -Filter \"ProcessId=%d\" -ErrorAction SilentlyContinue; "
    "if($null -eq $p){'null'}else{$p | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,"
    "@{N='CreationDate';E={$_.CreationDate.ToUniversalTime().ToString('o')}} | ConvertTo-Json -Compress}"
)
PS_PROCESS_SNAPSHOT = r"""
$ErrorActionPreference='Stop'
@(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,@{N='CreationDate';E={if ($null -ne $_.CreationDate) {$_.CreationDate.ToUniversalTime().ToString('o')} else {$null}}},@{N='CommandLine';E={if ($_.ProcessId -eq %d) {$_.CommandLine} else {$null}}}) | ConvertTo-Json -Depth 5 -Compress
"""


class RawObservationCapture:
    """Append-only command envelopes; the payload is never replaced by a summary."""

    def __init__(self, run_dir: Path):
        self.root = run_dir / 'raw-observations'
        self.root.mkdir(mode=0o700, exist_ok=False)
        self._sequence = 0
        self.references: dict[str, dict] = {}

    def record(self, label: str, round_id: str, argv: list[str], completed: subprocess.CompletedProcess) -> None:
        if not re.fullmatch(r'[a-z0-9-]{3,80}', label) or label in self.references:
            raise ValueError('raw observation label is invalid or would overwrite an original')
        if not isinstance(round_id, str) or not round_id:
            raise ValueError('raw observation round is invalid')
        self._sequence += 1
        path = self.root / f'{self._sequence:03d}-{label}.json'
        document = {
            'schema_version': 1,
            'kind': 'p05-command-observation-v1',
            'label': label,
            'round_id': round_id,
            'command': {'argv': argv},
            'started_at': completed._p05_started_at,
            'ended_at': completed._p05_ended_at,
            'exit_code': completed.returncode,
            'stdout': completed.stdout,
            'stderr': completed.stderr,
        }
        with path.open('x', encoding='utf-8', newline='\n') as stream:
            stream.write(json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False))
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        self.references[label] = {
            'path': path.relative_to(self.root.parent).as_posix(),
            'size': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        }


def _run_observed(argv: list[str], *, timeout: int, capture: RawObservationCapture | None,
                  label: str | None, round_id: str | None) -> subprocess.CompletedProcess:
    started = utc_now()
    completed = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )
    completed._p05_started_at = started
    completed._p05_ended_at = utc_now()
    if capture is not None:
        if label is None or round_id is None:
            raise ValueError('recorded command requires a fixed label and round')
        capture.record(label, round_id, argv, completed)
    return completed


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def exception_record(exc: BaseException) -> dict:
    record = {"type": type(exc).__name__, "message": str(exc)}
    nested = getattr(exc, "exceptions", None)
    if nested:
        record["exceptions"] = [exception_record(item) for item in nested]
    return record


def powershell(command: str, *, timeout: int = 60, capture: RawObservationCapture | None = None,
               label: str | None = None, round_id: str | None = None) -> str:
    completed = _run_observed(
        [*POWERSHELL_PREFIX, command], timeout=timeout, capture=capture, label=label, round_id=round_id
    )
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(completed.returncode, completed.args, completed.stdout, completed.stderr)
    return completed.stdout.strip()






def process_identity(pid: int, *, capture: RawObservationCapture | None = None, label: str | None = None,
                     round_id: str | None = None) -> dict | None:
    raw = powershell(PS_PROCESS_IDENTITY % pid, capture=capture, label=label, round_id=round_id)
    return None if raw == "null" or not raw else json.loads(raw)


def process_snapshot(target_pid: int | None = None, *, capture: RawObservationCapture | None = None,
                     label: str | None = None, round_id: str | None = None) -> list[dict]:
    if target_pid is not None and (type(target_pid) is not int or target_pid<=4):
        raise ValueError('invalid fixture PID for observation')
    raw = powershell(
        PS_PROCESS_SNAPSHOT % (target_pid if target_pid is not None else -1),
        capture=capture,
        label=label,
        round_id=round_id,
    )
    value = json.loads(raw)
    return value if isinstance(value, list) else [value]


def select_protected_processes(rows: list[dict], preparer_pid: int | None = None) -> list[dict]:
    by_pid = {row['ProcessId']: row for row in rows}
    if len(by_pid)!=len(rows):
        raise ValueError('duplicate protected process observation')
    velo = {row['ProcessId'] for row in rows if row['Name'].lower().startswith('velociraptor')}
    roots = {0,4,os.getpid(),os.getppid()} | velo
    if preparer_pid is not None:
        roots.add(preparer_pid)
    if len(velo)<2 or not roots<=by_pid.keys():
        raise ValueError('protected process roots are missing')
    parents = {by_pid[pid]['ParentProcessId'] for pid in roots}
    if not parents<=by_pid.keys():
        raise ValueError('protected process parent identity is missing')
    selected = [by_pid[pid] for pid in sorted(roots|parents)]
    for row in selected:
        if type(row['ProcessId']) is not int or row['ProcessId']<0:
            raise ValueError('invalid protected process PID')
        # Win32_Process reports no creation instant for PID 0 (Idle) and some
        # builds' PID 4 (System); both stay protected without a timestamp.
        if row['ProcessId'] not in (0,4):
            process_instant(row['CreationDate'])
    for pid in roots-{0,4}:
        row=by_pid[pid]
        if process_instant(by_pid[row['ParentProcessId']]['CreationDate'])>process_instant(row['CreationDate']):
            raise ValueError('protected process parent PID was reused')
    return selected


def protected_processes(preparer_pid: int | None = None, *, capture: RawObservationCapture | None = None,
                        label: str | None = None, round_id: str | None = None) -> list[dict]:
    return select_protected_processes(
        process_snapshot(capture=capture, label=label, round_id=round_id), preparer_pid
    )


def process_instant(value: str) -> datetime:
    instant = datetime.fromisoformat(value.replace('Z','+00:00'))
    if instant.tzinfo is None:
        raise ValueError('process creation time must have a timezone')
    return instant.astimezone(UTC)


def verify_fixture_process(target: dict, observed: dict | None, *, workflow_id: str,
                           attempt_id: str, protected: list[dict]) -> None:
    if observed is None:
        raise ValueError('fixture process is absent')
    if (type(target['pid']) is not int or target['pid']<=4
            or observed['ProcessId']!=target['pid']
            or target['pid'] in {row['ProcessId'] for row in protected}):
        raise ValueError('fixture PID differs or belongs to protected processes')
    # The frozen P05 producer records UTC milliseconds (not CIM's finer
    # fraction). Compare at that exact declared precision, without rounding.
    if (process_instant(observed['CreationDate']).isoformat(timespec='milliseconds')
            !=process_instant(target['creation_time_utc']).isoformat(timespec='milliseconds')):
        raise ValueError('fixture process creation time differs (possible PID reuse)')
    if (target['token']!=f'{workflow_id}|{attempt_id}'
            or observed['CommandLine']!=target['command_line']
            or any(token not in observed['CommandLine'] for token in (workflow_id,attempt_id))):
        raise ValueError('fixture full command line or ownership token differs')


async def guarded_kill(session, evidence: dict, target: dict, attempt_id: str,
                       capture: RawObservationCapture | None = None,
                       sdk_capture: SDKCapture | None = None) -> tuple[dict,dict,list[dict]]:
    if capture is None:
        rows = process_snapshot(target['pid'])
    else:
        rows = process_snapshot(target['pid'], capture=capture, label='kill-pre-processes', round_id='kill-pre')
    observed = next((row for row in rows if row['ProcessId']==target['pid']),None)
    if observed is None:
        raise ValueError('fixture process is absent')
    protected = select_protected_processes(rows,observed['ParentProcessId'])
    preparer = next(row for row in protected if row['ProcessId']==observed['ParentProcessId'])
    if process_instant(preparer['CreationDate'])>process_instant(observed['CreationDate']):
        raise ValueError('fixture preparation executor PID was reused')
    verify_fixture_process(target,observed,workflow_id=WORKFLOW_ID,
                           attempt_id=attempt_id,protected=protected)
    # No further observation, wait or product call may intervene here. This
    # implements the pre-call check, not an unsupported atomic remote kill.
    killed = await call(session,evidence,'kill-process','kill_process',{'pid':target['pid']},sdk_capture)
    return killed,observed,protected


def result_row(result) -> dict:
    return {
        "is_error": bool(result.is_error),
        "structured": result.structured_content,
    }


async def call(session, evidence: dict, label: str, tool: str, arguments: dict,
               sdk_capture: SDKCapture) -> dict:
    if label in evidence["calls"]:
        raise ValueError('P05 call label would overwrite an earlier original')
    started = utc_now()
    raw = await session.call_tool(tool, arguments)
    result = result_row(raw)
    ended = utc_now()
    evidence["calls"][label] = {
        "tool": tool, "arguments": arguments, "result": result,
        "started_at": started, "ended_at": ended,
        "mcp_result": raw.model_dump(mode='json', by_alias=True, exclude_none=True),
        # Join this call to its raw SDK request by the real JSON-RPC id so
        # repeated identical flow polls stay uniquely paired downstream.
        "sdk_request_id": sdk_capture.request_id_for(
            tool=tool, arguments=arguments, started_at=started, ended_at=ended
        ),
    }
    return result


async def wait_flow(session, evidence: dict, flow_id: str, label: str, timeout: int,
                    sdk_capture: SDKCapture) -> dict:
    deadline = time.monotonic() + timeout
    samples = []
    while time.monotonic() < deadline:
        row = await call(
            session,
            evidence,
            f"{label}-poll-{len(samples):03d}",
            "get_flow_status",
            {"flow_id": flow_id},
            sdk_capture,
        )
        if row["is_error"]:
            raise AssertionError(row)
        samples.append(row["structured"]["state"])
        if samples[-1] in TERMINAL:
            evidence.setdefault("flow_states", {})[flow_id] = samples
            return row["structured"]
        await asyncio.sleep(1)
    raise AssertionError(f"flow timeout: {flow_id}; samples={samples}")


async def main_async(attempt_id: str) -> tuple[dict, Path]:
    if os.environ.get("COMPUTERNAME", "").upper() != "DESKTOP-3FI41GR":
        raise RuntimeError("P05 real acceptance only runs on DESKTOP-3FI41GR")
    fixture = json.loads(FIXTURE_INSTANCE.read_text(encoding="utf-8"))
    if fixture["workflow_id"] != WORKFLOW_ID or fixture["attempt_id"] != attempt_id:
        raise RuntimeError("fixture instance identity mismatch")
    run_dir = OUT_ROOT / attempt_id / 'real-acceptance' / str(uuid.uuid4())
    run_dir.mkdir(parents=True, exist_ok=False)
    raw_capture = RawObservationCapture(run_dir)
    evidence = {
        "schema": "p05-real-acceptance-v1",
        "workflow_id": WORKFLOW_ID,
        "attempt_id": attempt_id,
        "hostname": os.environ.get("COMPUTERNAME"),
        "started_at": utc_now(),
        "calls": {},
        "owned_flows": [],
        "raw_observations": raw_capture.references,
    }
    active_flows: set[str] = set()
    failure: BaseException | None = None
    stderr_path = run_dir / 'bridge-stderr.log'
    stderr_file = stderr_path.open('x', encoding='utf-8')
    sdk_capture = SDKCapture(run_dir / 'sdk-messages.ndjson')
    try:
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(REPO_ROOT / "mcp_velociraptor_bridge.py")],
            cwd=REPO_ROOT,
            # This is the approved VM-internal stdio adapter, not a second
            # formal network server. Never inherit the service Bearer token or
            # its protected environment-file reference into this child.
            env={
                **{key: value for key, value in os.environ.items() if key.upper() in {
                    'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATH', 'PATHEXT', 'TEMP', 'TMP',
                    'VELOCIRAPTOR_API_CONFIG', 'VELOCIRAPTOR_DOWNLOAD_ROOT', 'PYTHONUTF8',
                }},
                'VELOCIRAPTOR_MCP_TRANSPORT': 'stdio',
                'PYTHONDONTWRITEBYTECODE': '1',
            },
        )
        async with stdio_client(params, errlog=stderr_file) as (read, write):
            observed_read, observed_write = sdk_capture.wrap(read, write)
            async with ClientSession(observed_read, observed_write) as session:
                await session.initialize()
                tools = (await session.list_tools()).tools
                assert len(tools) == 130

                # PLAN-CHANGE-014: the netsh-trace PacketCapture chain was
                # removed (network capture is the FakeNet-NG domain); the
                # acceptance runs the three chains Autoruns/Triage/Kill.

                autoruns = await call(session, evidence, "autoruns", "Windows.Sysinternals.Autoruns", {}, sdk_capture)
                assert not autoruns["is_error"], autoruns
                autoruns_id = autoruns["structured"]["flow_id"]
                evidence["owned_flows"].append(autoruns_id)
                active_flows.add(autoruns_id)
                final = await wait_flow(session, evidence, autoruns_id, "autoruns", 600, sdk_capture)
                assert final["state"] == "FINISHED", final
                active_flows.discard(autoruns_id)
                autorun_rows = await call(
                    session,
                    evidence,
                    "autoruns-results",
                    "get_flow_results",
                    {"flow_id": autoruns_id, "page_size": 10},
                    sdk_capture,
                )
                assert not autorun_rows["is_error"], autorun_rows

                triage = await call(session, evidence, "triage", "collect_forensic_triage", {}, sdk_capture)
                assert not triage["is_error"], triage
                triage_id = triage["structured"]["flow_id"]
                evidence["owned_flows"].append(triage_id)
                active_flows.add(triage_id)
                final = await wait_flow(session, evidence, triage_id, "triage", 2400, sdk_capture)
                assert final["state"] == "FINISHED", final
                active_flows.discard(triage_id)
                triage_results = await call(
                    session,
                    evidence,
                    "triage-results",
                    "get_flow_results",
                    {"flow_id": triage_id, "page_size": 10},
                    sdk_capture,
                )
                assert not triage_results["is_error"], triage_results
                triage_files = await call(
                    session,
                    evidence,
                    "triage-files",
                    "list_flow_files",
                    {"flow_id": triage_id},
                    sdk_capture,
                )
                assert not triage_files["is_error"], triage_files

                target = fixture["process"]
                killed,target_before,protected_before = await guarded_kill(
                    session, evidence, target, attempt_id, raw_capture, sdk_capture
                )
                assert not killed["is_error"], killed
                kill_id = killed["structured"]["flow_id"]
                evidence["owned_flows"].append(kill_id)
                active_flows.add(kill_id)
                final = await wait_flow(session, evidence, kill_id, "kill", 180, sdk_capture)
                assert final["state"] == "FINISHED", final
                active_flows.discard(kill_id)
                kill_rows = await call(
                    session,
                    evidence,
                    "kill-results",
                    "get_flow_results",
                    {"flow_id": kill_id, "page_size": 10},
                    sdk_capture,
                )
                assert not kill_rows["is_error"], kill_rows
                assert any(
                    row.get("Pid") == int(target["pid"])
                    and row.get("Killed") == int(target["pid"])
                    for row in kill_rows["structured"]["data"]
                )
                target_after = process_identity(
                    int(target['pid']), capture=raw_capture, label='kill-post-target', round_id='kill-post'
                )
                assert target_after is None
                protected_after = protected_processes(
                    target_before['ParentProcessId'], capture=raw_capture,
                    label='kill-post-processes', round_id='kill-post'
                )
                before_identity = {(row["ProcessId"], row["CreationDate"]) for row in protected_before}
                after_identity = {(row["ProcessId"], row["CreationDate"]) for row in protected_after}
                assert before_identity <= after_identity
                evidence["kill_identity"] = {
                    "target_before": target_before,
                    "target_after": target_after,
                    "protected_before": protected_before,
                    "protected_after": protected_after,
                }

                evidence["active_flow_count_at_exit"] = len(active_flows)
                assert evidence["active_flow_count_at_exit"] == 0
    except BaseException as exc:
        failure = exc
        evidence["failure"] = exception_record(exc)
    finally:
        # Cleanup and final observations must never discard the evidence that
        # already exists.  Each step records its own failure instead of
        # raising, the document is still written, and any recorded failure
        # keeps `ok` false below.  The original exception survives in
        # evidence["failure"] and in the raised AssertionError.
        cleanup_failures = evidence.setdefault('final_observation_failures', [])
        evidence["unsettled_owned_flows"] = sorted(active_flows)
        evidence["ended_at"] = utc_now()
        for stage, close in (('bridge-stderr-close', stderr_file.close), ('sdk-capture-close', sdk_capture.close)):
            try:
                close()
            except BaseException as exc:
                cleanup_failures.append({**exception_record(exc), 'stage': stage})
        try:
            evidence['raw_originals'] = {
                name: {'path': path.name, 'size': path.stat().st_size,
                       'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                for name, path in (('sdk_messages', sdk_capture.path), ('stderr', stderr_path))
            }
        except BaseException as exc:
            cleanup_failures.append(exception_record(exc))

    evidence["ok"] = (
        failure is None
        and not evidence["unsettled_owned_flows"]
        and not cleanup_failures
        and evidence.get("active_flow_count_at_exit") == 0
    )
    output = run_dir / "p05-real-acceptance.json"
    with output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(evidence, ensure_ascii=False, indent=2))
    if failure is not None:
        raise AssertionError(f"P05 real acceptance failed; evidence={output}") from failure
    if not evidence["ok"]:
        raise AssertionError(f"P05 real acceptance cleanup failed; evidence={output}")
    return evidence, output


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].startswith("p05-"):
        print("usage: python -m tests.p05_real_acceptance <p05-attempt-id>", file=sys.stderr)
        return 2
    evidence, output = asyncio.run(main_async(sys.argv[1]))
    print(json.dumps({"ok": evidence["ok"], "output": str(output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
