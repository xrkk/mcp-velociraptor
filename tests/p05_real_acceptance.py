from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


WORKFLOW_ID = "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2"
FIXTURE_INSTANCE = Path(r"C:\VelociraptorMCP\fixtures-p05\fixture-instance-v1.json")
OUT_ROOT = REPO_ROOT / "Logs" / "P05" / "wf-01a05d1d-p05"
TERMINAL = {"FINISHED", "ERROR"}
ORIGINAL_DOMAINS = (
    "github.com",
    "api.github.com",
    "live.sysinternals.com",
    "triage.velocidex.com",
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def exception_record(exc: BaseException) -> dict:
    record = {"type": type(exc).__name__, "message": str(exc)}
    nested = getattr(exc, "exceptions", None)
    if nested:
        record["exceptions"] = [exception_record(item) for item in nested]
    return record


def powershell(command: str, *, timeout: int = 60) -> str:
    completed = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )
    return completed.stdout.strip()


def os_observation() -> dict:
    command = r"""
$names = @('velociraptor','velociraptor-client','velociraptor-v0.75.1-windows-amd64')
$procs = @(Get-CimInstance Win32_Process | Where-Object { $names -contains ([IO.Path]::GetFileNameWithoutExtension($_.Name)) -or $_.Name -like 'velociraptor*' })
$pids = @($procs.ProcessId)
$connections = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $pids -contains $_.OwningProcess } | Select-Object OwningProcess,State,LocalAddress,LocalPort,RemoteAddress,RemotePort)
$dns = @(Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -match 'github\.com|sysinternals\.com|velocidex\.com' } | Select-Object Entry,Type,Status,Data)
[ordered]@{ at=(Get-Date).ToUniversalTime().ToString('o'); processes=@($procs | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CreationDate,CommandLine); connections=$connections; dns_cache=$dns } | ConvertTo-Json -Depth 8 -Compress
"""
    return json.loads(powershell(command))


def trace_status() -> str:
    completed = subprocess.run(
        ["netsh.exe", "trace", "show", "status"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )
    output = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip())
    if completed.returncode not in (0, 1) or not output:
        raise RuntimeError(f"netsh trace status failed: rc={completed.returncode}; output={output!r}")
    return output


def trace_is_inactive(raw: str) -> bool:
    lowered = raw.lower()
    return (
        "not running" in lowered
        or "no trace session currently in progress" in lowered
        or "没有运行" in raw
        or "未运行" in raw
    )


def process_identity(pid: int) -> dict | None:
    raw = powershell(
        "$p=Get-CimInstance Win32_Process -Filter \"ProcessId=%d\" -ErrorAction SilentlyContinue; "
        "if($null -eq $p){'null'}else{$p | Select-Object ProcessId,ParentProcessId,Name,CreationDate,CommandLine | ConvertTo-Json -Compress}" % pid
    )
    return None if raw == "null" or not raw else json.loads(raw)


def protected_processes() -> list[dict]:
    protected = f"0,4,{os.getpid()},{os.getppid()}"
    command = r"""
$protected = @(%s)
$items = @(Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -in $protected -or $_.Name -like 'velociraptor*' })
@($items | Where-Object { $null -ne $_ } | Sort-Object ProcessId -Unique | Select-Object ProcessId,ParentProcessId,Name,CreationDate,CommandLine) | ConvertTo-Json -Depth 5 -Compress
""" % protected
    raw = powershell(command)
    value = json.loads(raw)
    return value if isinstance(value, list) else [value]


def result_row(result) -> dict:
    return {
        "is_error": bool(result.is_error),
        "structured": result.structured_content,
    }


async def call(session, evidence: dict, label: str, tool: str, arguments: dict) -> dict:
    result = result_row(await session.call_tool(tool, arguments))
    evidence["calls"][label] = {"tool": tool, "arguments": arguments, "result": result}
    return result


async def wait_flow(session, evidence: dict, flow_id: str, label: str, timeout: int) -> dict:
    deadline = time.monotonic() + timeout
    samples = []
    while time.monotonic() < deadline:
        row = await call(
            session,
            evidence,
            f"{label}-poll-{len(samples):03d}",
            "get_flow_status",
            {"flow_id": flow_id},
        )
        if row["is_error"]:
            raise AssertionError(row)
        samples.append(row["structured"]["state"])
        if samples[-1] in TERMINAL:
            evidence.setdefault("flow_states", {})[flow_id] = samples
            return row["structured"]
        await asyncio.sleep(1)
    raise AssertionError(f"flow timeout: {flow_id}; samples={samples}")


def find_etl(rows: list[dict]) -> str:
    for row in rows:
        for key, value in row.items():
            if str(key).lower() not in {"etl_file", "tracefile", "trace_file"} or not isinstance(value, str):
                continue
            if value.lower().endswith(".etl") and "\n" not in value and "\r" not in value:
                return value
            match = re.search(r"[A-Za-z]:\\[^\r\n]*?\.etl", value, flags=re.IGNORECASE)
            if match:
                return match.group(0)
    raise AssertionError(f"PacketCapture start result has no ETL path: {rows!r}")


async def main_async(attempt_id: str) -> tuple[dict, Path]:
    if os.environ.get("COMPUTERNAME", "").upper() != "DESKTOP-3FI41GR":
        raise RuntimeError("P05 real acceptance only runs on DESKTOP-3FI41GR")
    fixture = json.loads(FIXTURE_INSTANCE.read_text(encoding="utf-8"))
    if fixture["workflow_id"] != WORKFLOW_ID or fixture["attempt_id"] != attempt_id:
        raise RuntimeError("fixture instance identity mismatch")
    initial_trace = trace_status()
    if not trace_is_inactive(initial_trace):
        raise RuntimeError("global netsh trace was already active; refusing to stop it")
    run_dir = OUT_ROOT / attempt_id
    run_dir.mkdir(parents=True, exist_ok=True)
    evidence = {
        "schema": "p05-real-acceptance-v1",
        "workflow_id": WORKFLOW_ID,
        "attempt_id": attempt_id,
        "hostname": os.environ.get("COMPUTERNAME"),
        "started_at": utc_now(),
        "calls": {},
        "owned_flows": [],
        "network_before": os_observation(),
        "trace_before": initial_trace,
    }
    active_flows: set[str] = set()
    trace_owned = False
    failure: BaseException | None = None
    stderr_file = tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False)
    stderr_path = Path(stderr_file.name)
    try:
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(REPO_ROOT / "mcp_velociraptor_bridge.py")],
            cwd=REPO_ROOT,
            env=dict(os.environ),
        )
        async with stdio_client(params, errlog=stderr_file) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = (await session.list_tools()).tools
                assert len(tools) == 130

                packet_start = await call(
                    session,
                    evidence,
                    "packet-start",
                    "Windows.Network.PacketCapture",
                    {"StartTrace": True},
                )
                assert not packet_start["is_error"], packet_start
                packet_start_id = packet_start["structured"]["flow_id"]
                evidence["owned_flows"].append(packet_start_id)
                active_flows.add(packet_start_id)
                final = await wait_flow(session, evidence, packet_start_id, "packet-start", 180)
                assert final["state"] == "FINISHED", final
                active_flows.discard(packet_start_id)
                packet_rows = await call(
                    session,
                    evidence,
                    "packet-start-results",
                    "get_flow_results",
                    {"flow_id": packet_start_id, "page_size": 20},
                )
                assert not packet_rows["is_error"], packet_rows
                active_trace = trace_status()
                assert not trace_is_inactive(active_trace), active_trace
                # The initial state was inactive and this exact owned flow just
                # started the now-active trace. Mark ownership before parsing the
                # localized netsh output so every later failure may clean it up.
                trace_owned = True
                evidence["trace_owned"] = {"owned": True, "status": active_trace, "at": utc_now()}
                etl_path = find_etl(packet_rows["structured"]["data"])
                assert Path(etl_path).suffix.lower() == ".etl"
                evidence["trace_owned"]["etl_path"] = etl_path

                packet_stop = await call(
                    session,
                    evidence,
                    "packet-stop",
                    "Windows.Network.PacketCapture",
                    {"StartTrace": False, "TraceFile": etl_path},
                )
                assert not packet_stop["is_error"], packet_stop
                packet_stop_id = packet_stop["structured"]["flow_id"]
                evidence["owned_flows"].append(packet_stop_id)
                active_flows.add(packet_stop_id)
                final = await wait_flow(session, evidence, packet_stop_id, "packet-stop", 300)
                assert final["state"] == "FINISHED", final
                active_flows.discard(packet_stop_id)
                packet_files = await call(
                    session,
                    evidence,
                    "packet-files",
                    "list_flow_files",
                    {"flow_id": packet_stop_id},
                )
                assert not packet_files["is_error"], packet_files
                paths = [row["original_path"].lower() for row in packet_files["structured"]["data"]]
                assert any(path.endswith(".etl") for path in paths), paths
                assert any(path.endswith(".pcapng") for path in paths), paths
                assert trace_is_inactive(trace_status())
                trace_owned = False

                autoruns = await call(session, evidence, "autoruns", "Windows.Sysinternals.Autoruns", {})
                assert not autoruns["is_error"], autoruns
                autoruns_id = autoruns["structured"]["flow_id"]
                evidence["owned_flows"].append(autoruns_id)
                active_flows.add(autoruns_id)
                final = await wait_flow(session, evidence, autoruns_id, "autoruns", 600)
                assert final["state"] == "FINISHED", final
                active_flows.discard(autoruns_id)
                autorun_rows = await call(
                    session,
                    evidence,
                    "autoruns-results",
                    "get_flow_results",
                    {"flow_id": autoruns_id, "page_size": 10},
                )
                assert not autorun_rows["is_error"], autorun_rows

                triage = await call(session, evidence, "triage", "collect_forensic_triage", {})
                assert not triage["is_error"], triage
                triage_id = triage["structured"]["flow_id"]
                evidence["owned_flows"].append(triage_id)
                active_flows.add(triage_id)
                final = await wait_flow(session, evidence, triage_id, "triage", 2400)
                assert final["state"] == "FINISHED", final
                active_flows.discard(triage_id)
                triage_results = await call(
                    session,
                    evidence,
                    "triage-results",
                    "get_flow_results",
                    {"flow_id": triage_id, "page_size": 10},
                )
                assert not triage_results["is_error"], triage_results
                triage_files = await call(
                    session,
                    evidence,
                    "triage-files",
                    "list_flow_files",
                    {"flow_id": triage_id},
                )
                assert not triage_files["is_error"], triage_files

                target = fixture["process"]
                target_before = process_identity(int(target["pid"]))
                assert target_before is not None
                assert WORKFLOW_ID in target_before["CommandLine"] and attempt_id in target_before["CommandLine"]
                protected_before = protected_processes()
                killed = await call(
                    session,
                    evidence,
                    "kill-process",
                    "kill_process",
                    {"pid": int(target["pid"])},
                )
                assert not killed["is_error"], killed
                kill_id = killed["structured"]["flow_id"]
                evidence["owned_flows"].append(kill_id)
                active_flows.add(kill_id)
                final = await wait_flow(session, evidence, kill_id, "kill", 180)
                assert final["state"] == "FINISHED", final
                active_flows.discard(kill_id)
                kill_rows = await call(
                    session,
                    evidence,
                    "kill-results",
                    "get_flow_results",
                    {"flow_id": kill_id, "page_size": 10},
                )
                assert not kill_rows["is_error"], kill_rows
                assert any(
                    row.get("Pid") == int(target["pid"])
                    and row.get("Killed") == int(target["pid"])
                    for row in kill_rows["structured"]["data"]
                )
                assert process_identity(int(target["pid"])) is None
                protected_after = protected_processes()
                before_identity = {(row["ProcessId"], row["CreationDate"]) for row in protected_before}
                after_identity = {(row["ProcessId"], row["CreationDate"]) for row in protected_after}
                assert before_identity <= after_identity
                evidence["kill_identity"] = {
                    "target_before": target_before,
                    "target_after": None,
                    "protected_before": protected_before,
                    "protected_after": protected_after,
                }

                evidence["active_flow_count_at_exit"] = len(active_flows)
                assert evidence["active_flow_count_at_exit"] == 0
    except BaseException as exc:
        failure = exc
        evidence["failure"] = exception_record(exc)
    finally:
        if trace_owned:
            emergency_before = trace_status()
            evidence["emergency_trace_stop"] = {
                "before": emergency_before,
                "owned": True,
                "result": powershell("netsh trace stop", timeout=120),
                "after": trace_status(),
            }
        evidence["unsettled_owned_flows"] = sorted(active_flows)
        evidence["trace_after"] = trace_status()
        evidence["network_after"] = os_observation()
        evidence["ended_at"] = utc_now()
        stderr_file.close()
        stderr_path.unlink(missing_ok=True)

    combined_network = json.dumps(
        [evidence["network_before"], evidence["network_after"]], ensure_ascii=False
    ).lower()
    evidence["original_domain_observation"] = {
        domain: combined_network.count(domain) for domain in ORIGINAL_DOMAINS
    }
    # Existing DNS cache entries are reported, not hidden. Product success additionally
    # requires no new connection or service-log evidence to an original source.
    evidence["ok"] = (
        failure is None
        and not evidence["unsettled_owned_flows"]
        and trace_is_inactive(evidence["trace_after"])
        and evidence.get("active_flow_count_at_exit") == 0
    )
    output = OUT_ROOT / attempt_id / "p05-real-acceptance.json"
    output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
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
