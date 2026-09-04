from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


OUT = REPO_ROOT / "Logs" / "P04" / "wf-01a05d1d-p04" / "p04-real-acceptance.json"
FIXTURE_ROOT = Path(r"C:\VelociraptorMCP\fixtures")


def result_row(result):
    return {
        "is_error": bool(result.is_error),
        "content_count": len(result.content),
        "structured": result.structured_content,
    }


async def call(session, evidence, label, name, arguments):
    result = await session.call_tool(name, arguments)
    row = result_row(result)
    evidence["calls"][label] = {"tool": name, "arguments": arguments, "result": row}
    return row


async def wait_flow(session, evidence, flow_id, label, *, timeout=180, terminal=True):
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
        assert not row["is_error"], row
        samples.append(row["structured"]["state"])
        is_terminal = samples[-1] in {"FINISHED", "ERROR"}
        if is_terminal == terminal:
            return row["structured"], samples
        await asyncio.sleep(1)
    raise AssertionError(f"flow {flow_id} did not reach requested state; samples={samples}")


async def main_async():
    config = os.environ.get("VELOCIRAPTOR_API_CONFIG", "")
    if not config or not Path(config).is_file():
        raise RuntimeError("VELOCIRAPTOR_API_CONFIG must name an existing file")
    FIXTURE_ROOT.mkdir(parents=True, exist_ok=True)
    fixture_hashes = {}
    for index in range(1, 4):
        path = FIXTURE_ROOT / f"p04 page {index:02d}.txt"
        payload = f"p04-page-{index:02d}\r\n".encode("ascii")
        path.write_bytes(payload)
        fixture_hashes[str(path)] = hashlib.sha256(payload).hexdigest()
    exact_path = FIXTURE_ROOT / "p04 file fixture.txt"
    if not exact_path.exists():
        exact_path.write_bytes(b"mcp-p04-file-fixture\r\nline two\r\n")
    fixture_hashes[str(exact_path)] = hashlib.sha256(exact_path.read_bytes()).hexdigest()
    for directory, payload in (("p04 same a", b"same-a\r\n"), ("p04 same b", b"same-b\r\n")):
        same_path = FIXTURE_ROOT / directory / "same.txt"
        same_path.parent.mkdir(parents=True, exist_ok=True)
        same_path.write_bytes(payload)
        fixture_hashes[str(same_path)] = hashlib.sha256(payload).hexdigest()

    run_key = str(int(time.time() * 1000))
    download_root = Path(r"C:\VelociraptorMCP\downloads-p04") / run_key
    download_root.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ)
    env["VELOCIRAPTOR_DOWNLOAD_ROOT"] = str(download_root)
    stderr_file = tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False)
    stderr_path = Path(stderr_file.name)
    evidence = {
        "schema": "p04-real-acceptance-v1",
        "hostname": os.environ.get("COMPUTERNAME"),
        "fixture_hashes": fixture_hashes,
        "download_root": str(download_root),
        "calls": {},
        "owned": {"flows": [], "hunts": []},
    }
    active_flows = set()
    active_hunts = set()
    try:
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(REPO_ROOT / "mcp_velociraptor_bridge.py")],
            cwd=REPO_ROOT,
            env=env,
        )
        async with stdio_client(params, errlog=stderr_file) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                collected = await call(
                    session,
                    evidence,
                    "collect-glob",
                    "collect_file",
                    {"path": r"C:\VelociraptorMCP\fixtures\p04 page *.txt"},
                )
                assert not collected["is_error"], collected
                flow_id = collected["structured"]["flow_id"]
                evidence["owned"]["flows"].append(flow_id)
                active_flows.add(flow_id)
                final, samples = await wait_flow(session, evidence, flow_id, "glob")
                assert final["state"] == "FINISHED", final
                active_flows.discard(flow_id)
                evidence["glob_states"] = samples

                pages = []
                cursor = None
                for index in range(3):
                    page = await call(
                        session,
                        evidence,
                        f"metadata-page-{index + 1}",
                        "get_flow_results",
                        {
                            "flow_id": flow_id,
                            "source": "All Matches Metadata",
                            "cursor": cursor,
                            "page_size": 1,
                        },
                    )
                    assert not page["is_error"] and len(page["structured"]["data"]) == 1, page
                    pages.append(page["structured"]["data"][0])
                    cursor = page["structured"]["pagination"].get("next_cursor")
                assert [
                    evidence["calls"][f"metadata-page-{index}"]["result"]["structured"]["pagination"]["cursor"]
                    for index in range(1, 4)
                ] == ["v1:0", "v1:1", "v1:2"]
                assert len({json.dumps(row, sort_keys=True, default=str) for row in pages}) == 3

                uploads_page = await call(
                    session,
                    evidence,
                    "uploads-page",
                    "get_flow_results",
                    {"flow_id": flow_id, "source": "Uploads", "page_size": 3},
                )
                assert not uploads_page["is_error"]
                assert len(uploads_page["structured"]["data"]) == 3
                all_sources = await call(
                    session,
                    evidence,
                    "all-sources-page",
                    "get_flow_results",
                    {"flow_id": flow_id, "page_size": 6},
                )
                assert not all_sources["is_error"]
                assert len(all_sources["structured"]["data"]) == 6

                files = await call(
                    session, evidence, "list-files", "list_flow_files", {"flow_id": flow_id}
                )
                assert not files["is_error"] and len(files["structured"]["data"]) == 3, files
                file_entry = files["structured"]["data"][0]
                downloaded = await call(
                    session,
                    evidence,
                    "download-file",
                    "download_flow_file",
                    {"flow_id": flow_id, "file_id": file_entry["file_id"]},
                )
                assert not downloaded["is_error"] and downloaded["content_count"] == 0
                local_path = Path(downloaded["structured"]["local_path"])
                assert local_path.is_file()
                local_hash = hashlib.sha256(local_path.read_bytes()).hexdigest()
                assert local_hash == downloaded["structured"]["sha256"]
                assert str(local_path).startswith(str(download_root.resolve()))
                assert flow_id not in str(local_path)
                evidence["download_sha256_recomputed"] = local_hash
                conflict = await call(
                    session,
                    evidence,
                    "download-conflict",
                    "download_flow_file",
                    {"flow_id": flow_id, "file_id": file_entry["file_id"]},
                )
                assert conflict["is_error"]
                assert conflict["structured"]["code"] == "ALREADY_EXISTS"
                assert list(download_root.rglob("*.part")) == []

                exact = await call(
                    session,
                    evidence,
                    "collect-exact-space-path",
                    "collect_file",
                    {"path": str(exact_path)},
                )
                assert not exact["is_error"]
                exact_flow = exact["structured"]["flow_id"]
                evidence["owned"]["flows"].append(exact_flow)
                active_flows.add(exact_flow)
                exact_final, _ = await wait_flow(session, evidence, exact_flow, "exact")
                assert exact_final["state"] == "FINISHED"
                active_flows.discard(exact_flow)

                same_names = await call(
                    session,
                    evidence,
                    "collect-same-name-different-directories",
                    "collect_file",
                    {"path": r"C:\VelociraptorMCP\fixtures\p04 same *\same.txt"},
                )
                assert not same_names["is_error"]
                same_flow = same_names["structured"]["flow_id"]
                evidence["owned"]["flows"].append(same_flow)
                active_flows.add(same_flow)
                same_final, _ = await wait_flow(session, evidence, same_flow, "same-name")
                assert same_final["state"] == "FINISHED"
                active_flows.discard(same_flow)
                same_files = await call(
                    session,
                    evidence,
                    "list-same-name-different-directories",
                    "list_flow_files",
                    {"flow_id": same_flow},
                )
                assert not same_files["is_error"]
                same_rows = same_files["structured"]["data"]
                assert len(same_rows) == 2
                assert {Path(row["original_path"]).name for row in same_rows} == {"same.txt"}
                assert len({row["file_id"] for row in same_rows}) == 2

                sleep_flow = await call(
                    session,
                    evidence,
                    "start-cancel-flow",
                    "Windows.System.PowerShell",
                    {"Command": "Start-Sleep -Seconds 180", "Timeout": 210, "Stateful": False},
                )
                assert not sleep_flow["is_error"]
                cancel_id = sleep_flow["structured"]["flow_id"]
                evidence["owned"]["flows"].append(cancel_id)
                active_flows.add(cancel_id)
                before_cancel, _ = await wait_flow(
                    session, evidence, cancel_id, "cancel-before", terminal=False, timeout=30
                )
                assert before_cancel["state"] in {"WAITING", "RUNNING", "IN_PROGRESS"}
                cancelled = await call(
                    session, evidence, "cancel-flow", "cancel_flow", {"flow_id": cancel_id}
                )
                assert not cancelled["is_error"]
                assert cancelled["structured"]["state_before"] in {
                    "WAITING",
                    "RUNNING",
                    "IN_PROGRESS",
                }
                cancel_final, _ = await wait_flow(session, evidence, cancel_id, "cancel-after")
                assert cancel_final["state"] == "ERROR"
                active_flows.discard(cancel_id)
                cancel_again = await call(
                    session,
                    evidence,
                    "cancel-terminal",
                    "cancel_flow",
                    {"flow_id": cancel_id},
                )
                assert cancel_again["is_error"]
                assert cancel_again["structured"]["code"] == "NOT_CANCELLABLE"

                hunt = await call(
                    session,
                    evidence,
                    "start-hunt",
                    "start_hunt",
                    {
                        "artifact": "Windows.System.PowerShell",
                        "parameters": {
                            "Command": "Start-Sleep -Seconds 300",
                            "Timeout": 330,
                            "Stateful": False,
                        },
                        "description": "wf-01a05d1d-p04 real acceptance",
                    },
                )
                assert not hunt["is_error"], hunt
                hunt_id = hunt["structured"]["hunt_id"]
                hunt_flow = hunt["structured"]["flow_id"]
                evidence["owned"]["hunts"].append(hunt_id)
                evidence["owned"]["flows"].append(hunt_flow)
                active_hunts.add(hunt_id)
                active_flows.add(hunt_flow)
                hunt_status = await call(
                    session,
                    evidence,
                    "hunt-before-stop",
                    "get_hunt_status",
                    {"hunt_id": hunt_id},
                )
                assert hunt_status["structured"]["flow_id"] == hunt_flow
                hunt_flow_before, _ = await wait_flow(
                    session, evidence, hunt_flow, "hunt-flow-before-stop", terminal=False, timeout=30
                )
                assert hunt_flow_before["state"] in {"WAITING", "RUNNING", "IN_PROGRESS"}
                stopped = await call(
                    session, evidence, "stop-hunt", "stop_hunt", {"hunt_id": hunt_id}
                )
                assert not stopped["is_error"] and stopped["structured"]["state"] == "STOPPED"
                active_hunts.discard(hunt_id)
                hunt_flow_after = await call(
                    session,
                    evidence,
                    "hunt-flow-after-stop",
                    "get_flow_status",
                    {"flow_id": hunt_flow},
                )
                assert hunt_flow_after["structured"]["state"] in {
                    "WAITING",
                    "RUNNING",
                    "IN_PROGRESS",
                }
                hunt_cancel = await call(
                    session,
                    evidence,
                    "hunt-flow-explicit-cancel",
                    "cancel_flow",
                    {"flow_id": hunt_flow},
                )
                assert not hunt_cancel["is_error"]
                hunt_cancelled, _ = await wait_flow(
                    session, evidence, hunt_flow, "hunt-flow-after-cancel"
                )
                assert hunt_cancelled["state"] == "ERROR"
                active_flows.discard(hunt_flow)

                rejected_hunt = await call(
                    session,
                    evidence,
                    "hunt-not-allowlisted",
                    "start_hunt",
                    {"artifact": "Windows.Not.Approved"},
                )
                assert rejected_hunt["is_error"]
                assert rejected_hunt["structured"]["code"] == "NOT_FOUND"

                unknown_file = await call(
                    session,
                    evidence,
                    "unknown-file-id",
                    "download_flow_file",
                    {"flow_id": flow_id, "file_id": "0" * 64},
                )
                assert unknown_file["is_error"]
                assert unknown_file["structured"]["code"] == "NOT_FOUND"

                evidence["ok"] = True
    finally:
        stderr_file.flush()
        stderr_file.seek(0)
        stderr = stderr_file.read()
        stderr_file.close()
        stderr_path.unlink(missing_ok=True)
        evidence["stderr"] = {
            "length": len(stderr),
            "contains_traceback": "Traceback" in stderr,
            "contains_secret_path": "api_client.yaml" in stderr,
        }
        evidence["active_at_exit"] = {
            "flows": sorted(active_flows),
            "hunts": sorted(active_hunts),
        }
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": evidence.get("ok", False), "out": str(OUT)}, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main_async())
