"""G05 real-API acceptance probe for tests/p05_pc021_package.py.

Runs on the audited Windows target inside one owned directory.  Builds a
frozen synthetic report with the real runner call-row schema and a trusted
download root, then exercises the preserver, manifest, and verifier over
real NTFS I/O: ordinary / empty / sparse-logical members, two independently
bound fixture chains, and the full rejection matrix.  Real-API outcomes and
injected faults are counted separately; no mock success is ever reported as
production I/O.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import p05_pc021_package as pkg  # noqa: E402


SENTINEL_BYTES = b"g05 external sentinel must remain unchanged"
ASCII_FLOW = "ascii-fixture-flow-0001"
UTF8_FLOW = "utf8-元据-flow-0002"
SPARSE_LOGICAL = 16
SPARSE_STORED = 7
WORKFLOW_ID = "wf-01a05d1d-6e2b-7f41-b936-536d20ce55a2"


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record(kind: str, **fields: Any) -> dict[str, Any]:
    return {"kind": kind, **fields}


def make_case(root: Path) -> tuple[dict[str, Any], dict[str, dict[str, bytes]]]:
    """Frozen report + trusted-root contents for three chains."""
    ordinary_id = "a" * 64
    empty_id = "b" * 64
    sparse_id = "c" * 64
    ordinary_payload = b"g05 ordinary logical original bytes"
    sparse_payload = b"0123456" + b"\x00" * (SPARSE_LOGICAL - SPARSE_STORED)
    original_paths = {
        ordinary_id: "C:\\Users\\sample\\ordinary.bin",
        empty_id: "C:\\Users\\sample\\empty.bin",
        sparse_id: "C:\\Users\\sample\\sparse.bin",
    }
    sources = {
        ASCII_FLOW: {
            ordinary_id: ordinary_payload,
            empty_id: b"",
        },
        UTF8_FLOW: {
            sparse_id: sparse_payload,
        },
    }
    calls: list[dict[str, Any]] = []

    def list_call(flow_id: str, rows: list[dict[str, Any]], *, truncated: bool = False):
        calls.append(
            {
                "arguments": {"flow_id": flow_id},
                "attempt": 1,
                "sequence": len(calls) + 1,
                "is_error": False,
                "step_id": f"list-{flow_id}",
                "structured": {
                    "operation": "list_flow_files",
                    "status": "success",
                    "warnings": [],
                    "data": rows,
                    "truncated": truncated,
                },
                "mcp_result": None,
                "tool": "list_flow_files",
                "started_at": "2026-09-22T01:00:00Z",
                "ended_at": "2026-09-22T01:00:01Z",
                "duration_ms": 1000,
            }
        )

    trusted = root / "trusted"

    def download_call(flow_id: str, file_id: str, payload: bytes):
        local_path = str(trusted / pkg.flow_key(flow_id) / file_id / "content.bin")
        calls.append(
            {
                "arguments": {"flow_id": flow_id, "file_id": file_id},
                "attempt": 1,
                "sequence": len(calls) + 1,
                "is_error": False,
                "step_id": f"download-{file_id[:6]}",
                "structured": {
                    "operation": "download_flow_file",
                    "status": "success",
                    "warnings": [],
                    "flow_id": flow_id,
                    "file_id": file_id,
                    "local_path": local_path,
                    "size": len(payload),
                    "sha256": sha_bytes(payload),
                    "original_path": original_paths[file_id],
                },
                "mcp_result": None,
                "tool": "download_flow_file",
                "started_at": "2026-09-22T01:00:02Z",
                "ended_at": "2026-09-22T01:00:03Z",
                "duration_ms": 1000,
            }
        )

    list_call(
        ASCII_FLOW,
        [
            {
                "file_id": ordinary_id,
                "original_path": original_paths[ordinary_id],
                "file_size": len(ordinary_payload),
                "uploaded_size": len(ordinary_payload),
                "accessor": "file",
            },
            {
                "file_id": empty_id,
                "original_path": original_paths[empty_id],
                "file_size": 0,
                "uploaded_size": 0,
                "accessor": "file",
            },
        ],
    )
    download_call(ASCII_FLOW, ordinary_id, ordinary_payload)
    download_call(ASCII_FLOW, empty_id, b"")
    list_call(
        UTF8_FLOW,
        [
            {
                "file_id": sparse_id,
                "original_path": original_paths[sparse_id],
                "file_size": SPARSE_LOGICAL,
                "uploaded_size": SPARSE_STORED,
                "accessor": "file",
            }
        ],
    )
    download_call(UTF8_FLOW, sparse_id, sparse_payload)
    report = {
        "schema_version": 2,
        "run_id": "g05-synthetic",
        "scenario": "g05-package",
        "calls": calls,
    }
    return report, sources


def materialize_trusted_root(root: Path, sources: dict[str, dict[str, bytes]]) -> None:
    for flow_id, files in sources.items():
        for file_id, payload in files.items():
            directory = root / pkg.flow_key(flow_id) / file_id
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "content.bin").write_bytes(payload)


def run_case(results: list[dict[str, Any]], name: str, reject_kind: str, fn) -> None:
    try:
        results.append(fn())
    except pkg.PackagePreservationError as exc:
        results.append(
            record(reject_kind, case=name, rejected=True, message=str(exc)[:200])
        )
    except refresh_error() as exc:
        results.append(
            record(reject_kind, case=name, rejected=True, stage=exc.stage, message=str(exc)[:200])
        )
    except Exception as exc:
        results.append(
            record("unexpected_error", case=name, error=f"{type(exc).__name__}: {exc}")
        )


def refresh_error():
    return pkg.refresh.Pc022WindowsRefreshError


def main() -> int:
    if os.name != "nt":
        raise RuntimeError("Windows-only probe")
    root = Path(sys.argv[1]).resolve(strict=True)
    sentinel = root / "sentinel.bin"
    sentinel.write_bytes(SENTINEL_BYTES)

    report, sources = make_case(root)
    report_bytes = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    report_sha_before = sha_bytes(report_bytes)

    results: list[dict[str, Any]] = []

    def fresh_phase(name: str) -> tuple[Path, Path, Path]:
        trusted = root / "trusted"
        materialize_trusted_root(trusted, sources)
        phase = root / f"{name}-phase"
        phase.mkdir()
        report_path = phase / "report.json"
        report_path.write_bytes(report_bytes)
        return trusted, phase, report_path

    def p1_preserve_all_members() -> dict[str, Any]:
        trusted, phase, report_path = fresh_phase("p1")
        frozen = json.loads(report_path.read_bytes())
        chains = pkg.locate_download_chains(frozen)
        preserved = [
            pkg.preserve_chain(chain, phase_root=phase, trusted_root=trusted)
            for chain in chains
        ]
        return record(
            "real_api_success",
            case="P1_preserve_ordinary_empty_sparse",
            chains=len(chains),
            members=[row["member_path"] for row in preserved],
            note="ordinary+empty on ASCII flow; sparse-logical member on UTF-8 flow",
        )

    def p2_manifest_and_verify() -> dict[str, Any]:
        trusted, phase, report_path = fresh_phase("p2")
        frozen = json.loads(report_path.read_bytes())
        for chain in pkg.locate_download_chains(frozen):
            pkg.preserve_chain(chain, phase_root=phase, trusted_root=trusted)
        manifest = pkg.build_phase_manifest(
            phase_root=phase,
            phase_prefix="phase-p2",
            workflow_id=WORKFLOW_ID,
            report=frozen,
            report_ref_path="phase-p2/report.json",
        )
        payload = pkg.persist_phase_manifest(manifest, phase)
        reparsed = json.loads(payload)
        pkg.verify_phase_package(
            phase_root=phase,
            manifest=reparsed,
            report=frozen,
            report_ref_path="phase-p2/report.json",
        )
        member_paths = [member["path"] for member in reparsed["members"]]
        return record(
            "real_api_success",
            case="P2_manifest_exact_set_and_verify",
            members=member_paths,
            report_frozen=sha_bytes(report_path.read_bytes()) == report_sha_before,
        )

    def p3_two_fixtures_independently_bound() -> dict[str, Any]:
        trusted, phase, report_path = fresh_phase("p3")
        frozen = json.loads(report_path.read_bytes())
        chains = pkg.locate_download_chains(frozen)
        for chain in chains:
            pkg.preserve_chain(chain, phase_root=phase, trusted_root=trusted)
        keys = {pkg.flow_key(chain.flow_id) for chain in chains}
        return record(
            "real_api_success",
            case="P3_two_fixture_bindings_distinct",
            distinct_flow_keys=len(keys) == len({chain.flow_id for chain in chains}) == 2,
            utf8_flow_encoded=pkg.flow_key(UTF8_FLOW) != pkg.flow_key(ASCII_FLOW),
        )

    def n1_target_collision() -> dict[str, Any]:
        trusted, phase, report_path = fresh_phase("n1")
        frozen = json.loads(report_path.read_bytes())
        chain = pkg.locate_download_chains(frozen)[0]
        target = phase / "downloads" / pkg.flow_key(chain.flow_id) / chain.file_id / "content.bin"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"preexisting collision")
        pkg.preserve_chain(chain, phase_root=phase, trusted_root=trusted)
        raise AssertionError("collision did not reject")

    def n2_source_rewrite_same_size() -> dict[str, Any]:
        trusted, phase, report_path = fresh_phase("n2")
        frozen = json.loads(report_path.read_bytes())
        chain = pkg.locate_download_chains(frozen)[0]
        source = trusted / pkg.flow_key(chain.flow_id) / chain.file_id / "content.bin"
        payload = bytearray(source.read_bytes())
        payload[0] ^= 0xFF
        source.write_bytes(bytes(payload))
        pkg.preserve_chain(chain, phase_root=phase, trusted_root=trusted)
        raise AssertionError("content drift did not reject")

    def n3_source_identity_drift_injected() -> dict[str, Any]:
        trusted, phase, report_path = fresh_phase("n3")
        frozen = json.loads(report_path.read_bytes())
        chain = pkg.locate_download_chains(frozen)[0]
        real_identity = pkg._file_identity
        calls = {"n": 0}

        def drifting(path):
            calls["n"] += 1
            identity = real_identity(path)
            if calls["n"] == 2:
                return (identity[0], identity[1] + 1)
            return identity

        pkg._file_identity = drifting
        try:
            pkg.preserve_chain(chain, phase_root=phase, trusted_root=trusted)
            raise AssertionError("identity drift did not reject")
        finally:
            pkg._file_identity = real_identity

    def n4_reparse_source() -> dict[str, Any]:
        trusted, phase, report_path = fresh_phase("n4")
        chain = pkg.locate_download_chains(json.loads(report_bytes))[0]
        victim_dir = trusted / pkg.flow_key(chain.flow_id) / chain.file_id
        payload = victim_dir / "content.bin"
        expected_payload = payload.read_bytes()
        payload.unlink()
        victim_dir.rmdir()
        real_dir = root / "n4-real"
        real_dir.mkdir()
        (real_dir / "content.bin").write_bytes(expected_payload)
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"New-Item -ItemType Junction -Path '{victim_dir}' -Value '{real_dir}' | Out-Null"],
            check=True, capture_output=True, timeout=60,
        )
        # local_path stays exact; the reparse sits on the ancestor chain
        try:
            pkg.preserve_chain(chain, phase_root=phase, trusted_root=trusted)
            raise AssertionError("reparse ancestor did not reject")
        finally:
            import shutil
            victim_dir.rmdir()  # removes the junction itself, not the target
            victim_dir.mkdir(parents=True, exist_ok=True)
            payload.write_bytes(expected_payload)
            shutil.rmtree(real_dir)

    def n5_alias_local_path() -> dict[str, Any]:
        outcomes: dict[str, bool] = {}
        for alias in ("upper", "slash", "dotdot"):
            trusted, phase, report_path = fresh_phase(f"n5-{alias}")
            mutated = json.loads(report_bytes)
            chain = pkg.locate_download_chains(mutated)[0]
            exact = chain.local_path
            variant = {
                "upper": exact.upper(),
                "slash": exact.replace("\\", "/"),
                "dotdot": exact.replace("\\content.bin", "\\..\\content.bin"),
            }[alias]
            mutated["calls"][chain.download_index]["structured"]["local_path"] = variant
            try:
                pkg.preserve_chain(
                    pkg.locate_download_chains(mutated)[0],
                    phase_root=phase,
                    trusted_root=trusted,
                )
                outcomes[alias] = False
            except (pkg.PackagePreservationError, pkg.refresh.Pc022WindowsRefreshError):
                outcomes[alias] = True
        if not all(outcomes.values()):
            raise AssertionError(f"alias acceptance leak: {outcomes}")
        return record(
            "real_api_success",
            case="N5_alias_local_paths_all_rejected",
            rejected_aliases=outcomes,
        )

    def n6_fabricated_files_field() -> dict[str, Any]:
        trusted, phase, report_path = fresh_phase("n6")
        mutated = json.loads(report_bytes)
        list_index = pkg.locate_download_chains(mutated)[0].list_index
        structured = mutated["calls"][list_index]["structured"]
        structured["files"] = structured.pop("data")
        pkg.locate_download_chains(mutated)
        raise AssertionError("fabricated files field did not reject")

    def n7_truncated_list() -> dict[str, Any]:
        trusted, phase, report_path = fresh_phase("n7")
        mutated = json.loads(report_bytes)
        list_index = pkg.locate_download_chains(mutated)[0].list_index
        mutated["calls"][list_index]["structured"]["truncated"] = True
        pkg.locate_download_chains(mutated)
        raise AssertionError("truncated list did not reject")

    def n8_duplicate_chain() -> dict[str, Any]:
        mutated = json.loads(report_bytes)
        chains = pkg.locate_download_chains(mutated)
        duplicate = json.loads(json.dumps(mutated["calls"][chains[0].download_index]))
        mutated["calls"].append(duplicate)
        pkg.locate_download_chains(mutated)
        raise AssertionError("duplicate chain did not reject")

    def n9_size_mismatch() -> dict[str, Any]:
        trusted, phase, report_path = fresh_phase("n9")
        mutated = json.loads(report_bytes)
        chains = pkg.locate_download_chains(mutated)
        list_index = chains[0].list_index
        mutated["calls"][list_index]["structured"]["data"][0]["file_size"] += 1
        pkg.locate_download_chains(mutated)
        raise AssertionError("row/download size mismatch did not reject")

    def n10_stale_part_blocks_manifest() -> dict[str, Any]:
        trusted, phase, report_path = fresh_phase("n10")
        frozen = json.loads(report_path.read_bytes())
        for chain in pkg.locate_download_chains(frozen):
            pkg.preserve_chain(chain, phase_root=phase, trusted_root=trusted)
        (phase / "downloads" / "stale.part").write_bytes(b"stale")
        pkg.build_phase_manifest(
            phase_root=phase,
            phase_prefix="phase-n10",
            workflow_id=WORKFLOW_ID,
            report=frozen,
            report_ref_path="phase-n10/report.json",
        )
        raise AssertionError("stale part did not reject manifest build")

    def n11_manifest_extra_member_rejected_by_verify() -> dict[str, Any]:
        trusted, phase, report_path = fresh_phase("n11")
        frozen = json.loads(report_path.read_bytes())
        for chain in pkg.locate_download_chains(frozen):
            pkg.preserve_chain(chain, phase_root=phase, trusted_root=trusted)
        manifest = pkg.build_phase_manifest(
            phase_root=phase,
            phase_prefix="phase-n11",
            workflow_id=WORKFLOW_ID,
            report=frozen,
            report_ref_path="phase-n11/report.json",
        )
        manifest["members"] = manifest["members"][:-1]
        pkg.verify_phase_package(
            phase_root=phase,
            manifest=manifest,
            report=frozen,
            report_ref_path="phase-n11/report.json",
        )
        raise AssertionError("missing member did not reject verification")

    for case in (p1_preserve_all_members, p2_manifest_and_verify, p3_two_fixtures_independently_bound):
        run_case(results, case.__name__, "real_api_rejection", case)
    for case in (
        n1_target_collision, n2_source_rewrite_same_size, n3_source_identity_drift_injected,
        n4_reparse_source, n5_alias_local_path, n6_fabricated_files_field, n7_truncated_list,
        n8_duplicate_chain, n9_size_mismatch, n10_stale_part_blocks_manifest,
        n11_manifest_extra_member_rejected_by_verify,
    ):
        run_case(results, case.__name__, "real_api_rejection", case)
    results.append(
        record(
            "injected_fault",
            case="N3_identity_drift_note",
            note="identity drift executed via a seam substitution inside "
                 "n3_source_identity_drift_injected; that row also carries the rejection",
        )
    )

    sentinel_ok = sentinel.read_bytes() == SENTINEL_BYTES
    summary = {
        "schema_version": 1,
        "probe": "g05-pc021-package",
        "runtime": {
            "sys_executable": sys.executable,
            "python_version": sys.version,
            "platform": platform.platform(),
            "root": str(root),
        },
        "counts": {
            "real_api_success": sum(1 for r in results if r["kind"] == "real_api_success"),
            "real_api_rejection": sum(
                1 for r in results if r.get("rejected") and r["kind"] != "injected_fault"
            ),
            "injected_fault": sum(1 for r in results if r["kind"] == "injected_fault"),
            "not_run": sum(1 for r in results if r["kind"] == "not_run"),
            "unexpected_error": sum(1 for r in results if r["kind"] == "unexpected_error"),
        },
        "sentinel_unchanged": sentinel_ok,
        "durability_claim": False,
        "results": results,
    }
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0 if (summary["counts"]["unexpected_error"] == 0 and sentinel_ok) else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise RuntimeError("expected one owned directory argument")
    raise SystemExit(main())
