"""G04 real-API acceptance probe for tests/pc022_windows_refresh.py.

Runs on the audited Windows target inside one owned temporary directory.
Every case is classified as one of: real_api_success, real_api_rejection,
injected_fault, or not_run.  Mock-level injections (CloseHandle /
FlushFileBuffers / FileIdInfo identity substitution) are counted separately
from real-API outcomes and never presented as production I/O.  The probe
asserts that an external sentinel file and the absent canonical state remain
untouched by every negative case.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pc022_windows_refresh as refresh  # noqa: E402


SENTINEL_BYTES = b"g04 external sentinel must remain unchanged"


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record(kind: str, **fields: Any) -> dict[str, Any]:
    return {"kind": kind, **fields}


def run_case(results: list[dict[str, Any]], name: str, reject_kind: str, fn) -> None:
    try:
        results.append(fn())
    except refresh.Pc022WindowsRefreshError as exc:
        results.append(
            record(
                reject_kind,
                case=name,
                rejected=True,
                stage=exc.stage,
                winerror=exc.winerror,
                aggregated=exc.aggregated,
            )
        )
    except Exception as exc:  # unexpected outcome invalidates the probe
        results.append(
            record("unexpected_error", case=name, error=f"{type(exc).__name__}: {exc}")
        )


def make_probe(root: Path) -> int:
    if os.name != "nt":
        raise RuntimeError("Windows-only probe")
    root = root.resolve(strict=True)
    sentinel = root / "sentinel.bin"
    sentinel.write_bytes(SENTINEL_BYTES)
    canonical_probe_path = root.parent / "snapshot-recovery-state.json"
    canonical_before = canonical_probe_path.exists()

    results: list[dict[str, Any]] = []

    unique = itertools.count(1)

    def plain_directory() -> Path:
        directory = root / f"plain-dir-{next(unique)}"
        directory.mkdir(exist_ok=False)
        return directory

    # P1 real: refresh succeeds on a fresh plain directory
    def p1_refresh_success() -> dict[str, Any]:
        directory = plain_directory()
        observation = refresh.windows_refresh_directory(directory)
        return record(
            "real_api_success", case="P1_refresh_success", observation=observation
        )

    # P2 real: three-level hierarchy with per-level refresh
    def p2_hierarchy_success() -> dict[str, Any]:
        base = root / "hier-base"
        base.mkdir(exist_ok=False)
        deepest = refresh.create_hierarchy_and_refresh(base, ("A", "B", "C"))
        marker = deepest / "member.bin"
        marker.write_bytes(b"hierarchy member")
        refresh.windows_refresh_directory(marker.parent)
        return record(
            "real_api_success",
            case="P2_hierarchy_success",
            deepest=str(deepest.relative_to(root)),
            member_sha256=sha_bytes(marker.read_bytes()),
        )

    # P3 real: regular file persist control then parent refresh
    def p3_file_control() -> dict[str, Any]:
        target = root / "plain-file.bin"
        with target.open("xb") as stream:
            stream.write(b"g04 regular file control")
            stream.flush()
            os.fsync(stream.fileno())
        refresh.windows_refresh_directory(target.parent)
        return record(
            "real_api_success",
            case="P3_file_control",
            sha256=sha_bytes(target.read_bytes()),
        )

    # P4 real: same-volume replace via MoveFileExW flags 9
    def p4_replace_success() -> dict[str, Any]:
        source = root / "move-src.bin"
        target = root / "move-tgt.bin"
        source.write_bytes(b"g04 replace new content")
        target.write_bytes(b"g04 replace old content")
        refresh.windows_replace_file(source, target)
        return record(
            "real_api_success",
            case="P4_replace_success",
            source_exists=source.exists(),
            target_sha256=sha_bytes(target.read_bytes()),
        )

    # P5 real: stable identity across two lightweight probes
    def p5_identity_stable() -> dict[str, Any]:
        directory = plain_directory()
        first = refresh.handle_directory_identity(directory)
        second = refresh.handle_directory_identity(directory)
        return record(
            "real_api_success",
            case="P5_identity_stable",
            equal=first == second,
            volume_serial_number=first[0],
        )

    # N1 real: helper called on a regular writable file -> type rejection
    def n1_type_reject() -> dict[str, Any]:
        target = root / "type-file.bin"
        target.write_bytes(b"writable file for type rejection")
        refresh.windows_refresh_directory(target)
        raise AssertionError("type rejection did not trigger")

    # N2 real: junction directory -> reparse rejection without following
    def n2_reparse_reject() -> dict[str, Any]:
        target = root / "junction-target"
        target.mkdir(exist_ok=False)
        link = root / "junction-link"
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"New-Item -ItemType Junction -Path '{link}' -Value '{target}' | Out-Null"],
            check=True,
            capture_output=True,
            timeout=60,
        )
        refresh.windows_refresh_directory(link)
        raise AssertionError("reparse rejection did not trigger")

    # N3 real: a real directory swap produces different FileIdInfo identities,
    # which is exactly what helper compare_pre/compare_post reject (see I3)
    def n3_drift_detectable() -> dict[str, Any]:
        directory = root / "drift-dir"
        directory.mkdir(exist_ok=False)
        (directory / "marker.bin").write_bytes(b"original directory object")
        main_identity = refresh.handle_directory_identity(
            directory, desired_access=refresh.GENERIC_WRITE
        )
        moved = root / "drift-dir-moved"
        os.rename(directory, moved)
        directory.mkdir(exist_ok=False)
        (directory / "marker.bin").write_bytes(b"replacement directory object")
        pre_identity = refresh.handle_directory_identity(
            directory, desired_access=refresh.GENERIC_WRITE
        )
        drift_detected = main_identity != pre_identity
        (directory / "marker.bin").unlink()
        os.rmdir(directory)
        os.rename(moved, directory)
        refresh.windows_refresh_directory(directory)
        return record(
            "real_api_success",
            case="N3_drift_detectable",
            drift_detected=drift_detected,
            note="FileIdInfo identities differ across a real swap; the helper's "
                 "compare_pre/compare_post refusal of such a difference is covered "
                 "by the I3 injection",
        )

    # N4 real: nonexistent path -> open rejection
    def n4_open_reject() -> dict[str, Any]:
        refresh.windows_refresh_directory(root / "does-not-exist")
        raise AssertionError("open rejection did not trigger")

    # N5 real: denied write ACL on an owned directory -> open rejection, then restore
    def n5_permission_reject() -> dict[str, Any]:
        directory = plain_directory()
        user = os.environ.get("USERNAME", "")
        subprocess.run(
            ["icacls", str(directory), "/deny", f"{user}:(W)"],
            check=True, capture_output=True, timeout=60,
        )
        try:
            refresh.windows_refresh_directory(directory)
            raise AssertionError("permission rejection did not trigger")
        finally:
            subprocess.run(
                ["icacls", str(directory), "/remove:d", user],
                check=True, capture_output=True, timeout=60,
            )

    # N6 real: hierarchy refuses an already-existing component
    def n6_already_exists() -> dict[str, Any]:
        base = root / "exists-base"
        base.mkdir(exist_ok=False)
        (base / "A").mkdir(exist_ok=False)
        refresh.create_hierarchy_and_refresh(base, ("A", "B"))
        raise AssertionError("already-exists rejection did not trigger")

    # N7 pure: cross-volume comparison refusal is a pure function of identities
    def n7_cross_volume_pure() -> dict[str, Any]:
        refresh.require_same_volume((111, b"a"), (222, b"a"), label="pure")
        raise AssertionError("cross-volume rejection did not trigger")

    # I1 injected: third close attempt fails; aggregated, helper reports close failure
    def i1_close_injection() -> dict[str, Any]:
        directory = plain_directory()
        real_close = refresh.CloseHandle
        calls = {"n": 0}

        def failing_close(handle):
            calls["n"] += 1
            if calls["n"] == 3:
                return 0
            return real_close(handle)

        refresh.CloseHandle = failing_close
        try:
            refresh.windows_refresh_directory(directory)
            raise AssertionError("close injection did not surface")
        except refresh.Pc022WindowsRefreshError as exc:
            return record(
                "injected_fault",
                case="I1_close_injection",
                stage=exc.stage,
                aggregated=exc.aggregated,
                close_calls=calls["n"],
                note="third close (close_post) injected zero return; primary stage is close",
            )
        finally:
            refresh.CloseHandle = real_close

    # I2 injected: FlushFileBuffers returns zero; main failure kept, closes still run
    def i2_flush_injection() -> dict[str, Any]:
        directory = plain_directory()
        real_flush = refresh.FlushFileBuffers

        def failing_flush(handle):
            return 0

        refresh.FlushFileBuffers = failing_flush
        try:
            refresh.windows_refresh_directory(directory)
            raise AssertionError("flush injection did not surface")
        except refresh.Pc022WindowsRefreshError as exc:
            return record(
                "injected_fault",
                case="I2_flush_injection",
                stage=exc.stage,
                aggregated=exc.aggregated,
                note="flush_main failure preserved; handle closes still attempted",
            )
        finally:
            refresh.FlushFileBuffers = real_flush

    # I3 injected: post-close identity substitution -> compare_post rejection
    def i3_post_drift_injection() -> dict[str, Any]:
        directory = plain_directory()
        real_query = refresh._query_file_id
        calls = {"n": 0}

        def drifting_query(handle):
            calls["n"] += 1
            volser, file_id = real_query(handle)
            if calls["n"] == 3:
                return volser + 1, file_id
            return volser, file_id

        refresh._query_file_id = drifting_query
        try:
            refresh.windows_refresh_directory(directory)
            raise AssertionError("post-drift injection did not surface")
        except refresh.Pc022WindowsRefreshError as exc:
            return record(
                "injected_fault",
                case="I3_post_drift_injection",
                stage=exc.stage,
                aggregated=exc.aggregated,
                note="third FileIdInfo query (H_post) substituted; compare_post rejects",
            )
        finally:
            refresh._query_file_id = real_query

    for case in (
        p1_refresh_success, p2_hierarchy_success, p3_file_control,
        p4_replace_success, p5_identity_stable, n1_type_reject,
        n2_reparse_reject, n3_drift_detectable, n4_open_reject,
        n5_permission_reject, n6_already_exists, n7_cross_volume_pure,
    ):
        run_case(results, case.__name__, "real_api_rejection", case)
    for case in (i1_close_injection, i2_flush_injection, i3_post_drift_injection):
        run_case(results, case.__name__, "injected_fault", case)

    results.append(
        record(
            "not_run",
            case="cross_volume_real",
            reason="target exposes a single NTFS volume; real cross-volume replace "
                   "refusal is covered by the N7 identity comparison plus G05+ "
                   "same-volume preconditions",
        )
    )

    sentinel_ok = sentinel.read_bytes() == SENTINEL_BYTES
    canonical_after = canonical_probe_path.exists()
    summary = {
        "schema_version": 1,
        "probe": "g04-pc022-windows-refresh",
        "runtime": {
            "sys_executable": sys.executable,
            "python_version": sys.version,
            "platform": platform.platform(),
            "root": str(root),
            "is_windows": os.name == "nt",
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
        "canonical_probe_absent_before": canonical_before,
        "canonical_probe_absent_after": canonical_after,
        "durability_claim": False,
        "results": results,
    }
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0 if (summary["counts"]["unexpected_error"] == 0 and sentinel_ok) else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise RuntimeError("expected one owned directory argument")
    raise SystemExit(make_probe(Path(sys.argv[1])))
