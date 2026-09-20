#!/usr/bin/env python3
"""Validate the single recovery state and emit a VMware revert argv.

This governance helper never executes VMware or any other external process.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any


WORKFLOW_ID = "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2"
VMX = "/home/adminn/vmware/Win10MalBox-Velo/Win10MalBox-Velo.vmx"
BOOTSTRAP_NAME = "Snapshot 183-FakenetNG测试专用"
BOOTSTRAP_MARKER = "win10h2-MalBox-20241110-Snapshot99.vmsn"
INSTALLED_NAME = "Snapshot 184-Velociraptor-MCP测试基线"
DEPENDENCIES_NAME = "Snapshot 1-开启Windows-MCP"
NETWORK_NAME = "Snapshot 186-Velociraptor-MCP网络部署基线"
PREPARATION_NAME = "Snapshot 187-固定IP+WindowsMCP开机自启"
RECOVERY_NAME = "Snapshot 188-Velociraptor-MCP可恢复验收基线"
INSTALLED_MARKER = "win10h2-MalBox-20241110-Snapshot100.vmsn"
DEPENDENCIES_MARKER = "Win10MalBox-Velo-Snapshot1.vmsn"
PREPARATION_MARKER = "Win10MalBox-Velo-Snapshot3.vmsn"
MANUAL_ONLY = "MANUAL_ONLY_REQUIRES_NEW_USER_AUTHORIZATION"
EVIDENCE_ROOT = Path(__file__).resolve().parents[3] / "Logs/P05/wf-01a05d1d-p05"

V1_TOP_KEYS = {
    "schema_version",
    "workflow_id",
    "epoch",
    "phase",
    "active_snapshot",
    "automatic_restore_allowlist",
    "legacy_snapshot",
    "activation_evidence",
}
V2_TOP_KEYS = {
    "schema_version",
    "workflow_id",
    "epoch",
    "phase",
    "active_snapshot",
    "automatic_restore_allowlist",
    "retired_snapshots",
    "activation_evidence",
}
V5_TOP_KEYS = {
    "schema_version",
    "workflow_id",
    "epoch",
    "phase",
    "active_snapshot",
    "automatic_restore_allowlist",
    "retired_snapshots",
    "baseline_evidence",
    "activation_evidence",
}
SNAPSHOT_KEYS = {"name", "checkpoint_marker", "purpose"}
LEGACY_KEYS = {"name", "status"}
EVIDENCE_KEYS = {"source", "evidence_path", "evidence_sha256", "activated_at"}
BASELINE_EVIDENCE_KEYS = {"source", "evidence_path", "evidence_sha256", "recorded_at"}


class StateError(ValueError):
    pass


def fail(message: str, code: int = 2) -> int:
    print(f"recovery-selector: {message}", file=sys.stderr)
    return code


def require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StateError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        raise StateError(
            f"{label} keys mismatch: missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )
    return value


def read_state(path: Path, expected_workflow: str) -> dict[str, Any]:
    if not path.is_absolute():
        raise StateError("state path must be absolute")
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise StateError(f"cannot stat state: {exc}") from exc
    if not stat.S_ISREG(mode) or path.is_symlink():
        raise StateError("state must be a regular non-symlink file")
    try:
        raw = path.read_text(encoding="utf-8")
        state = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StateError(f"cannot read valid JSON state: {exc}") from exc

    if not isinstance(state, dict):
        raise StateError("state must be an object")
    schema_version = state.get("schema_version")
    if schema_version == 1:
        state = require_exact_keys(state, V1_TOP_KEYS, "state")
    elif schema_version in (2, 3, 4):
        state = require_exact_keys(state, V2_TOP_KEYS, "state")
    elif schema_version == 5:
        state = require_exact_keys(state, V5_TOP_KEYS, "state")
    else:
        raise StateError("schema_version must equal 1, 2, 3, 4, or 5")
    active = require_exact_keys(state["active_snapshot"], SNAPSHOT_KEYS, "active_snapshot")
    activation_evidence = state["activation_evidence"]
    if schema_version != 5 or activation_evidence is not None:
        evidence = require_exact_keys(
            activation_evidence, EVIDENCE_KEYS, "activation_evidence"
        )
    else:
        evidence = None

    if expected_workflow != WORKFLOW_ID or state["workflow_id"] != expected_workflow:
        raise StateError("workflow_id mismatch")
    if type(state["epoch"]) is not int or state["epoch"] <= 0:
        raise StateError("epoch must be a positive integer")
    if state["phase"] not in {
        "BOOTSTRAP_ACTIVE",
        "INSTALLED_ACTIVE",
        "DEPENDENCIES_ACTIVE",
        "NETWORK_ACTIVE",
        "PREPARATION_BASELINE",
    }:
        raise StateError("phase is not allowed")
    allowlist = state["automatic_restore_allowlist"]
    if not isinstance(allowlist, list) or len(allowlist) != 1:
        raise StateError("automatic_restore_allowlist must contain exactly one item")
    if allowlist[0] != active["name"]:
        raise StateError("allowlist does not equal active snapshot")
    if not all(isinstance(active[key], str) and active[key] for key in SNAPSHOT_KEYS):
        raise StateError("active snapshot fields must be non-empty strings")
    marker = active["checkpoint_marker"]
    if marker != os.path.basename(marker) or not marker.endswith(".vmsn"):
        raise StateError("checkpoint marker must be a .vmsn basename")
    if evidence is not None:
        if not all(isinstance(evidence[key], str) and evidence[key] for key in EVIDENCE_KEYS):
            raise StateError("activation evidence fields must be non-empty strings")
        digest = evidence["evidence_sha256"]
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise StateError("activation evidence SHA-256 is invalid")

    if schema_version == 1:
        legacy = require_exact_keys(state["legacy_snapshot"], LEGACY_KEYS, "legacy_snapshot")
    else:
        retired = state["retired_snapshots"]
        expected_retired_count = {2: 2, 3: 3, 4: 4, 5: 4 if state["epoch"] == 5 else 5}[schema_version]
        if not isinstance(retired, list) or len(retired) != expected_retired_count:
            raise StateError(
                f"retired_snapshots must contain exactly {expected_retired_count} items"
            )
        retired = [require_exact_keys(item, LEGACY_KEYS, "retired_snapshot") for item in retired]
        retired_names = [item["name"] for item in retired]
        expected_retired_names = {
            2: [BOOTSTRAP_NAME, INSTALLED_NAME],
            3: [BOOTSTRAP_NAME, INSTALLED_NAME, DEPENDENCIES_NAME],
            4: [BOOTSTRAP_NAME, INSTALLED_NAME, DEPENDENCIES_NAME, NETWORK_NAME],
            5: (
                [BOOTSTRAP_NAME, INSTALLED_NAME, DEPENDENCIES_NAME, NETWORK_NAME]
                if state["epoch"] == 5
                else [
                    BOOTSTRAP_NAME,
                    INSTALLED_NAME,
                    DEPENDENCIES_NAME,
                    NETWORK_NAME,
                    PREPARATION_NAME,
                ]
            ),
        }[schema_version]
        if retired_names != expected_retired_names or len(set(retired_names)) != len(
            expected_retired_names
        ):
            raise StateError(
                "retired snapshots must be unique and ordered "
                + " then ".join(expected_retired_names)
            )
        if any(item["status"] != MANUAL_ONLY for item in retired):
            raise StateError("retired snapshots must be manual-only")
        if active["name"] in retired_names or allowlist[0] in retired_names:
            raise StateError("active and retired snapshots must not overlap")

    if schema_version == 1 and state["epoch"] == 1:
        expected = (
            state["phase"] == "BOOTSTRAP_ACTIVE"
            and active["name"] == BOOTSTRAP_NAME
            and marker == BOOTSTRAP_MARKER
            and legacy == {"name": "", "status": "NOT_APPLICABLE"}
        )
    elif schema_version == 1 and state["epoch"] == 2:
        expected = (
            state["phase"] == "INSTALLED_ACTIVE"
            and active["name"] == INSTALLED_NAME
            and marker == INSTALLED_MARKER
            and legacy == {"name": BOOTSTRAP_NAME, "status": MANUAL_ONLY}
        )
    elif schema_version == 2 and state["epoch"] == 3:
        expected = (
            state["phase"] == "DEPENDENCIES_ACTIVE"
            and active["name"] == DEPENDENCIES_NAME
            and marker == DEPENDENCIES_MARKER
        )
    elif schema_version == 3 and state["epoch"] == 4:
        # The 186 checkpoint marker is read back from VMware metadata when the
        # candidate is created; it must be a fresh Snapshot*.vmsn beyond the
        # 99/100/101 markers already owned by retired snapshots.
        import re as _re

        fresh_marker = _re.fullmatch(r"Win10MalBox-Velo-Snapshot(\d+)\.vmsn", marker)
        expected = (
            state["phase"] == "NETWORK_ACTIVE"
            and active["name"] == NETWORK_NAME
            and fresh_marker is not None
            and int(fresh_marker.group(1)) > 1
        )
    elif schema_version == 4 and state["epoch"] == 5:
        # Snapshot188's marker is VMware-created metadata, never a prefilled
        # expected number.  It must still be fresh beyond the retired Snapshot1
        # marker and use this VM's exact checkpoint basename convention.
        import re as _re

        fresh_marker = _re.fullmatch(r"Win10MalBox-Velo-Snapshot(\d+)\.vmsn", marker)
        expected = (
            state["phase"] == "NETWORK_ACTIVE"
            and active["name"] == RECOVERY_NAME
            and fresh_marker is not None
            and int(fresh_marker.group(1)) > 1
        )
    elif schema_version == 5:
        baseline = require_exact_keys(
            state["baseline_evidence"], BASELINE_EVIDENCE_KEYS, "baseline_evidence"
        )
        if not all(
            isinstance(baseline[key], str) and baseline[key] for key in BASELINE_EVIDENCE_KEYS
        ):
            raise StateError("baseline evidence fields must be non-empty strings")
        baseline_path = Path(baseline["evidence_path"])
        if not baseline_path.is_absolute() or baseline_path.is_symlink() or not baseline_path.is_file():
            raise StateError("baseline evidence must be an existing absolute plain file")
        if baseline["evidence_sha256"] != sha256_file(baseline_path):
            raise StateError("baseline evidence hash mismatch")
        try:
            datetime.fromisoformat(baseline["recorded_at"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise StateError("baseline evidence recorded_at is invalid") from exc
        adoption = verify_baseline_adoption(baseline_path)
        if (
            adoption["snapshot_name"] != PREPARATION_NAME
            or adoption["checkpoint_marker"] != PREPARATION_MARKER
        ):
            raise StateError("baseline evidence does not identify Snapshot187")
        import re as _re

        fresh_marker = _re.fullmatch(r"Win10MalBox-Velo-Snapshot(\d+)\.vmsn", marker)
        if state["epoch"] == 5:
            expected = (
                state["phase"] == "PREPARATION_BASELINE"
                and active["name"] == PREPARATION_NAME
                and marker == PREPARATION_MARKER
                and state["activation_evidence"] is None
            )
        elif state["epoch"] == 6:
            if evidence is None:
                raise StateError("activated schema5 state requires activation evidence")
            evidence_path = Path(evidence["evidence_path"])
            if (
                not evidence_path.is_absolute()
                or evidence_path.is_symlink()
                or not evidence_path.is_file()
                or evidence["evidence_sha256"] != sha256_file(evidence_path)
            ):
                raise StateError("activated schema5 evidence path or hash is invalid")
            verify_snapshot188_activation(evidence_path)
            expected = (
                state["phase"] == "NETWORK_ACTIVE"
                and active["name"] == RECOVERY_NAME
                and fresh_marker is not None
                and int(fresh_marker.group(1)) > 3
            )
        else:
            expected = False
    else:
        expected = False
    if not expected:
        raise StateError("epoch, phase, snapshot, marker, or legacy combination is invalid")
    return state


def revert_payload(state: dict[str, Any]) -> dict[str, Any]:
    if state.get("schema_version") != 5:
        raise StateError("historical schema cannot emit a recovery argv")
    active = state["active_snapshot"]
    return {
        "epoch": state["epoch"],
        "phase": state["phase"],
        "snapshot_name": active["name"],
        "checkpoint_marker": active["checkpoint_marker"],
        "revert_argv": [
            "/usr/bin/vmrun",
            "-T",
            "ws",
            "revertToSnapshot",
            VMX,
            active["name"],
        ],
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def verify_snapshot188_activation(evidence_path: Path) -> None:
    """Load the shared recursive bundle verifier for the schema5 5/5 -> 5/6 gate."""
    repo_root = Path(__file__).resolve().parents[3]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    try:
        from tests.p06_evidence import EvidenceError, verify_activation_bundle

        verify_activation_bundle(evidence_path, require_p05_layout=True)
    except (ImportError, OSError, ValueError) as exc:
        raise StateError(f"Snapshot188 activation bundle validation failed: {exc}") from exc


def verify_baseline_adoption(
    path: Path, expected_old_bytes: bytes | None = None
) -> dict[str, Any]:
    """Expose the relocatable, read-only adoption verifier to P05/P06 callers."""
    repo_root = Path(__file__).resolve().parents[3]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    try:
        from tests.p05_baseline_adoption import verify_baseline_adoption as verify

        return verify(path, expected_old_bytes)
    except (ImportError, OSError, ValueError) as exc:
        raise StateError(f"baseline adoption validation failed: {exc}") from exc


def next_exists(path: Path) -> bool:
    return os.path.lexists(path)


def require_governed_evidence(path: Path) -> None:
    """Constrain real CLI actions, while read-only validators stay relocatable."""
    if not path.is_absolute() or '..' in path.parts:
        raise StateError("governed evidence path must be absolute")
    try:
        path.relative_to(EVIDENCE_ROOT)
    except ValueError as exc:
        raise StateError("governed evidence is outside the fixed P05 evidence root") from exc
    for part in (path, *path.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise StateError("governed evidence traverses a link or reparse point")
    if not path.is_file():
        raise StateError("governed evidence must be a plain file")


def write_exclusive_json(path: Path, value: dict[str, Any]) -> None:
    """Create a candidate only if this invocation owns the absent .next name."""
    payload = (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise StateError("pending .next state blocks exclusive transition") from exc
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise StateError("cannot complete exclusive .next write")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_directory(path.parent)


def preparation_state(
    canonical: dict[str, Any], adoption_path: Path, canonical_bytes: bytes
) -> dict[str, Any]:
    """Derive, rather than accept, the sole schema5 preparation state."""
    adoption = verify_baseline_adoption(adoption_path, canonical_bytes)
    if adoption["vmx"] != VMX:
        raise StateError("adoption VMX does not match the governed VMX")
    recorded_at = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    return {
        "schema_version": 5,
        "workflow_id": WORKFLOW_ID,
        "epoch": 5,
        "phase": "PREPARATION_BASELINE",
        "active_snapshot": {
            "name": PREPARATION_NAME,
            "checkpoint_marker": PREPARATION_MARKER,
            "purpose": "P05 preparation only; not a product acceptance baseline",
        },
        "automatic_restore_allowlist": [PREPARATION_NAME],
        "retired_snapshots": [
            *canonical["retired_snapshots"],
            {"name": NETWORK_NAME, "status": MANUAL_ONLY},
        ],
        "baseline_evidence": {
            "source": "baseline-adoption",
            "evidence_path": str(adoption_path),
            "evidence_sha256": sha256_file(adoption_path),
            "recorded_at": recorded_at,
        },
        "activation_evidence": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--expect-workflow", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--emit-active", action="store_true")
    mode.add_argument("--validate-candidate")
    mode.add_argument("--emit-next")
    mode.add_argument("--adopt-baseline")
    parser.add_argument("--activation-evidence")
    args = parser.parse_args()

    state_path = Path(args.state)
    next_path = Path(str(state_path) + ".next")
    try:
        canonical = read_state(state_path, args.expect_workflow)
        if canonical['schema_version'] == 5:
            require_governed_evidence(Path(canonical['baseline_evidence']['evidence_path']))
            if canonical['activation_evidence'] is not None:
                require_governed_evidence(Path(canonical['activation_evidence']['evidence_path']))
        if args.adopt_baseline:
            if args.activation_evidence:
                raise StateError("--activation-evidence is only valid with --emit-next")
            if next_exists(next_path):
                raise StateError("pending .next state blocks baseline adoption")
            if (canonical["schema_version"], canonical["epoch"]) != (3, 4):
                raise StateError("baseline adoption requires the historical schema3 epoch4 predecessor")
            adoption_path = Path(args.adopt_baseline)
            require_governed_evidence(adoption_path)
            if not adoption_path.is_absolute():
                raise StateError("baseline adoption record path must be absolute")
            canonical_bytes = state_path.read_bytes()
            if json.loads(canonical_bytes) != canonical:
                raise StateError("canonical state changed while baseline adoption was being prepared")
            target = preparation_state(canonical, adoption_path, canonical_bytes)
            write_exclusive_json(next_path, target)
            written = read_state(next_path, args.expect_workflow)
            if written != target:
                raise StateError("exclusive preparation .next differs from the derived adoption state")
            if state_path.read_bytes() != canonical_bytes:
                raise StateError("canonical state drifted before baseline adoption replacement")
            os.replace(next_path, state_path)
            fsync_directory(state_path.parent)
            activated = read_state(state_path, args.expect_workflow)
            if activated != target:
                raise StateError("adopted preparation state differs from the derived state")
            print(json.dumps(revert_payload(activated), ensure_ascii=False, separators=(",", ":")))
            return 0

        if args.emit_next:
            requested_next = Path(args.emit_next)
            if not requested_next.is_absolute() or requested_next != next_path:
                raise StateError("emit-next must reference the canonical same-directory .next path")
            if (
                canonical["schema_version"] != 5
                or canonical["epoch"] != 5
                or canonical["phase"] != "PREPARATION_BASELINE"
            ):
                raise StateError(
                    "emit-next requires schema5 epoch5 PREPARATION_BASELINE; "
                    "historical schemas are read-only"
                )
            if not next_exists(next_path):
                raise StateError("emit-next requires an exclusively created same-directory .next")
            if not args.activation_evidence:
                raise StateError("emit-next requires --activation-evidence")
            evidence_path = Path(args.activation_evidence)
            require_governed_evidence(evidence_path)
            if (
                not evidence_path.is_absolute()
                or not evidence_path.is_file()
                or evidence_path.is_symlink()
            ):
                raise StateError("activation evidence must be an existing absolute file")
            candidate = read_state(requested_next, args.expect_workflow)
            if (
                candidate["schema_version"] != 5
                or candidate["epoch"] != 6
                or candidate["phase"] != "NETWORK_ACTIVE"
                or candidate["baseline_evidence"] != canonical["baseline_evidence"]
            ):
                raise StateError("next state must be schema5 epoch6 with unchanged baseline evidence")
            evidence = candidate["activation_evidence"]
            if evidence["evidence_path"] != str(evidence_path):
                raise StateError("next state evidence path mismatch")
            if evidence["evidence_sha256"] != sha256_file(evidence_path):
                raise StateError("next state evidence hash mismatch")
            # read_state(candidate) already invoked the complete activation
            # verifier.  Do not add a summary-only substitute here.
            canonical_bytes = state_path.read_bytes()
            candidate_bytes = requested_next.read_bytes()
            if json.loads(canonical_bytes) != canonical or json.loads(candidate_bytes) != candidate:
                raise StateError("canonical or candidate state changed during activation validation")
            os.replace(requested_next, state_path)
            fsync_directory(state_path.parent)
            activated = read_state(state_path, args.expect_workflow)
            if activated != candidate:
                raise StateError("activated state differs from validated candidate")
            if activated["activation_evidence"]["evidence_sha256"] != sha256_file(evidence_path):
                raise StateError("activated state evidence hash mismatch")
            print(json.dumps(revert_payload(activated), ensure_ascii=False, separators=(",", ":")))
            return 0

        if args.activation_evidence:
            raise StateError("--activation-evidence is only valid with --emit-next")
        if next_exists(next_path):
            raise StateError("pending .next state blocks normal recovery selection")
        if canonical["schema_version"] != 5:
            raise StateError("historical schemas are read-only and cannot select a recovery argv")
        if args.validate_candidate is not None:
            if args.validate_candidate != canonical["active_snapshot"]["name"]:
                return 3
            print(
                json.dumps(
                    {
                        "epoch": canonical["epoch"],
                        "phase": canonical["phase"],
                        "snapshot_name": canonical["active_snapshot"]["name"],
                        "valid": True,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )
            return 0
        print(json.dumps(revert_payload(canonical), ensure_ascii=False, separators=(",", ":")))
        return 0
    except (StateError, OSError) as exc:
        return fail(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
