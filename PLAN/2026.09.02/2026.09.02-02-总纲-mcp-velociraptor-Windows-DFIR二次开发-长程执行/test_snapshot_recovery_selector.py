from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, call, Mock


ROOT = Path(__file__).resolve().parent
SELECTOR = ROOT / "快照恢复选择器.py"
WORKFLOW = "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2"
MANUAL = "MANUAL_ONLY_REQUIRES_NEW_USER_AUTHORIZATION"
SNAPSHOT_183 = "Snapshot 183-FakenetNG测试专用"
SNAPSHOT_184 = "Snapshot 184-Velociraptor-MCP测试基线"
SNAPSHOT_185 = "Snapshot 1-开启Windows-MCP"


def load_selector():
    spec = importlib.util.spec_from_file_location("snapshot_recovery_selector", SELECTOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def evidence(path: Path) -> tuple[str, str]:
    path.write_bytes(b"p05-selector-evidence\n")
    return str(path), hashlib.sha256(path.read_bytes()).hexdigest()


def state_v1(epoch: int) -> dict:
    if epoch == 1:
        phase = "BOOTSTRAP_ACTIVE"
        name = SNAPSHOT_183
        marker = "win10h2-MalBox-20241110-Snapshot99.vmsn"
        legacy = {"name": "", "status": "NOT_APPLICABLE"}
    else:
        phase = "INSTALLED_ACTIVE"
        name = SNAPSHOT_184
        marker = "win10h2-MalBox-20241110-Snapshot100.vmsn"
        legacy = {"name": SNAPSHOT_183, "status": MANUAL}
    return {
        "schema_version": 1,
        "workflow_id": WORKFLOW,
        "epoch": epoch,
        "phase": phase,
        "active_snapshot": {
            "name": name,
            "checkpoint_marker": marker,
            "purpose": "test",
        },
        "automatic_restore_allowlist": [name],
        "legacy_snapshot": legacy,
        "activation_evidence": {
            "source": "test",
            "evidence_path": "/tmp/test-evidence",
            "evidence_sha256": "0" * 64,
            "activated_at": "2026-09-05T00:00:00+08:00",
        },
    }


def state_v2(evidence_path: str, evidence_hash: str) -> dict:
    return {
        "schema_version": 2,
        "workflow_id": WORKFLOW,
        "epoch": 3,
        "phase": "DEPENDENCIES_ACTIVE",
        "active_snapshot": {
            "name": SNAPSHOT_185,
            "checkpoint_marker": "Win10MalBox-Velo-Snapshot1.vmsn",
            "purpose": "test",
        },
        "automatic_restore_allowlist": [SNAPSHOT_185],
        "retired_snapshots": [
            {"name": SNAPSHOT_183, "status": MANUAL},
            {"name": SNAPSHOT_184, "status": MANUAL},
        ],
        "activation_evidence": {
            "source": "test",
            "evidence_path": evidence_path,
            "evidence_sha256": evidence_hash,
            "activated_at": "2026-09-05T08:05:00+08:00",
        },
    }


def state_v3(evidence_path: str, evidence_hash: str) -> dict:
    return {
        "schema_version": 3,
        "workflow_id": WORKFLOW,
        "epoch": 4,
        "phase": "NETWORK_ACTIVE",
        "active_snapshot": {
            "name": "Snapshot 186-Velociraptor-MCP网络部署基线",
            "checkpoint_marker": "Win10MalBox-Velo-Snapshot2.vmsn",
            "purpose": "test",
        },
        "automatic_restore_allowlist": ["Snapshot 186-Velociraptor-MCP网络部署基线"],
        "retired_snapshots": [
            {"name": SNAPSHOT_183, "status": MANUAL},
            {"name": SNAPSHOT_184, "status": MANUAL},
            {"name": SNAPSHOT_185, "status": MANUAL},
        ],
        "activation_evidence": {
            "source": "test",
            "evidence_path": evidence_path,
            "evidence_sha256": evidence_hash,
            "activated_at": "2026-09-06T08:05:00+08:00",
        },
    }


class RecoverySelectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "state.json"
        self.evidence_path, self.evidence_hash = evidence(self.root / "evidence.json")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, value: dict, path: Path | None = None) -> Path:
        target = path or self.state
        target.write_text(json.dumps(value), encoding="utf-8")
        return target

    def run_selector(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SELECTOR),
                "--state",
                str(self.state),
                "--expect-workflow",
                WORKFLOW,
                *args,
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_historical_states_are_readable_but_cannot_emit_recovery_argv(self) -> None:
        selector = load_selector()
        for value, expected in (
            (state_v1(1), SNAPSHOT_183),
            (state_v1(2), SNAPSHOT_184),
            (state_v2(self.evidence_path, self.evidence_hash), SNAPSHOT_185),
        ):
            with self.subTest(expected=expected):
                self.write(value)
                self.assertEqual(
                    selector.read_state(self.state, WORKFLOW)["active_snapshot"]["name"], expected
                )
                result = self.run_selector("--emit-active")
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")

    def test_invalid_state_matrix(self) -> None:
        base_v1 = state_v1(2)
        base_v2 = state_v2(self.evidence_path, self.evidence_hash)
        cases: list[dict] = []
        item = copy.deepcopy(base_v1); item["unknown"] = True; cases.append(item)
        item = copy.deepcopy(base_v1); del item["phase"]; cases.append(item)
        item = copy.deepcopy(base_v1); item["epoch"] = 4; cases.append(item)
        item = copy.deepcopy(base_v1); item["active_snapshot"]["checkpoint_marker"] = "wrong.vmsn"; cases.append(item)
        item = copy.deepcopy(base_v1); item["automatic_restore_allowlist"].append(SNAPSHOT_183); cases.append(item)
        item = copy.deepcopy(base_v2); item["retired_snapshots"].reverse(); cases.append(item)
        item = copy.deepcopy(base_v2); item["retired_snapshots"][0]["status"] = "ACTIVE"; cases.append(item)
        item = copy.deepcopy(base_v2); item["active_snapshot"]["checkpoint_marker"] = "other.vmsn"; cases.append(item)
        for index, value in enumerate(cases):
            with self.subTest(index=index):
                self.write(value)
                result = self.run_selector("--emit-active")
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")

    def test_pending_next_blocks_normal_selection(self) -> None:
        self.write(state_v1(2))
        self.write(state_v2(self.evidence_path, self.evidence_hash), Path(str(self.state) + ".next"))
        result = self.run_selector("--emit-active")
        self.assertEqual(result.returncode, 2)
        self.assertIn("pending .next", result.stderr)

    def test_historical_emit_next_cannot_activate_a_new_state(self) -> None:
        original = json.dumps(state_v1(2)).encode()
        self.state.write_bytes(original)
        next_path = self.write(
            state_v2(self.evidence_path, self.evidence_hash),
            Path(str(self.state) + ".next"),
        )
        result = self.run_selector(
            "--emit-next",
            str(next_path),
            "--activation-evidence",
            self.evidence_path,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.state.read_bytes(), original)
        self.assertTrue(next_path.exists())

    def test_bad_evidence_does_not_replace_canonical(self) -> None:
        original = json.dumps(state_v1(2)).encode()
        self.state.write_bytes(original)
        candidate = state_v2(self.evidence_path, "f" * 64)
        next_path = self.write(candidate, Path(str(self.state) + ".next"))
        result = self.run_selector(
            "--emit-next",
            str(next_path),
            "--activation-evidence",
            self.evidence_path,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.state.read_bytes(), original)
        self.assertTrue(next_path.exists())

    def test_owned_invalid_next_can_be_quarantined_without_state_loss(self) -> None:
        original = json.dumps(state_v1(2)).encode()
        self.state.write_bytes(original)
        candidate = state_v2(self.evidence_path, self.evidence_hash)
        candidate["active_snapshot"]["checkpoint_marker"] = "invalid.vmsn"
        next_path = self.write(candidate, Path(str(self.state) + ".next"))
        result = self.run_selector(
            "--emit-next",
            str(next_path),
            "--activation-evidence",
            self.evidence_path,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.state.read_bytes(), original)
        digest = hashlib.sha256(next_path.read_bytes()).hexdigest()
        quarantine = self.root / f"state.p05-test-{digest[:12]}.invalid-next.json"
        os.replace(next_path, quarantine)
        # This Windows fixture proves rename/byte preservation, not POSIX
        # directory durability. Actual host transitions still require fsync.
        self.assertTrue(quarantine.is_file())
        self.assertEqual(hashlib.sha256(quarantine.read_bytes()).hexdigest(), digest)
        selector = load_selector()
        self.assertEqual(selector.read_state(self.state, WORKFLOW)["epoch"], 2)

    def test_host_directory_fsync_syscall_contract_and_failure_propagation(self):
        selector = load_selector()
        calls = Mock()
        with (patch.object(selector.os, 'open', return_value=37) as opened,
              patch.object(selector.os, 'fsync') as synced,
              patch.object(selector.os, 'close') as closed):
            calls.attach_mock(opened, 'open')
            calls.attach_mock(synced, 'fsync')
            calls.attach_mock(closed, 'close')
            selector.fsync_directory(self.root)
            self.assertEqual(calls.mock_calls, [call.open(self.root, os.O_RDONLY),
                                               call.fsync(37), call.close(37)])
            synced.side_effect = OSError('synthetic fsync failure')
            with self.assertRaises(OSError):
                selector.fsync_directory(self.root)
            self.assertEqual(closed.call_count, 2)

    def test_schema3_epoch4_state_is_historical_only(self) -> None:
        self.write(state_v3(self.evidence_path, self.evidence_hash))
        selector = load_selector()
        self.assertEqual(selector.read_state(self.state, WORKFLOW)["epoch"], 4)
        result = self.run_selector("--emit-active")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")

    def test_schema3_rejects_stale_marker_and_missing_185_retired(self) -> None:
        stale = state_v3(self.evidence_path, self.evidence_hash)
        stale["active_snapshot"]["checkpoint_marker"] = (
            "Win10MalBox-Velo-Snapshot1.vmsn"
        )
        self.write(stale)
        self.assertEqual(self.run_selector("--emit-active").returncode, 2)

        missing = state_v3(self.evidence_path, self.evidence_hash)
        missing["retired_snapshots"] = missing["retired_snapshots"][:2]
        self.state.write_text(json.dumps(missing), encoding="utf-8")
        self.assertEqual(self.run_selector("--emit-active").returncode, 2)

    def test_emit_next_rejects_schema2_epoch3_to_schema3_epoch4(self) -> None:
        original = json.dumps(state_v2(self.evidence_path, self.evidence_hash)).encode()
        self.state.write_bytes(original)
        next_path = self.write(
            state_v3(self.evidence_path, self.evidence_hash),
            Path(str(self.state) + ".next"),
        )
        result = self.run_selector(
            "--emit-next",
            str(next_path),
            "--activation-evidence",
            self.evidence_path,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.state.read_bytes(), original)
        self.assertTrue(next_path.exists())

    def test_emit_next_rejects_schema3_canonical_or_wrong_next_shape(self) -> None:
        self.write(state_v3(self.evidence_path, self.evidence_hash))
        next_path = self.write(
            state_v3(self.evidence_path, self.evidence_hash),
            Path(str(self.state) + ".next"),
        )
        result = self.run_selector(
            "--emit-next",
            str(next_path),
            "--activation-evidence",
            self.evidence_path,
        )
        self.assertEqual(result.returncode, 2)
        self.assertTrue(next_path.exists())

        self.write(state_v2(self.evidence_path, self.evidence_hash))
        same_shape = self.write(
            state_v2(self.evidence_path, self.evidence_hash),
            Path(str(self.state) + ".next"),
        )
        result = self.run_selector(
            "--emit-next",
            str(same_shape),
            "--activation-evidence",
            self.evidence_path,
        )
        self.assertEqual(result.returncode, 2)
        self.assertTrue(same_shape.exists())

    def test_symlink_state_is_rejected(self) -> None:
        real = self.write(state_v1(2), self.root / "real.json")
        self.state.symlink_to(real)
        self.assertEqual(self.run_selector("--emit-active").returncode, 2)


if __name__ == "__main__":
    unittest.main()
