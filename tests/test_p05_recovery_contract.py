from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2"
SNAPSHOT_183 = "Snapshot 183-FakenetNG测试专用"
SNAPSHOT_184 = "Snapshot 184-Velociraptor-MCP测试基线"
SNAPSHOT_1 = "Snapshot 1-开启Windows-MCP"
SNAPSHOT_186 = "Snapshot 186-Velociraptor-MCP网络部署基线"
SNAPSHOT_187 = "Snapshot 187-固定IP+WindowsMCP开机自启"
SNAPSHOT_188 = "Snapshot 188-Velociraptor-MCP可恢复验收基线"
MANUAL = "MANUAL_ONLY_REQUIRES_NEW_USER_AUTHORIZATION"


def load_selector():
    path = (
        ROOT
        / "PLAN/2026.09.02"
        / "2026.09.02-02-总纲-mcp-velociraptor-Windows-DFIR二次开发-长程执行"
        / "快照恢复选择器.py"
    )
    spec = importlib.util.spec_from_file_location("p05_recovery_selector", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def schema4_state() -> dict:
    return {
        "schema_version": 4,
        "workflow_id": WORKFLOW,
        "epoch": 5,
        "phase": "NETWORK_ACTIVE",
        "active_snapshot": {
            "name": SNAPSHOT_188,
            "checkpoint_marker": "Win10MalBox-Velo-Snapshot341.vmsn",
            "purpose": "test-only contract fixture",
        },
        "automatic_restore_allowlist": [SNAPSHOT_188],
        "retired_snapshots": [
            {"name": SNAPSHOT_183, "status": MANUAL},
            {"name": SNAPSHOT_184, "status": MANUAL},
            {"name": SNAPSHOT_1, "status": MANUAL},
            {"name": SNAPSHOT_186, "status": MANUAL},
        ],
        "activation_evidence": {
            "source": "test-only contract fixture",
            "evidence_path": "/tmp/p05-activation-evidence.json",
            "evidence_sha256": "0" * 64,
            "activated_at": "2026-09-13T00:00:00+08:00",
        },
    }


def schema3_state(evidence_path: str, evidence_sha256: str) -> dict:
    return {
        "schema_version": 3,
        "workflow_id": WORKFLOW,
        "epoch": 4,
        "phase": "NETWORK_ACTIVE",
        "active_snapshot": {
            "name": SNAPSHOT_186,
            "checkpoint_marker": "Win10MalBox-Velo-Snapshot340.vmsn",
            "purpose": "test-only predecessor fixture",
        },
        "automatic_restore_allowlist": [SNAPSHOT_186],
        "retired_snapshots": [
            {"name": SNAPSHOT_183, "status": MANUAL},
            {"name": SNAPSHOT_184, "status": MANUAL},
            {"name": SNAPSHOT_1, "status": MANUAL},
        ],
        "activation_evidence": {
            "source": "test-only predecessor fixture",
            "evidence_path": evidence_path,
            "evidence_sha256": evidence_sha256,
            "activated_at": "2026-09-12T00:00:00+08:00",
        },
    }


class RecoveryStateContractTests(unittest.TestCase):
    def test_schema4_epoch5_is_historical_read_only(self):
        selector = load_selector()
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            state_path.write_text(json.dumps(schema4_state()), encoding="utf-8")
            state = selector.read_state(state_path, WORKFLOW)
        self.assertEqual(state["active_snapshot"]["name"], SNAPSHOT_188)
        self.assertEqual(
            [item["name"] for item in state["retired_snapshots"]],
            [SNAPSHOT_183, SNAPSHOT_184, SNAPSHOT_1, SNAPSHOT_186],
        )
        with self.assertRaises(selector.StateError):
            selector.revert_payload(state)

    def test_schema4_rejects_prefilled_or_reordered_recovery_state(self):
        selector = load_selector()
        invalid = []
        marker = schema4_state()
        marker["active_snapshot"]["checkpoint_marker"] = "Win10MalBox-Velo-Snapshot1.vmsn"
        invalid.append(marker)
        retired = schema4_state()
        retired["retired_snapshots"][2], retired["retired_snapshots"][3] = (
            retired["retired_snapshots"][3],
            retired["retired_snapshots"][2],
        )
        invalid.append(retired)
        for value in invalid:
            with self.subTest(value=value):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "state.json"
                    path.write_text(json.dumps(value), encoding="utf-8")
                    with self.assertRaises(selector.StateError):
                        selector.read_state(path, WORKFLOW)

    def test_snapshot188_activation_rejects_a_passed_summary_without_originals(self):
        selector = load_selector()
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "activation-188" / "9d82d7f6-918a-4d65-9c3e-d77077b3ee9a"
            bundle.mkdir(parents=True)
            evidence = bundle / "activation-evidence.json"
            evidence.write_text(
                json.dumps(
                    {
                        "candidate": SNAPSHOT_188,
                        "checkpoint_marker": "Win10MalBox-Velo-Snapshot341.vmsn",
                        "cycles": [
                            {"report_status": "success", "restore_attempt_id": "one"},
                            {"report_status": "success", "restore_attempt_id": "two"},
                        ],
                        "workflow_id": WORKFLOW,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(selector.StateError):
                selector.verify_snapshot188_activation(evidence)

    def test_invalid_bundle_and_historical_schema_cannot_replace_schema3_canonical(self):
        selector = load_selector()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "activation-188" / "9d82d7f6-918a-4d65-9c3e-d77077b3ee9a"
            bundle.mkdir(parents=True)
            evidence = bundle / "activation-evidence.json"
            evidence.write_text("{}", encoding="utf-8")
            evidence_sha256 = hashlib.sha256(evidence.read_bytes()).hexdigest()
            state_path = root / "state.json"
            canonical = schema3_state(str(evidence), evidence_sha256)
            state_path.write_text(json.dumps(canonical), encoding="utf-8")
            candidate = schema4_state()
            candidate["activation_evidence"]["evidence_path"] = str(evidence)
            candidate["activation_evidence"]["evidence_sha256"] = evidence_sha256
            next_path = Path(f"{state_path}.next")
            next_path.write_text(json.dumps(candidate), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(selector.__file__),
                    "--state",
                    str(state_path),
                    "--expect-workflow",
                    WORKFLOW,
                    "--emit-next",
                    str(next_path),
                    "--activation-evidence",
                    str(evidence),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(json.loads(state_path.read_text(encoding="utf-8")), canonical)
            self.assertTrue(next_path.exists())


class RepairScenarioContractTests(unittest.TestCase):
    def test_repair_inputs_are_indexed_hashed_and_differ_only_by_id_snapshot(self):
        index_path = ROOT / "tests/data/p05_scenario_index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        self.assertEqual(index["schema_version"], 1)
        self.assertEqual(len(index["scenarios"]), 2)
        expected = {
            "p05-flow-triage-repair-initial": (
                "P05_REPAIR_INITIAL",
                SNAPSHOT_187,
                "representative/p05-flow-triage-repair-initial.json",
            ),
            "p05-flow-triage-repair-candidate": (
                "P05_REPAIR_CANDIDATE",
                SNAPSHOT_188,
                "representative/p05-flow-triage-repair-candidate.json",
            ),
        }
        scenarios = {}
        for row in index["scenarios"]:
            stage, snapshot, relative = expected[row["scenario_id"]]
            path = ROOT / "tests/scenarios" / relative
            self.assertEqual(row["snapshot_stage"], stage)
            self.assertEqual(row["required_snapshot"], snapshot)
            self.assertEqual(row["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            scenario = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(scenario["scenario_id"], row["scenario_id"])
            self.assertEqual(scenario["required_snapshot"], snapshot)
            scenarios[row["scenario_id"]] = scenario

        initial = copy.deepcopy(scenarios["p05-flow-triage-repair-initial"])
        candidate = copy.deepcopy(scenarios["p05-flow-triage-repair-candidate"])
        for scenario in (initial, candidate):
            del scenario["scenario_id"]
            del scenario["required_snapshot"]
        self.assertEqual(initial, candidate)

    def test_schema_allows_the_new_repair_snapshot_values(self):
        schema = json.loads(
            (ROOT / "tests/scenarios/schema-v1.json").read_text(encoding="utf-8")
        )
        snapshots = schema["properties"]["required_snapshot"]["enum"]
        self.assertNotIn(SNAPSHOT_186, snapshots)
        self.assertIn(SNAPSHOT_187, snapshots)
        self.assertIn(SNAPSHOT_188, snapshots)


if __name__ == "__main__":
    unittest.main()
