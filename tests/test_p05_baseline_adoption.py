from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tests" / "p05_baseline_adoption.py"
SELECTOR_PATH = (
    ROOT
    / "PLAN/2026.09.02"
    / "2026.09.02-02-总纲-mcp-velociraptor-Windows-DFIR二次开发-长程执行"
    / "快照恢复选择器.py"
)


def load_module():
    spec = importlib.util.spec_from_file_location("p05_baseline_adoption", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_selector():
    spec = importlib.util.spec_from_file_location("p05_recovery_selector", SELECTOR_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BaselineAdoptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.adoption_id = str(uuid.uuid4())
        self.bundle = self.root / "baseline-adoption" / self.adoption_id
        self.bundle.mkdir(parents=True)
        self.adoption_path = self.bundle / "adoption.json"
        self.old_bytes = json.dumps(self.old_state(), ensure_ascii=False).encode("utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def old_state(self) -> dict:
        return {
            "schema_version": 3,
            "workflow_id": self.module.WORKFLOW_ID,
            "epoch": 4,
            "phase": "NETWORK_ACTIVE",
            "active_snapshot": {
                "name": self.module.SNAPSHOT_186,
                "checkpoint_marker": "Win10MalBox-Velo-Snapshot340.vmsn",
                "purpose": "historical-only fixture",
            },
            "automatic_restore_allowlist": [self.module.SNAPSHOT_186],
            "retired_snapshots": [
                {"name": self.module.SNAPSHOT_183, "status": self.module.MANUAL_ONLY},
                {"name": self.module.SNAPSHOT_184, "status": self.module.MANUAL_ONLY},
                {"name": self.module.SNAPSHOT_1, "status": self.module.MANUAL_ONLY},
            ],
            "activation_evidence": {
                "source": "historical fixture",
                "evidence_path": "/historical/activation.json",
                "evidence_sha256": "0" * 64,
                "activated_at": "2026-09-12T00:00:00Z",
            },
        }

    def write_ref(self, relative: str, payload: bytes) -> dict:
        path = self.bundle / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return {
            "path": relative,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    def source_inputs(self) -> list[dict]:
        result = []
        for repo_path in sorted(self.module.ADOPTION_SOURCE_INPUTS):
            payload = f"fixture source {repo_path}\n".encode("utf-8")
            result.append(
                {
                    "repo_path": repo_path,
                    "blob": hashlib.sha1(
                        f"blob {len(payload)}\0".encode("ascii") + payload
                    ).hexdigest(),
                    "content": self.write_ref(f"source/{repo_path}", payload),
                }
            )
        return result

    def original(self, observation: str, stdout: str, vmx: str, ordinal: int) -> dict:
        argv = {
            'snapshot_tree': ['/usr/bin/vmrun', '-T', 'ws', 'listSnapshots', vmx, 'showTree'],
            'metadata': ['/usr/bin/cat', vmx[:-4] + '.vmsd'],
            'guest_identity': ['powershell.exe', '-NoProfile', '-Command',
                               'Get-CimInstance Win32_NetworkAdapterConfiguration'],
        }[observation]
        response = {}
        for name, text in [('stdout', stdout), ('stderr', '')]:
            payload = text.encode('utf-8')
            response[name] = text
            response[name + '_size'] = len(payload)
            response[name + '_sha256'] = hashlib.sha256(payload).hexdigest()
        value = {
            'schema_version': 1, 'kind': 'p05-snapshot-command-v1',
            'workflow_id': self.module.WORKFLOW_ID, 'operation_id': self.adoption_id,
            'observation': observation, 'vmx': vmx,
            'request': {'argv': argv, 'command_line': ' '.join(argv)},
            'started_at': f'2026-09-14T00:00:0{ordinal * 2}Z',
            'ended_at': f'2026-09-14T00:00:0{ordinal * 2 + 1}Z',
            'exit_status': {'code': 0}, 'response': response,
        }
        return self.write_ref('raw/' + observation + '.json', json.dumps(value).encode())

    def adoption(self, vmx='/fixture/Win10MalBox-Velo.vmx') -> dict:
        return {
            "schema_version": 1,
            "kind": "user187-preparation-adoption-v1",
            "workflow_id": self.module.WORKFLOW_ID,
            "adoption_id": self.adoption_id,
            "vmx": vmx,
            "snapshot_name": self.module.SNAPSHOT_187,
            "checkpoint_marker": self.module.SNAPSHOT_187_MARKER,
            "old_canonical": self.write_ref("old-canonical.json", self.old_bytes),
            "snapshot_tree": self.original(
                'snapshot_tree', 'Total snapshots: 1\n' + self.module.SNAPSHOT_187 + '\n', vmx, 0,
            ),
            "metadata": self.original(
                'metadata', '\n'.join([
                    'snapshot.numSnapshots = "1"', 'snapshot.current = "3"',
                    'snapshot0.uid = "3"',
                    'snapshot0.displayName = "' + self.module.SNAPSHOT_187 + '"',
                    'snapshot0.filename = "Win10MalBox-Velo-Snapshot3.vmsn"',
                ]), vmx, 1,
            ),
            "guest_identity": self.original(
                'guest_identity', json.dumps({'computer_name': 'DESKTOP-3FI41GR', 'adapters': [{
                    'MACAddress': '00:0c:29:83:b8:65', 'IPAddress': ['192.168.204.232'],
                    'DHCPEnabled': False, 'IPEnabled': True,
                }]}), vmx, 2,
            ),
            "source_inputs": self.source_inputs(),
        }

    def write_adoption(self, value: dict) -> None:
        self.adoption_path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    def test_accepts_complete_self_contained_record_and_expected_old_bytes(self) -> None:
        value = self.adoption()
        self.write_adoption(value)
        result = self.module.verify_baseline_adoption(self.adoption_path, self.old_bytes)
        self.assertEqual(result["adoption_id"], self.adoption_id)

    def test_rejects_old_byte_drift_and_unknown_source(self) -> None:
        value = self.adoption()
        self.write_adoption(value)
        with self.assertRaises(self.module.BaselineAdoptionError):
            self.module.verify_baseline_adoption(self.adoption_path, b"different")

        invalid = copy.deepcopy(value)
        invalid["source_inputs"][0]["repo_path"] = "README.md"
        self.write_adoption(invalid)
        with self.assertRaises(self.module.BaselineAdoptionError):
            self.module.verify_baseline_adoption(self.adoption_path, self.old_bytes)

    def test_rejects_reference_escape_and_source_byte_mutation(self) -> None:
        value = self.adoption()
        value["metadata"]["path"] = "../escape.txt"
        self.write_adoption(value)
        with self.assertRaises(self.module.BaselineAdoptionError):
            self.module.verify_baseline_adoption(self.adoption_path, self.old_bytes)

        value = self.adoption()
        source_ref = value["source_inputs"][0]["content"]
        (self.bundle / source_ref["path"]).write_text("mutated", encoding="utf-8")
        self.write_adoption(value)
        with self.assertRaises(self.module.BaselineAdoptionError):
            self.module.verify_baseline_adoption(self.adoption_path, self.old_bytes)

    def test_schema5_preparation_is_derived_and_activation_remains_fail_closed(self) -> None:
        selector = load_selector()
        adoption = self.adoption(vmx=selector.VMX)
        self.write_adoption(adoption)
        state_path = self.root / "state.json"
        state_path.write_bytes(self.old_bytes)
        historical = selector.read_state(state_path, self.module.WORKFLOW_ID)
        preparation = selector.preparation_state(historical, self.adoption_path, self.old_bytes)
        state_path.write_text(json.dumps(preparation), encoding="utf-8")
        checked = selector.read_state(state_path, self.module.WORKFLOW_ID)
        self.assertEqual(checked["epoch"], 5)
        self.assertEqual(checked["phase"], "PREPARATION_BASELINE")
        self.assertEqual(selector.revert_payload(checked)["snapshot_name"], self.module.SNAPSHOT_187)

        activation_root = self.root / "activation-188" / str(uuid.uuid4())
        activation_root.mkdir(parents=True)
        activation_path = activation_root / "activation-evidence.json"
        activation_path.write_text("{}", encoding="utf-8")
        activated = copy.deepcopy(preparation)
        activated["epoch"] = 6
        activated["phase"] = "NETWORK_ACTIVE"
        activated["active_snapshot"] = {
            "name": selector.RECOVERY_NAME,
            "checkpoint_marker": "Win10MalBox-Velo-Snapshot4.vmsn",
            "purpose": "candidate fixture",
        }
        activated["automatic_restore_allowlist"] = [selector.RECOVERY_NAME]
        activated["retired_snapshots"].append(
            {"name": selector.PREPARATION_NAME, "status": selector.MANUAL_ONLY}
        )
        activated["activation_evidence"] = {
            "source": "fixture",
            "evidence_path": str(activation_path),
            "evidence_sha256": hashlib.sha256(activation_path.read_bytes()).hexdigest(),
            "activated_at": "2026-09-14T00:00:00Z",
        }
        state_path.write_text(json.dumps(activated), encoding="utf-8")
        with self.assertRaises(selector.StateError):
            selector.read_state(state_path, self.module.WORKFLOW_ID)

    def test_rejects_unstructured_claims_and_failed_actual_command(self):
        value = self.adoption()
        value['guest_identity'] = self.write_ref('raw/claims.txt',
            b'00:0c:29:83:b8:65 192.168.204.232 DHCP=false')
        self.write_adoption(value)
        with self.assertRaises(self.module.BaselineAdoptionError):
            self.module.verify_baseline_adoption(self.adoption_path)
        value = self.adoption()
        reference = value['snapshot_tree']
        command = json.loads((self.bundle / reference['path']).read_bytes())
        command['exit_status']['code'] = 1
        value['snapshot_tree'] = self.write_ref(reference['path'], json.dumps(command).encode())
        self.write_adoption(value)
        with self.assertRaises(self.module.BaselineAdoptionError):
            self.module.verify_baseline_adoption(self.adoption_path)


if __name__ == "__main__":
    unittest.main()
