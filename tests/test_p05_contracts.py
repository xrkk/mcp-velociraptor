from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


class P05ContractTests(unittest.TestCase):
    def test_dependency_manifest_locks_expected_identities(self):
        manifest = json.loads((ROOT / "tests/data/p05_dependency_manifest.json").read_text(encoding="utf-8"))
        dependencies = {row["name"]: row for row in manifest["dependencies"]}
        self.assertEqual(
            set(dependencies), {"Autorun_386", "Autorun_amd64"}
        )
        self.assertEqual(dependencies["Autorun_amd64"]["version"], "14.3")
        for row in dependencies.values():
            self.assertRegex(row["sha256"], r"^[0-9a-f]{64}$")
            self.assertGreater(row["size"], 0)
            self.assertTrue(row["source"].startswith("https://"))

    def test_kill_process_artifact_is_exactly_bounded(self):
        path = ROOT / "tests/fixtures/artifacts/Generic.Utils.KillProcess.yaml"
        raw = path.read_text(encoding="utf-8")
        artifact = yaml.safe_load(raw)
        self.assertEqual(artifact["name"], "Generic.Utils.KillProcess")
        self.assertEqual(artifact["type"], "CLIENT")
        self.assertEqual(artifact["required_permissions"], ["EXECVE"])
        self.assertEqual(artifact["precondition"], "SELECT OS FROM info() WHERE OS = 'windows'")
        self.assertEqual(artifact["parameters"], [{"name": "Pid", "type": "int"}])
        self.assertEqual(len(artifact["sources"]), 1)
        self.assertEqual(artifact["sources"][0]["name"], "KillProcess")
        self.assertEqual(
            artifact["sources"][0]["query"].strip(),
            "SELECT Pid, pskill(pid=Pid) AS Killed FROM scope()",
        )
        self.assertNotIn("tools", artifact)
        for forbidden in ("execve(", "http_client(", "process_tracker_pslist("):
            self.assertNotIn(forbidden, raw)

    def test_fixture_spec_payload_hashes_are_independent_golden(self):
        spec = json.loads((ROOT / "tests/data/p05_fixture_spec.json").read_text(encoding="utf-8"))
        for row in spec["files"]:
            if row["encoding"] == "ascii":
                payload = row["payload"].encode("ascii")
            elif row["encoding"] == "utf-8":
                payload = row["payload"].encode("utf-8")
            else:
                payload = bytes(range(256)) * 4
            self.assertEqual(len(payload), row["size"])
            self.assertEqual(hashlib.sha256(payload).hexdigest(), row["sha256"])
        self.assertFalse(spec["task"]["enabled"])
        self.assertEqual(spec["task"]["triggers"], [])
        self.assertIn("exit 0", spec["task"]["action"])
        self.assertEqual(spec["process"]["sleep_seconds"], 86400)

    def test_representative_scenario_matches_schema_and_index(self):
        schema = json.loads((ROOT / "tests/scenarios/schema-v1.json").read_text(encoding="utf-8"))
        index = json.loads((ROOT / "tests/data/p05_scenario_index.json").read_text(encoding="utf-8"))
        spec_hash = hashlib.sha256((ROOT / "tests/data/p05_fixture_spec.json").read_bytes()).hexdigest()
        self.assertEqual({row["scenario_id"] for row in index["scenarios"]},
                         {"p05-flow-triage-repair-initial", "p05-flow-triage-repair-candidate"})
        for row in index["scenarios"]:
            with self.subTest(scenario=row["scenario_id"]):
                scenario_path = ROOT / "tests/scenarios" / row["path"]
                scenario = json.loads(scenario_path.read_text(encoding="utf-8"))
                Draft202012Validator(schema).validate(scenario)
                self.assertGreaterEqual(sum(step["kind"] == "tool" for step in scenario["steps"]), 10)
                self.assertIn("collect_forensic_triage", {step.get("tool") for step in scenario["steps"]})
                self.assertEqual(row["sha256"], hashlib.sha256(scenario_path.read_bytes()).hexdigest())
                self.assertEqual(row["fixture_spec_sha256"], spec_hash)
                self.assertEqual(scenario["scenario_id"], row["scenario_id"])
                self.assertEqual(scenario["fixture_spec_sha256"], spec_hash)

    def test_fixture_script_has_fixed_scope_and_inert_task(self):
        source = (ROOT / "tests/p05_prepare_fixtures.ps1").read_text(encoding="utf-8")
        self.assertIn("$FixtureRoot = 'C:\\VelociraptorMCP\\fixtures-p05'", source)
        self.assertNotIn("[string]$FixtureRoot", source)
        self.assertIn("Disable-ScheduledTask", source)
        self.assertIn("Get-CimInstance Win32_Process", source)
        self.assertNotIn("Invoke-WebRequest", source)
        self.assertNotIn("Start-BitsTransfer", source)


if __name__ == "__main__":
    unittest.main()
