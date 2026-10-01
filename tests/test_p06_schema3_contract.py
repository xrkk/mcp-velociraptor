"""PLAN-CHANGE-025 schema3 contract: baseline binding replaces the 189 chain.

Local, hermetic checks for the producer gates and the strict consumer; the
five-scenario rerun itself is live evidence on the adopted .232 baseline.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

try:
    from . import p06_aggregate_reports as aggregate_module
    from . import scenario_runner as runner_module
except ImportError:
    import p06_aggregate_reports as aggregate_module
    import scenario_runner as runner_module

SCHEMA3_REPORT_KEYS = aggregate_module.SCHEMA3_REPORT_KEYS
AggregateError = aggregate_module.AggregateError
verify_baseline_binding = aggregate_module.verify_baseline_binding
verify_report_shape = aggregate_module.verify_report_shape
BASELINE_BINDING_SCHEMA = runner_module.BASELINE_BINDING_SCHEMA
ScenarioInputError = runner_module.ScenarioInputError
load_baseline_binding = runner_module.load_baseline_binding
run_scenario = runner_module.run_scenario

GOOD_BINDING = {
    "schema": BASELINE_BINDING_SCHEMA,
    "produced_at": "2026-10-01T02:00:00Z",
    "computer_name": "DESKTOP-3FI41GR",
    "vm_uuid": "55804d56-262e-33b0-9e8f-fa0bb583b865",
    "mac": "00:0C:29:83:B8:65",
    "host_only_ip": "192.168.204.232",
    "policy_sha256": "37dbfb371f8e57a01cea0bf6a730866de78bc8aa91d775c7208e355fe1f708f4",
    "deployed_tree": {
        "velociraptor_transport.py": "90bc56df1f0faa63fe0bad3ae03b2162cf195cff6f83d13c33790c426a175ac9",
        "velo_transfer/guest_service.py": "b5e2ba5f4ad2c535d4803a6e4ea243d61296e7b13ea11277508a5d498a525909",
    },
}


def _binding_file(directory: Path, **overrides) -> Path:
    document = {**GOOD_BINDING, **overrides}
    path = directory / "baseline-binding.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


class LoadBaselineBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_document_loads(self):
        document = load_baseline_binding(_binding_file(self.dir))
        self.assertEqual(document["vm_uuid"], GOOD_BINDING["vm_uuid"])

    def test_rejects_missing_file(self):
        with self.assertRaises(ScenarioInputError):
            load_baseline_binding(self.dir / "absent.json")

    def test_rejects_unknown_keys(self):
        bad = {**GOOD_BINDING, "extra": 1}
        (self.dir / "bad.json").write_text(json.dumps(bad), encoding="utf-8")
        with self.assertRaises(ScenarioInputError):
            load_baseline_binding(self.dir / "bad.json")

    def test_rejects_malformed_vm_identity(self):
        with self.assertRaises(ScenarioInputError):
            load_baseline_binding(_binding_file(self.dir, vm_uuid="not-a-uuid"))
        with self.assertRaises(ScenarioInputError):
            load_baseline_binding(_binding_file(self.dir, mac="00:00"))
        with self.assertRaises(ScenarioInputError):
            load_baseline_binding(_binding_file(self.dir, host_only_ip="example"))

    def test_rejects_bad_policy_hash(self):
        with self.assertRaises(ScenarioInputError):
            load_baseline_binding(_binding_file(self.dir, policy_sha256="zz"))

    def test_rejects_tree_path_escapes_and_non_py(self):
        with self.assertRaises(ScenarioInputError):
            load_baseline_binding(_binding_file(self.dir, deployed_tree={"../evil.py": "a" * 64}))
        with self.assertRaises(ScenarioInputError):
            load_baseline_binding(_binding_file(self.dir, deployed_tree={"payload.bin": "a" * 64}))
        with self.assertRaises(ScenarioInputError):
            load_baseline_binding(_binding_file(self.dir, deployed_tree={}))


class RunScenarioGateOrderTests(unittest.TestCase):
    """Baseline-mode input gates fire before any network or filesystem work."""

    def test_baseline_requires_http_transport(self):
        with tempfile.TemporaryDirectory() as tmp:
            binding = _binding_file(Path(tmp))
            with self.assertRaises(ScenarioInputError):
                import asyncio

                asyncio.run(run_scenario(
                    "p06-compromise-scope", transport="stdio",
                    evidence_root=Path(tmp) / "root", baseline_binding=binding,
                    fixture_instance=Path(tmp) / "fixture.json",
                ))

    def test_baseline_requires_explicit_root_and_fixture(self):
        import asyncio

        with tempfile.TemporaryDirectory() as tmp:
            dir_path = Path(tmp)
            binding = _binding_file(dir_path)
            with self.assertRaises(ScenarioInputError):
                asyncio.run(run_scenario(
                    "p06-compromise-scope", transport="streamable-http",
                    endpoint="http://192.168.204.232:28790/mcp",
                    baseline_binding=binding,
                ))
            with self.assertRaises(ScenarioInputError):
                asyncio.run(run_scenario(
                    "p06-compromise-scope", transport="streamable-http",
                    endpoint="http://192.168.204.232:28790/mcp",
                    evidence_root=dir_path / "root", baseline_binding=binding,
                ))


def _schema3_report() -> dict:
    report = {key: None for key in SCHEMA3_REPORT_KEYS}
    report.update({
        "schema_version": 3,
        "transport": "streamable-http",
        "endpoint": "http://192.168.204.232:28790/mcp",
        "authorization_configured": True,
        "mcp_session": {"id": "s", "initialized_at": "a", "closed_at": "b"},
        "server_identity": {
            "computer_name": "DESKTOP-3FI41GR", "service_name": "mcp-velociraptor",
            "pid": 1, "process_start_time_utc": "t", "instance_id": "i",
            "executable_sha256": "e",
        },
        "runner": {"pid": 2, "process_start_time_utc": "t", "executable_sha256": "e"},
        "server_observation_sha256": "o",
        "baseline_binding": {**GOOD_BINDING, "observation_sha256": "b" * 64},
    })
    return report


class VerifyReportShapeSchema3Tests(unittest.TestCase):
    def test_well_formed_schema3_passes(self):
        verify_report_shape(_schema3_report())

    def test_schema3_must_not_carry_snapshot_key(self):
        report = _schema3_report()
        report["snapshot_evidence_sha256"] = None
        with self.assertRaises(AggregateError):
            verify_report_shape(report)

    def test_binding_computer_name_must_match_server(self):
        report = _schema3_report()
        report["baseline_binding"] = {**GOOD_BINDING, "observation_sha256": "b" * 64,
                                      "computer_name": "OTHER-HOST"}
        with self.assertRaises(AggregateError):
            verify_report_shape(report)

    def test_binding_shape_rejects_missing_observation_hash(self):
        report = _schema3_report()
        report["baseline_binding"] = dict(GOOD_BINDING)
        with self.assertRaises(AggregateError):
            verify_report_shape(report)

    def test_binding_tree_entries_validated(self):
        report = _schema3_report()
        report["baseline_binding"] = {
            **GOOD_BINDING, "observation_sha256": "b" * 64,
            "deployed_tree": {"../escape.py": "a" * 64},
        }
        with self.assertRaises(AggregateError):
            verify_report_shape(report)

    def test_version_four_is_rejected(self):
        report = _schema3_report()
        report["schema_version"] = 4
        with self.assertRaises(AggregateError):
            verify_report_shape(report)

    def test_verify_baseline_binding_direct(self):
        report = _schema3_report()
        verify_baseline_binding(report)


if __name__ == "__main__":
    unittest.main()
