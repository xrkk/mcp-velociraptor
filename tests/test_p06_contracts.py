from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from tests import p06_aggregate_reports as aggregate
from tests import p06_contracts
from tests import p06_resource_qualification as qualification
from tests import scenario_runner


class P06ContractTests(unittest.TestCase):
    def test_resource_qualification_prepares_only_an_absolute_download_root(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "nested" / "downloads"
            qualification.prepare_download_root(target)
            self.assertTrue(target.is_dir())
        with self.assertRaises(ValueError):
            qualification.prepare_download_root(Path("relative-downloads"))

    def test_generated_contracts_are_exact_and_cover_650_relations(self):
        self.assertEqual(
            p06_contracts.validate_contracts(),
            {"scenarios": 5, "tools": 130, "relations": 650},
        )

    def test_every_tool_has_five_distinct_scenario_roles(self):
        manifest = json.loads(p06_contracts.MANIFEST.read_text(encoding="utf-8"))
        by_tool = {}
        for row in manifest["relations"]:
            by_tool.setdefault(row["tool"], []).append(row)
        self.assertEqual(len(by_tool), 130)
        for tool, rows in by_tool.items():
            with self.subTest(tool=tool):
                self.assertEqual(len(rows), 5)
                self.assertEqual(len({row["scenario_id"] for row in rows}), 5)
                self.assertEqual(len({row["investigative_question"] for row in rows}), 5)
                self.assertEqual(len({row["expected_evidence"] for row in rows}), 5)

    def test_cross_step_validator_rejects_flow_hunt_and_file_substitution(self):
        scenario = {
            "steps": [
                {"kind": "tool", "id": "flow", "tool": "get_flow_status"},
                {"kind": "tool", "id": "hunt", "tool": "get_hunt_status"},
                {"kind": "tool", "id": "file", "tool": "download_flow_file"},
            ]
        }
        good = [
            {"step_id": "flow", "arguments": {"flow_id": "F.1"}, "structured": {"flow_id": "F.1"}},
            {"step_id": "hunt", "arguments": {"hunt_id": "H.1"}, "structured": {"hunt_id": "H.1"}},
            {
                "step_id": "file",
                "arguments": {"flow_id": "F.1", "file_id": "a" * 64},
                "structured": {"flow_id": "F.1", "file_id": "a" * 64},
            },
        ]
        self.assertEqual(len(scenario_runner.validate_cross_step_invariants(scenario, {}, good)), 4)
        for index, field in ((0, "flow_id"), (1, "hunt_id"), (2, "file_id")):
            bad = copy.deepcopy(good)
            bad[index]["structured"][field] = "wrong"
            with self.subTest(field=field), self.assertRaises(scenario_runner.ScenarioFailure):
                scenario_runner.validate_cross_step_invariants(scenario, {}, bad)


class AggregateNegativeTests(unittest.TestCase):
    def test_ledger_rejects_non_monotonic_and_duplicate_history(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.jsonl"
            path.write_text(
                "\n".join(
                    json.dumps(row)
                    for row in (
                        {
                            "monotonic_attempt": 1,
                            "report_relative_path": "a/report.json",
                            "report_sha256": "a" * 64,
                            "package_sha256": "b" * 64,
                        },
                        {
                            "monotonic_attempt": 3,
                            "report_relative_path": "b/report.json",
                            "report_sha256": "c" * 64,
                            "package_sha256": "d" * 64,
                        },
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(aggregate.AggregateError):
                aggregate.load_ledger(path)


if __name__ == "__main__":
    unittest.main()
