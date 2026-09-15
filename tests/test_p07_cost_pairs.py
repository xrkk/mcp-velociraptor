"""Host regressions for the five upstream/current cost pairs (ACC-024 v3)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tests import p07_cost_measurement as cost

# These regressions bind the host-side acceptance artifacts (the r3 evidence
# root, the five cost-pair captures and the emitted report). On a Windows
# guest those originals do not exist by design; the module scope is the host.
HOST_ARTIFACTS = (cost.P06_ROOT / "final-selection.json").is_file() and (
    cost.REPO_ROOT / "Logs" / "P07" / "cost-measurement.json"
).is_file()


@unittest.skipUnless(HOST_ARTIFACTS, "host acceptance artifacts (r3 + cost pairs) are required")
class CostPairTests(unittest.TestCase):
    def test_final_selection_resolves_five_distinct_runs(self) -> None:
        runs = cost.final_selection_runs()
        self.assertEqual(set(runs), set(cost.SCENARIOS))
        self.assertEqual(len(set(runs.values())), 5)

    def test_pairs_are_complete_semantically_comparable_and_direction_free(self) -> None:
        upstream = cost.upstream_group_rows()
        current = cost.current_task_chain_rows()
        pairs = cost.cost_pair_rows(upstream, current)
        self.assertEqual(len(pairs), 5)
        for pair in pairs:
            self.assertEqual(pair["upstream"]["results_rows"], pair["current"]["results_rows"])
            self.assertEqual(pair["upstream"]["file_rows"], pair["current"]["file_rows"])
            self.assertIn("stdio", pair["upstream"]["transport"])
            self.assertIn("transport", pair["transport_disclosure"].lower())

    def test_report_carries_five_pairs_and_schema_faces(self) -> None:
        report = json.loads(cost.OUTPUT.read_text(encoding="utf-8"))
        face = report["tool_face"]
        self.assertEqual(face["upstream_78"]["tool_count"], 78)
        self.assertEqual(face["current_130"]["tool_count"], 130)
        pairs = report["fixed_investigation_task_costs"]["five_cost_pairs"]["pairs"]
        self.assertEqual(len(pairs), 5)
        self.assertEqual({p["scenario"] for p in pairs}, set(cost.SCENARIOS))

    def test_upstream_probe_scripts_are_content_addressed_on_host(self) -> None:
        for name in ("upstream78-launcher.py", "upstream78-task-probe.py"):
            path = cost.REPO_ROOT / "Logs" / "P07" / name
            self.assertTrue(path.is_file(), name)
            if "launcher" in name:
                self.assertIn("MCPServer", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
