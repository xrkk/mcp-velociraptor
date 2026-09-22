"""Stage-rule binding tests for the unified PC021/PC022 stage table."""

from __future__ import annotations

import copy
import json
import os
import unittest
from pathlib import Path

from tests import p05_pc021_stage_rules as rules


REPO = Path(__file__).resolve().parents[1]


class StageRuleTableTests(unittest.TestCase):
    def test_rule_table_matches_the_normative_stage_matrix(self) -> None:
        self.assertEqual(
            rules.STAGE_RULES["P05_REPAIR_INITIAL"]["restored_snapshot"],
            rules.SNAPSHOT_187,
        )
        self.assertEqual(
            rules.STAGE_RULES["P05_REPAIR_CANDIDATE"]["restored_snapshot"],
            rules.SNAPSHOT_189,
        )
        self.assertEqual(
            rules.STAGE_RULES["P06_ACTIVE"]["restored_snapshot"],
            rules.SNAPSHOT_189,
        )
        candidate = rules.STAGE_RULES["P05_REPAIR_CANDIDATE"]["canonical"]
        self.assertEqual(
            (candidate["schema_version"], candidate["epoch"], candidate["phase"], candidate["active_snapshot"]),
            (6, 7, "PREPARATION_BASELINE", rules.SNAPSHOT_187),
        )
        active = rules.STAGE_RULES["P06_ACTIVE"]["canonical"]
        self.assertEqual(
            (active["schema_version"], active["epoch"], active["phase"], active["active_snapshot"]),
            (6, 8, "NETWORK_ACTIVE", rules.SNAPSHOT_189),
        )
        self.assertNotIn("activation_evidence", rules.STAGE_RULES["P05_REPAIR_INITIAL"]["record_kinds"])
        self.assertNotIn("activation_evidence", rules.STAGE_RULES["P05_REPAIR_CANDIDATE"]["record_kinds"])
        self.assertIn("activation_evidence", rules.STAGE_RULES["P06_ACTIVE"]["record_kinds"])
        self.assertNotIn("baseline_adoption", rules.STAGE_RULES["P06_ACTIVE"]["record_kinds"])
        for stage, rule in rules.STAGE_RULES.items():
            self.assertEqual(len(rule["record_kinds"]), 8 if stage == "P06_ACTIVE" else 7)


class IndexBindingTests(unittest.TestCase):
    def test_current_repo_index_binds(self) -> None:
        rows = rules.verify_index_binding(REPO / "tests/data/p05_scenario_index.json", repo_root=REPO)
        self.assertEqual(
            {row["snapshot_stage"] for row in rows},
            {"P05_REPAIR_INITIAL", "P05_REPAIR_CANDIDATE"},
        )

    def test_index_mutations_refuse(self) -> None:
        original = json.loads((REPO / "tests/data/p05_scenario_index.json").read_bytes())

        def check(mutate, pattern):
            value = copy.deepcopy(original)
            mutate(value)
            path = REPO / "tests/data/.g09-mutated-index.json"
            path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
            try:
                with self.assertRaisesRegex(rules.StageRuleError, pattern):
                    rules.verify_index_binding(path, repo_root=REPO)
            finally:
                path.unlink()

        def cross_use(value):
            row = next(r for r in value["scenarios"] if r["snapshot_stage"] == "P05_REPAIR_CANDIDATE")
            row["required_snapshot"] = rules.SNAPSHOT_187

        def wrong_sha(value):
            value["scenarios"][0]["sha256"] = "0" * 64

        def escape(value):
            value["scenarios"][0]["path"] = "../data/p05_scenario_index.json"

        def foreign_fixture(value):
            value["scenarios"][0]["fixture_spec_sha256"] = "1" * 64

        check(cross_use, "not approved")
        check(wrong_sha, "does not bind the scenario bytes")
        check(escape, "escapes the scenario root")
        check(foreign_fixture, "restate its index binding|one frozen fixture spec digest")


class RestoreBindingTests(unittest.TestCase):
    def _declaration(self) -> dict:
        kinds = sorted(rules.SEVEN_KINDS)
        return {
            "workflow_id": "wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2",
            "run_id": "run-1", "restore_attempt_id": "attempt-1",
            "snapshot_stage": "P05_REPAIR_CANDIDATE",
            "snapshot_name": rules.SNAPSHOT_189,
            "checkpoint_marker": "Win10MalBox-Velo-Snapshot27.vmsn",
            "canonical_schema_version": 6, "canonical_epoch": 7,
            "canonical_phase": "PREPARATION_BASELINE",
            "canonical_sha256": "a" * 64,
            "restore_records": [
                {"kind": kind, "path": f"restore/{kind}.json", "sha256": "b" * 64}
                for kind in kinds
            ],
        }

    def test_candidate_declaration_binds(self) -> None:
        result = rules.verify_restore_stage_binding(self._declaration())
        self.assertEqual(result["stage"], "P05_REPAIR_CANDIDATE")

    def test_stage_mutations_refuse(self) -> None:
        cases = {
            "wrong snapshot": lambda d: d.update(snapshot_name=rules.SNAPSHOT_187),
            "jumped canonical": lambda d: d.update(canonical_epoch=8, canonical_phase="NETWORK_ACTIVE"),
            "old generation": lambda d: d.update(canonical_schema_version=5, canonical_epoch=6),
            "missing kind": lambda d: d["restore_records"].pop(),
            "extra kind": lambda d: d["restore_records"].append(
                {"kind": "activation_evidence", "path": "restore/activation.json", "sha256": "c" * 64}
            ),
            "legacy kind": lambda d: d["restore_records"].__setitem__(
                0, {"kind": "baseline_adoption", "path": "restore/x.json", "sha256": "c" * 64}
            ),
            "duplicate kind": lambda d: d["restore_records"].append(
                dict(d["restore_records"][0])
            ),
            "dotdot path": lambda d: d["restore_records"][0].update(path="../escape.json"),
            "backslash path": lambda d: d["restore_records"][0].update(path="restore\\x.json"),
            "p06 needs activation": lambda d: d.update(
                snapshot_stage="P06_ACTIVE", snapshot_name=rules.SNAPSHOT_189,
            ),
            "unknown stage": lambda d: d.update(snapshot_stage="P05_UNKNOWN"),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                declaration = self._declaration()
                mutate(declaration)
                with self.assertRaises(rules.StageRuleError):
                    rules.verify_restore_stage_binding(declaration)

    def test_p06_active_requires_eight_kinds(self) -> None:
        declaration = self._declaration()
        declaration.update(
            snapshot_stage="P06_ACTIVE", snapshot_name=rules.SNAPSHOT_189,
            canonical_epoch=8, canonical_phase="NETWORK_ACTIVE",
        )
        with self.assertRaisesRegex(rules.StageRuleError, "record kind set differs"):
            rules.verify_restore_stage_binding(declaration)
        declaration["restore_records"].append(
            {"kind": "activation_evidence", "path": "restore/activation-evidence.json", "sha256": "c" * 64}
        )
        result = rules.verify_restore_stage_binding(declaration)
        self.assertIn("activation_evidence", result["kinds"])


class RunnerReportBindingTests(unittest.TestCase):
    def test_report_bindings(self) -> None:
        index = json.loads((REPO / "tests/data/p05_scenario_index.json").read_bytes())
        row = index["scenarios"][0]
        report = {
            "schema_version": 2, "scenario": row["scenario_id"],
            "source_sha256": row["sha256"],
            "fixture_spec_sha256": row["fixture_spec_sha256"],
            "transport": "streamable-http", "status": "success",
            "failure": None, "unexecuted_step_ids": [],
        }
        rules.verify_runner_report_binding(report, row)
        for name, mutate in {
            "wrong scenario": lambda r: r.update(scenario="other"),
            "wrong source": lambda r: r.update(source_sha256="0" * 64),
            "wrong fixture": lambda r: r.update(fixture_spec_sha256="0" * 64),
            "stdio": lambda r: r.update(transport="stdio"),
            "failure": lambda r: r.update(failure={"x": 1}),
            "unexecuted": lambda r: r.update(unexecuted_step_ids=["a"]),
            "old schema": lambda r: r.update(schema_version=1),
        }.items():
            with self.subTest(name=name):
                mutated = copy.deepcopy(report)
                mutate(mutated)
                with self.assertRaises(rules.StageRuleError):
                    rules.verify_runner_report_binding(mutated, row)


if __name__ == "__main__":
    unittest.main(verbosity=2)
