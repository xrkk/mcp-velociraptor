"""Windows-only P06/P07 unified consumer predicate tests."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
import uuid
from pathlib import Path

from tests import p05_pc020_activation as graph
from tests import p05_pc020_evidence as evidence
from tests import p05_pc021_activation_writer as writer
from tests import p05_pc021_issuer as issuer
from tests import p06_pc021_consumer as consumer
from tests.pc020_activation_fixture import ActivationFixture


@unittest.skipUnless(os.name == "nt", "CON002: behavioral tests execute only on Windows")
class ConsumerAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        names = {
            "historical": "PC020_ACTIVATION188_FIXTURE", "predecessor": "PC020_PREDECESSOR_FIXTURE",
            "baseline": "PC020_BASELINE_DIR_FIXTURE", "old_activation": "PC020_ACTIVATION_DIR_FIXTURE",
            "sources": "PC020_REAL_SOURCE_ROOT",
        }
        values = {key: os.environ.get(env) for key, env in names.items()}
        missing = [key for key, value in values.items() if not value or not Path(value).exists()]
        if missing:
            raise RuntimeError(f"required PC020 activation fixtures missing: {missing}")
        cls.temp = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
        cls.parent = Path(cls.temp.name).resolve()
        activation_parent = cls.parent / "p06-root" / "activation-189"
        root = activation_parent / str(uuid.uuid4())
        repo = Path(__file__).resolve().parents[1]
        fixture = ActivationFixture(
            root, Path(values["historical"]), Path(values["predecessor"]).read_bytes(),
            Path(values["baseline"]), Path(values["old_activation"]), Path(values["sources"]), repo,
        )
        cls.base = root
        cls.policy = fixture.policy
        cls.root_policy = fixture.root_policy
        cls.epoch7 = fixture.canonical_bytes
        cls.reference_root_doc = json.loads((root / "activation-evidence.json").read_bytes())

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def scene(self):
        """Re-issued activation plus a committed epoch8 transition."""
        case = self.base.parent / str(uuid.uuid4())
        shutil.copytree(self.base, case)
        (case / "activation-evidence.json").unlink()
        (case / "issuance-receipt.json").unlink()
        draft = json.loads(json.dumps(self.reference_root_doc))
        draft.pop("issued_at")
        issuance = issuer.issue_activation(
            case, root_draft=draft, policy=self.policy,
            root_policy=self.root_policy, epoch7_canonical=self.epoch7,
        )
        canonical = case.parent.parent / f"canonical-{uuid.uuid4()}.json"
        canonical.write_bytes(self.epoch7)
        outcome = writer.transition_to_epoch8(
            canonical, case, issuance.capability,
            policy=self.policy, root_policy=self.root_policy,
        )
        assert outcome.status == writer.COMMITTED
        return case, canonical, outcome

    def admit(self, case, canonical, outcome):
        return consumer.verify_p06_admission(
            case, epoch7_canonical=self.epoch7,
            epoch8_canonical=canonical.read_bytes(),
            epoch8_receipt_path=outcome.receipt_path,
            policy=self.policy, root_policy=self.root_policy,
        )

    def test_admitted_current_graph(self) -> None:
        case, canonical, outcome = self.scene()
        admission = self.admit(case, canonical, outcome)
        self.assertTrue(admission["authorizes_p06"])
        self.assertFalse(admission["historical_only"])
        self.assertEqual(admission["epoch8_sha256"], evidence._sha(canonical.read_bytes()))

    def test_legacy_and_version_mutations_refuse(self) -> None:
        case, canonical, outcome = self.scene()
        original_receipt = outcome.receipt_path.read_bytes()
        def restore():
            outcome.receipt_path.write_bytes(original_receipt)
        try:
            _mutate_receipt(outcome, kind="pc020-canonical-transition-receipt-v2")
            with self.assertRaisesRegex(consumer.ConsumerError, "v3 kind"):
                self.admit(case, canonical, outcome)
            restore()
            _mutate_receipt(outcome, status="TRANSITION_INDETERMINATE", error="x")
            with self.assertRaisesRegex(consumer.ConsumerError, "not COMMITTED"):
                self.admit(case, canonical, outcome)
            restore()
            _mutate_receipt(outcome, to_sha256="0" * 64)
            with self.assertRaisesRegex(consumer.ConsumerError, "do not bind"):
                self.admit(case, canonical, outcome)
            restore()
            _mutate_receipt(outcome, extra_key=True)
            with self.assertRaisesRegex(Exception, "keys differ"):
                self.admit(case, canonical, outcome)
        finally:
            restore()
        # an epoch8 canonical that is not the active 189 state refuses
        case2, canonical2, outcome2 = self.scene()
        mutated = json.loads(canonical2.read_bytes())
        mutated["phase"] = "PREPARATION_BASELINE"
        canonical2.write_bytes(evidence.canonical_json(mutated))
        with self.assertRaisesRegex(Exception, "shape differs|not the active Snapshot189 state"):
            self.admit(case2, canonical2, outcome2)

    def test_future_timestamps_and_wrong_binding_refuse(self) -> None:
        case, canonical, outcome = self.scene()
        root_path = case / "activation-evidence.json"
        document = json.loads(root_path.read_bytes())
        document["issued_at"] = "2999-01-01T00:00:00Z"
        root_path.write_bytes(json.dumps(document, sort_keys=True, separators=(",", ":")).encode())
        with self.assertRaises(Exception):
            self.admit(case, canonical, outcome)


def _mutate_receipt(outcome, *, kind=None, status=None, error=None, to_sha256=None, extra_key=False):
    """Write a mutated copy of the committed receipt and return its path."""
    receipt = json.loads(outcome.receipt_path.read_bytes())
    if kind is not None:
        receipt["kind"] = kind
    if status is not None:
        receipt["status"] = status
    if error is not None:
        receipt["error"] = error
    if to_sha256 is not None:
        receipt["to_sha256"] = to_sha256
    if extra_key:
        receipt["future_field"] = 1
    outcome.receipt_path.write_bytes(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())
    return outcome.receipt_path


@unittest.skipUnless(os.name == "nt", "CON002: behavioral tests execute only on Windows")
class SelectionAggregateHandoffTests(unittest.TestCase):
    def _ledger(self):
        return [
            {"scenario": "s1", "run_id": "r1", "restore_attempt_id": "a1", "status": "success"},
            {"scenario": "s1", "run_id": "r2", "restore_attempt_id": "a2", "status": "failed"},
            {"scenario": "s2", "run_id": "r3", "restore_attempt_id": "a3", "status": "success"},
        ]

    def _selection(self, *, include_failed=False, drop_reason=False, miss_scenario=False):
        alternates = [{"run_id": "r2", "reason": "failed attempt"}]
        if drop_reason:
            alternates = [{"run_id": "r2"}]
        rows = [
            {"scenario": "s1", "run_id": "r1", "restore_attempt_id": "a1",
             "report_relative_path": "s1/r1/report.json", "status": "success",
             "rejected_alternates": alternates},
            {"scenario": "s2", "run_id": "r3", "restore_attempt_id": "a3",
             "report_relative_path": "s2/r3/report.json", "status": "success",
             "rejected_alternates": []},
        ]
        if include_failed:
            rows[0]["run_id"] = "r2"
        if miss_scenario:
            rows = rows[:1]
        return rows

    def test_valid_selection_binds(self) -> None:
        consumer.verify_selection(self._ledger(), self._selection())

    def test_selection_mutations_refuse(self) -> None:
        cases = {
            "failed attempt selected": dict(include_failed=True),
            "alternate without reason": dict(drop_reason=True),
            "scenario never selected": dict(miss_scenario=True),
        }
        for name, kwargs in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(consumer.ConsumerError):
                    consumer.verify_selection(self._ledger(), self._selection(**kwargs))
        duplicate = self._selection()
        duplicate.append(dict(duplicate[0]))
        with self.assertRaises(consumer.ConsumerError):
            consumer.verify_selection(self._ledger(), duplicate)

    def test_aggregate_strict_recompute(self) -> None:
        tools = {f"t{i}" for i in range(129)}
        scenarios = {f"s{i}" for i in range(5)}
        relations = 129 * 5
        ledger = [
            {"scenario": scenario, "run_id": f"r-{scenario}", "status": "success"}
            for scenario in sorted(scenarios)
        ]
        selection = [
            {"scenario": scenario, "run_id": f"r-{scenario}",
             "restore_attempt_id": f"a-{scenario}",
             "report_relative_path": f"{scenario}/report.json",
             "status": "success", "rejected_alternates": []}
            for scenario in sorted(scenarios)
        ]
        coverage = [
            {"tool": tool, "scenario": scenario, "run_id": f"r-{scenario}"}
            for tool in tools for scenario in scenarios
        ]
        result = consumer.verify_aggregate_binding(
            selection_rows=selection, coverage=coverage,
            expected_tools=tools, expected_scenarios=scenarios,
            expected_relations=relations,
        )
        self.assertEqual((result["tools"], result["scenarios"], result["relations"]), (129, 5, 645))
        missing = coverage[:-1]
        with self.assertRaisesRegex(consumer.ConsumerError, "relations differ"):
            consumer.verify_aggregate_binding(
                selection_rows=selection, coverage=missing,
                expected_tools=tools, expected_scenarios=scenarios,
                expected_relations=relations,
            )
        cross_attempt = coverage + [{"tool": "t0", "scenario": "s9", "run_id": "r-s0"}]
        with self.assertRaisesRegex(consumer.ConsumerError, "unselected"):
            consumer.verify_aggregate_binding(
                selection_rows=selection, coverage=cross_attempt,
                expected_tools=tools, expected_scenarios=scenarios | {"s9"},
                expected_relations=relations,
            )

    def test_handoff_one_direction(self) -> None:
        admission = {"epoch8_sha256": "e8", "activation_root_sha256": "hr"}
        selection = self._selection()
        handoff = {
            "epoch8_sha256": "e8", "activation_root_sha256": "hr",
            "consumed_selection": [
                {"scenario": row["scenario"], "run_id": row["run_id"]} for row in selection
            ],
        }
        consumer.verify_p07_handoff(handoff, admission=admission, selection_rows=selection)
        bad = dict(handoff, epoch8_sha256="other")
        with self.assertRaises(consumer.ConsumerError):
            consumer.verify_p07_handoff(bad, admission=admission, selection_rows=selection)
        reverse = dict(handoff, p05_prerequisite=True)
        with self.assertRaises(consumer.ConsumerError):
            consumer.verify_p07_handoff(reverse, admission=admission, selection_rows=selection)

    def test_member_and_hash_domains(self) -> None:
        import subprocess

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "member.bin").write_bytes(b"payload")
            link = root / "link.bin"
            subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"New-Item -ItemType Junction -Path '{link}' -Value '{root}' | Out-Null"],
                check=True, capture_output=True, timeout=60,
            )
            try:
                resolved = consumer.member_paths_stay_in_package(
                    [{"path": "member.bin"}], root
                )
                self.assertEqual(len(resolved), 1)
                with self.assertRaises(consumer.ConsumerError):
                    consumer.member_paths_stay_in_package(
                        [{"path": "../escape.bin"}], root
                    )
                with self.assertRaises(consumer.ConsumerError):
                    consumer.member_paths_stay_in_package([{"path": "link.bin"}], root)
            finally:
                link.rmdir()
        with self.assertRaises(consumer.ConsumerError):
            consumer.transport_zip_hash_is_not_manifest_hash("a" * 64, "a" * 64)
        consumer.transport_zip_hash_is_not_manifest_hash("a" * 64, "b" * 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
