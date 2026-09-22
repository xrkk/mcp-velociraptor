"""Windows-only epoch7->epoch8 activation writer tests (P05 v19 0.PC021.4)."""

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
from tests import p05_pc020_transition as migration_writer
from tests import p05_pc021_activation_writer as writer
from tests import p05_pc021_issuer as issuer
from tests import pc022_windows_refresh as refresh
from tests.pc020_activation_fixture import ActivationFixture


@unittest.skipUnless(os.name == "nt", "CON002: behavioral tests execute only on Windows")
class Epoch8WriterTests(unittest.TestCase):
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
        activation_parent = cls.parent / "activation-189"
        root = activation_parent / str(uuid.uuid4())
        repo = Path(__file__).resolve().parents[1]
        fixture = ActivationFixture(
            root, Path(values["historical"]), Path(values["predecessor"]).read_bytes(),
            Path(values["baseline"]), Path(values["old_activation"]), Path(values["sources"]), repo,
        )
        cls.base = root
        cls.policy = fixture.policy
        cls.root_policy = fixture.root_policy
        cls.canonical_bytes = fixture.canonical_bytes
        cls.reference_root_doc = json.loads((root / "activation-evidence.json").read_bytes())

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def scene(self) -> tuple[Path, Path, issuer.IssuanceCapability]:
        """A freshly re-issued activation plus its canonical file and the
        capability minted by the real G07 issuer (end-to-end binding)."""
        case = self.base.parent / str(uuid.uuid4())
        shutil.copytree(self.base, case)
        (case / "activation-evidence.json").unlink()
        (case / "issuance-receipt.json").unlink()
        draft = json.loads(json.dumps(self.reference_root_doc))
        draft.pop("issued_at")
        issuance = issuer.issue_activation(
            case, root_draft=draft, policy=self.policy,
            root_policy=self.root_policy, epoch7_canonical=self.canonical_bytes,
        )
        canonical = case.parent.parent / f"canonical-{uuid.uuid4()}.json"
        canonical.write_bytes(self.canonical_bytes)
        return case, canonical, issuance.capability

    def run_writer(self, case, canonical, capability, transition_id=None):
        return writer.transition_to_epoch8(
            canonical, case, capability,
            policy=self.policy, root_policy=self.root_policy,
            transition_id=transition_id,
        )

    def test_committed_transition_rewrites_canonical_with_v3_receipt(self) -> None:
        case, canonical, capability = self.scene()
        outcome = self.run_writer(case, canonical, capability)
        self.assertEqual(outcome.status, writer.COMMITTED)
        self.assertTrue(outcome.receipt_written)
        self.assertTrue(capability.spent)
        committed = canonical.read_bytes()
        evidence.verify_schema6_shape(committed, expected_epoch=8)
        document = json.loads(committed.decode("utf-8"))
        self.assertEqual(document["phase"], "NETWORK_ACTIVE")
        self.assertEqual(document["automatic_restore_allowlist"], [evidence.SNAPSHOT_189])
        self.assertEqual(
            document["activation_evidence"]["activated_at"],
            json.loads((case / "activation-evidence.json").read_bytes())["issued_at"],
        )
        self.assertFalse(outcome.next_path.exists())
        receipt = json.loads(outcome.receipt_path.read_bytes())
        self.assertEqual(receipt["kind"], writer.RECEIPT_V3_KIND)
        self.assertEqual(receipt["schema_version"], 3)
        self.assertEqual(
            (receipt["from_sha256"], receipt["to_sha256"], receipt["status"]),
            (evidence._sha(self.canonical_bytes), outcome.to_sha256, "COMMITTED"),
        )
        self.assertNotEqual(writer.RECEIPT_V3_KIND, "pc020-epoch7-migration-transition-receipt-v2")
        self.assertNotEqual(writer.RECEIPT_V3_KIND, migration_writer._receipt(
            "00000000-0000-4000-8000-000000000000",
            to_sha256=None, next_sha256=None, started_at="", replaced_at=None,
            directory_fsynced_at=None, readback_at=None,
            status="FAILED_BEFORE_REPLACE", error="x",
        )["kind"])

    def test_wrong_predecessor_and_binding_mismatches_refuse_without_spending(self) -> None:
        case, canonical, capability = self.scene()
        canonical.write_bytes(self.canonical_bytes + b"x")
        with self.assertRaises(writer.Epoch8TransitionError) as raised:
            self.run_writer(case, canonical, capability)
        self.assertEqual(raised.exception.outcome.status, writer.FAILED_BEFORE_REPLACE)
        self.assertIn("external_drift", raised.exception.outcome.canonical_observation or "")
        self.assertFalse(capability.spent)
        self.assertFalse(Path(str(canonical) + ".next").exists())

        case, canonical, capability = self.scene()
        wrong_dir_capability = issuer.IssuanceCapability(
            operation=capability.operation, workflow_id=capability.workflow_id,
            issuance_id=str(uuid.uuid4()), epoch7_sha256=capability.epoch7_sha256,
            activation_root_sha256=capability.activation_root_sha256,
            issuance_receipt_sha256=capability.issuance_receipt_sha256,
        )
        with self.assertRaisesRegex(Exception, "not bound to this activation"):
            self.run_writer(case, canonical, wrong_dir_capability)
        self.assertFalse(Path(str(canonical) + ".next").exists())

    def test_unknown_next_and_collision_outputs_refuse(self) -> None:
        for kind in ("next", "intent", "receipt"):
            with self.subTest(kind=kind):
                case, canonical, capability = self.scene()
                transition_id = str(uuid.uuid4())
                if kind == "next":
                    Path(str(canonical) + ".next").write_bytes(b"unknown")
                elif kind == "intent":
                    (canonical.parent / f"{canonical.name}.{transition_id}.epoch8-intent.json").write_bytes(b"x")
                else:
                    (canonical.parent / f"{canonical.name}.{transition_id}.epoch8-receipt.json").write_bytes(b"x")
                with self.assertRaisesRegex(Exception, "blocks transition"):
                    self.run_writer(case, canonical, capability, transition_id=transition_id)

    def test_real_external_drift_before_replace_preserves_and_observates(self) -> None:
        case, canonical, capability = self.scene()
        real_create = writer._create_durable
        drift_done = {"n": 0}

        def drifting_create(path, payload):
            real_create(path, payload)
            if path.name.endswith(".epoch8-intent.json"):
                drift_done["n"] += 1
                canonical.write_bytes(self.canonical_bytes.replace(b'"epoch":7', b'"epoch": 7'))

        writer._create_durable = drifting_create
        try:
            with self.assertRaises(writer.Epoch8TransitionError) as raised:
                self.run_writer(case, canonical, capability)
        finally:
            writer._create_durable = real_create
        outcome = raised.exception.outcome
        self.assertEqual(outcome.status, writer.FAILED_BEFORE_REPLACE)
        self.assertTrue(outcome.canonical_observation and outcome.canonical_observation.startswith("external_drift:"))
        self.assertNotEqual(canonical.read_bytes(), self.canonical_bytes)
        self.assertTrue(Path(str(canonical) + ".next").exists())
        self.assertTrue(
            json.loads(outcome.receipt_path.read_bytes())["error"].endswith(
                f"canonical_observation={outcome.canonical_observation}"
            )
        )

    def test_replace_and_readback_faults_are_indeterminate_and_preserved(self) -> None:
        case, canonical, capability = self.scene()
        real_replace = writer.refresh.windows_replace_file
        writer.refresh.windows_replace_file = lambda source, target: (_ for _ in ()).throw(
            refresh.Pc022WindowsRefreshError("replace", "injected replace failure")
        )
        try:
            with self.assertRaises(writer.Epoch8TransitionError) as raised:
                self.run_writer(case, canonical, capability)
        finally:
            writer.refresh.windows_replace_file = real_replace
        self.assertEqual(raised.exception.outcome.status, writer.TRANSITION_INDETERMINATE)
        self.assertEqual(canonical.read_bytes(), self.canonical_bytes)
        self.assertTrue(Path(str(canonical) + ".next").exists())
        self.assertTrue(capability.spent)

        case, canonical, capability = self.scene()
        real_replace = writer.refresh.windows_replace_file

        def tampering_replace(source, target):
            real_replace(source, target)
            target.write_bytes(b"tampered after replace")

        writer.refresh.windows_replace_file = tampering_replace
        try:
            with self.assertRaises(writer.Epoch8TransitionError) as raised:
                self.run_writer(case, canonical, capability)
        finally:
            writer.refresh.windows_replace_file = real_replace
        self.assertEqual(raised.exception.outcome.status, writer.TRANSITION_INDETERMINATE)
        self.assertEqual(canonical.read_bytes(), b"tampered after replace")

    def test_complete_receipt_whose_final_refresh_fails_never_reports_success(self) -> None:
        case, canonical, capability = self.scene()
        real_refresh = writer.refresh.windows_refresh_directory
        calls = {"n": 0}

        def failing_last_refresh(directory):
            calls["n"] += 1
            # .next parent, intent parent, canonical parent = 3 successes;
            # the 4th call belongs to the final receipt persistence.
            if calls["n"] == 4:
                raise refresh.Pc022WindowsRefreshError("flush_main", "injected receipt refresh failure")
            return real_refresh(directory)

        writer.refresh.windows_refresh_directory = failing_last_refresh
        try:
            with self.assertRaises(writer.Epoch8TransitionError) as raised:
                self.run_writer(case, canonical, capability)
        finally:
            writer.refresh.windows_refresh_directory = real_refresh
        outcome = raised.exception.outcome
        self.assertEqual(outcome.status, writer.TRANSITION_INDETERMINATE)
        self.assertFalse(outcome.receipt_written)
        self.assertNotEqual(canonical.read_bytes(), self.canonical_bytes)

    def test_spent_capability_cannot_drive_a_second_transition(self) -> None:
        case, canonical, capability = self.scene()
        first = self.run_writer(case, canonical, capability)
        self.assertEqual(first.status, writer.COMMITTED)
        # the second run is refused before the capability is consulted again:
        # the canonical is now epoch8 (illegal predecessor), nothing is
        # rewritten, and the spent capability is never reused.
        with self.assertRaises(writer.Epoch8TransitionError) as raised:
            self.run_writer(case, canonical, capability)
        self.assertEqual(raised.exception.outcome.status, writer.FAILED_BEFORE_REPLACE)
        committed = canonical.read_bytes()
        evidence.verify_schema6_shape(committed, expected_epoch=8)
        with self.assertRaises(issuer.IssuerError):
            capability.spend()


if __name__ == "__main__":
    unittest.main(verbosity=2)
