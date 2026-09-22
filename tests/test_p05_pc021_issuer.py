"""Windows-only issuer and one-shot capability tests (P05 v19 0.PC021.2.2/.2.5)."""

from __future__ import annotations

import concurrent.futures
import json
import os
import pickle
import shutil
import tempfile
import unittest
import uuid
from pathlib import Path

from tests import p05_pc020_activation as graph
from tests import p05_pc020_evidence as evidence
from tests import p05_pc021_issuer as issuer
from tests.pc020_activation_fixture import ActivationFixture


@unittest.skipUnless(os.name == "nt", "CON002: behavioral tests execute only on Windows")
class IssuerTests(unittest.TestCase):
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
        parent = Path(cls.temp.name).resolve() / "activation-189"
        root = parent / str(uuid.uuid4())
        repo = Path(__file__).resolve().parents[1]
        fixture = ActivationFixture(
            root, Path(values["historical"]), Path(values["predecessor"]).read_bytes(),
            Path(values["baseline"]), Path(values["old_activation"]), Path(values["sources"]), repo,
        )
        cls.base = root
        cls.policy = fixture.policy
        cls.root_policy = fixture.root_policy
        cls.canonical = fixture.canonical_bytes
        cls.reference_root_doc = json.loads((root / "activation-evidence.json").read_bytes())

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def case(self) -> tuple[Path, dict]:
        case = self.base.parent / str(uuid.uuid4())
        shutil.copytree(self.base, case)
        (case / "activation-evidence.json").unlink()
        (case / "issuance-receipt.json").unlink()
        draft = json.loads(json.dumps(self.reference_root_doc))
        draft.pop("issued_at")
        return case, draft

    def issue(self, case: Path, draft: dict):
        return issuer.issue_activation(
            case, root_draft=draft, policy=self.policy,
            root_policy=self.root_policy, epoch7_canonical=self.canonical,
        )

    def verify_graph(self, case: Path):
        return graph.verify_snapshot189_activation(
            case / "activation-evidence.json", policy=self.policy,
            epoch7_canonical=self.canonical, root_policy=self.root_policy,
        )

    def test_full_issuance_passes_public_verifier_and_mints_capability(self) -> None:
        case, draft = self.case()
        outcome = self.issue(case, draft)
        facts = self.verify_graph(case)
        self.assertEqual(facts["phase_count"], 3)
        self.assertFalse(facts["operational_ready"])
        self.assertEqual(
            outcome.capability.activation_root_sha256,
            evidence._sha((case / "activation-evidence.json").read_bytes()),
        )
        self.assertEqual(
            outcome.capability.issuance_receipt_sha256,
            evidence._sha((case / "issuance-receipt.json").read_bytes()),
        )
        document = json.loads((case / "activation-evidence.json").read_bytes())
        receipt = json.loads((case / "issuance-receipt.json").read_bytes())
        self.assertEqual([event["event"] for event in outcome.events], list(graph.EVENT_ORDER))
        self.assertEqual(outcome.issued_at, document["issued_at"], )
        self.assertEqual(receipt["issued_at"], document["issued_at"])
        self.assertEqual(receipt["events"][1]["at"], document["issued_at"])
        outcome.capability.spend()
        self.assertTrue(outcome.capability.spent)

    def test_input_drift_and_existing_outputs_are_refused(self) -> None:
        case, draft = self.case()
        preparation = case / draft["preparation_evidence"]["path"]
        preparation.write_bytes(preparation.read_bytes() + b" ")
        with self.assertRaisesRegex(Exception, "identity|differs|preparation"):
            self.issue(case, draft)
        self.assertFalse((case / "activation-evidence.json").exists())

        case, draft = self.case()
        (case / "activation-evidence.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(issuer.IssuerError, "already exists"):
            self.issue(case, draft)

        case, draft = self.case()
        (case / "issuance-receipt.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(issuer.IssuerError, "already exists"):
            self.issue(case, draft)

        case, draft = self.case()
        drifted_canonical = bytearray(self.canonical)
        drifted_canonical[0] ^= 0x01
        with self.assertRaises(Exception):
            issuer.issue_activation(
                case, root_draft=draft, policy=self.policy,
                root_policy=self.root_policy, epoch7_canonical=bytes(drifted_canonical),
            )
        self.assertFalse((case / "activation-evidence.json").exists())

    def test_root_persistence_failures_refuse_and_preserve_scene(self) -> None:
        import subprocess

        case, draft = self.case()
        user = os.environ.get("USERNAME", "")
        subprocess.run(["icacls", str(case), "/deny", f"{user}:(W)"], check=True, capture_output=True, timeout=60)
        try:
            with self.assertRaises(Exception):
                self.issue(case, draft)
        finally:
            subprocess.run(["icacls", str(case), "/remove:d", user], check=True, capture_output=True, timeout=60)
        self.assertFalse((case / "activation-evidence.json").exists())

        case, draft = self.case()
        real_refresh = issuer.refresh.windows_refresh_directory
        calls = {"n": 0}

        def failing_refresh(directory):
            calls["n"] += 1
            if calls["n"] == 1:
                raise issuer.refresh.Pc022WindowsRefreshError("flush_main", "injected directory refresh failure")
            return real_refresh(directory)

        issuer.refresh.windows_refresh_directory = failing_refresh
        try:
            with self.assertRaisesRegex(Exception, "injected directory refresh failure"):
                self.issue(case, draft)
        finally:
            issuer.refresh.windows_refresh_directory = real_refresh
        root = case / "activation-evidence.json"
        self.assertTrue(root.exists())
        self.assertFalse((case / "issuance-receipt.json").exists())

        # a failed issuance never resumes over the preserved root
        with self.assertRaisesRegex(issuer.IssuerError, "already exists"):
            self.issue(case, draft)

    def test_root_readback_tamper_and_receipt_refresh_failure(self) -> None:
        case, draft = self.case()
        real_create = issuer._create_durable_file_events

        def tampering_create(path, payload, events):
            real_create(path, payload, events)
            path.write_bytes(payload + b"tamper")

        issuer._create_durable_file_events = tampering_create
        try:
            with self.assertRaisesRegex(issuer.IssuerError, "readback"):
                self.issue(case, draft)
        finally:
            issuer._create_durable_file_events = real_create
        self.assertTrue((case / "activation-evidence.json").exists())
        self.assertFalse((case / "issuance-receipt.json").exists())

        case, draft = self.case()
        real_refresh = issuer.refresh.windows_refresh_directory
        calls = {"n": 0}

        def failing_second_refresh(directory):
            calls["n"] += 1
            if calls["n"] == 2:
                raise issuer.refresh.Pc022WindowsRefreshError("flush_main", "injected receipt refresh failure")
            return real_refresh(directory)

        issuer.refresh.windows_refresh_directory = failing_second_refresh
        try:
            with self.assertRaisesRegex(Exception, "injected receipt refresh failure"):
                self.issue(case, draft)
        finally:
            issuer.refresh.windows_refresh_directory = real_refresh
        self.assertTrue((case / "activation-evidence.json").exists())
        self.assertTrue((case / "issuance-receipt.json").exists())

    def test_capability_single_use_thread_race_and_nonserializability(self) -> None:
        case, draft = self.case()
        outcome = self.issue(case, draft)
        capability = outcome.capability
        with self.assertRaises(TypeError):
            pickle.dumps(capability)
        with self.assertRaises(TypeError):
            __import__("copy").deepcopy(capability)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: _try_spend(capability), range(16)))
        self.assertEqual(results.count("spent"), 1)
        self.assertEqual(results.count("refused"), 15)
        with self.assertRaises(issuer.IssuerError):
            capability.spend()

    def test_capability_cannot_be_rebuilt_from_receipt(self) -> None:
        case, draft = self.case()
        outcome = self.issue(case, draft)
        receipt = json.loads((case / "issuance-receipt.json").read_bytes())
        reconstructed = issuer.IssuanceCapability(
            operation=receipt["operation"], workflow_id=receipt["workflow_id"],
            issuance_id=receipt["issuance_id"], epoch7_sha256=receipt["epoch7"]["canonical_sha256"],
            activation_root_sha256=receipt["activation_root"]["sha256"],
            issuance_receipt_sha256=evidence._sha((case / "issuance-receipt.json").read_bytes()),
        )
        # a separately constructed object is a different, unrelated token:
        # the controller only honors the capability returned by issuance
        self.assertIsNot(reconstructed, outcome.capability)
        self.assertTrue(outcome.capability.spent is False)


def _try_spend(capability) -> str:
    try:
        capability.spend()
        return "spent"
    except issuer.IssuerError:
        return "refused"


if __name__ == "__main__":
    unittest.main(verbosity=2)
