"""Host-only selector tests; complete synthetic graph, no VM commands.

The graph tests require the existing explicit PC020 fixture environment and
write only under PC020_TEST_TEMP_ROOT. No production trust binding is inferred.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import shutil
import tempfile
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tests import p05_selector_readonly as adapter
from tests import p05_pc020_evidence as evidence
from tests import p05_pc020_transition as migration
from tests import p05_pc021_activation_writer as activation
from tests.test_p05_recovery_contract import load_selector
from tests.test_p05_pc021_capability import CapabilityFixture


def epoch8(c7: bytes, activation_path: Path) -> dict:
    root = json.loads(activation_path.read_bytes())
    return activation._derive_epoch8(json.loads(c7), activation_ref={
        "source": "snapshot189-activation",
        "evidence_path": f"activation-189/{activation_path.parent.name}/activation-evidence.json",
        "evidence_sha256": evidence._sha(activation_path.read_bytes()),
        "activated_at": root["issued_at"],
    }, checkpoint_marker=root["checkpoint_marker"])


class Schema6ReadTests(unittest.TestCase):
    def setUp(self):
        self.selector = load_selector()
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("PC020_TEST_TEMP_ROOT"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / "state.json"
        canonical = Path(self.selector.__file__).with_name("快照恢复状态.json")
        self.c7 = json.loads(canonical.read_bytes())
        self.c8 = copy.deepcopy(self.c7)
        self.c8.update(epoch=8, phase="NETWORK_ACTIVE")
        self.c8["active_snapshot"].update(name=evidence.SNAPSHOT_189, checkpoint_marker="Win10MalBox-Velo-Snapshot5.vmsn")
        self.c8["automatic_restore_allowlist"] = [evidence.SNAPSHOT_189]
        self.c8["retired_snapshots"].append({"name": evidence.SNAPSHOT_187, "status": evidence.MANUAL_ONLY})
        self.c8["activation_evidence"] = {"source": "snapshot189-activation", "evidence_path":
            f"activation-189/{uuid.uuid4()}/activation-evidence.json", "evidence_sha256": "a"*64,
            "activated_at": "2026-10-01T00:00:00Z"}

    def save(self, value):
        self.path.write_bytes(evidence.canonical_json(value))

    def cli(self, *args, bindings=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(stdout))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            stack.enter_context(patch("sys.argv", [self.selector.__file__, "--state", str(self.path),
                "--expect-workflow", evidence.WORKFLOW_ID, *args]))
            if bindings is not None:
                stack.enter_context(patch.object(self.selector, "governed_bindings", return_value=bindings))
            result = self.selector.main()
        return result, stdout.getvalue(), stderr.getvalue()

    def test_current_shapes_and_invalid_matrix(self):
        for base in (self.c7, self.c8):
            self.save(base)
            self.assertEqual(self.selector.read_state(self.path, evidence.WORKFLOW_ID), base)
            changes = (
                lambda s: s.update(schema_version=True), lambda s: s.update(epoch=True),
                lambda s: s.update(epoch=6), lambda s: s.update(extra=True),
                lambda s: s.update(phase="BOOTSTRAP_ACTIVE"),
                lambda s: s["active_snapshot"].update(name=evidence.SNAPSHOT_188),
                lambda s: s["active_snapshot"].update(checkpoint_marker="bad.vmsn"),
                lambda s: s["active_snapshot"].update(checkpoint_marker="../bad.vmsn"),
                lambda s: s["active_snapshot"].update(checkpoint_marker="Win10MalBox-Velo-Snapshot0.vmsn"),
                lambda s: s["retired_snapshots"].reverse(),
                lambda s: s["retired_snapshots"].append(s["retired_snapshots"][0]),
                lambda s: s["retired_snapshots"][0].update(status="ACTIVE"),
                lambda s: s["automatic_restore_allowlist"].append(evidence.SNAPSHOT_188),
                lambda s: s["migration_evidence"].update(evidence_path="../migration.json"),
                lambda s: s["preparation_evidence"].update(evidence_path="C:/admission.json"),
                lambda s: s["migration_evidence"].update(extra=True),
                lambda s: s["preparation_evidence"].update(qualified_at="2026-10-01"),
                lambda s: s["migration_evidence"].update(evidence_sha256="A"*64),
                lambda s: s["preparation_evidence"].update(source="foreign"),
            )
            for change in changes:
                bad = copy.deepcopy(base); change(bad); self.save(bad)
                with self.subTest(epoch=base["epoch"], change=change):
                    with self.assertRaises(self.selector.StateError):
                        self.selector.read_state(self.path, evidence.WORKFLOW_ID)
        bad = copy.deepcopy(self.c7); bad["activation_evidence"] = self.c8["activation_evidence"]
        self.save(bad)
        with self.assertRaises(self.selector.StateError): self.selector.read_state(self.path, evidence.WORKFLOW_ID)
        bad = copy.deepcopy(self.c8); bad["activation_evidence"] = None; self.save(bad)
        with self.assertRaises(self.selector.StateError): self.selector.read_state(self.path, evidence.WORKFLOW_ID)

    def test_encoding_ambiguity_and_workflow_refuse(self):
        self.save(self.c7)
        good = self.path.read_bytes()
        for bad in (good.replace(b'"schema_version":6', b'"schema_version":6,"schema_version":6'),
                    good.replace(b'\n', b'\r\n'), json.dumps(self.c7).encode()):
            self.path.write_bytes(bad)
            with self.assertRaises(self.selector.StateError): self.selector.read_state(self.path, evidence.WORKFLOW_ID)
        self.path.write_bytes(good)
        with self.assertRaises(self.selector.StateError): self.selector.read_state(self.path, "foreign")

    def test_no_production_binding_and_foreign_candidate_emit_nothing(self):
        self.save(self.c7)
        for args in (("--emit-active",), ("--validate-candidate", evidence.SNAPSHOT_187),
                     ("--validate-candidate", evidence.SNAPSHOT_189),
                     ("--validate-candidate", evidence.SNAPSHOT_188)):
            result, out, error = self.cli(*args)
            self.assertEqual((result, out), (2, "")); self.assertTrue(error)

    def test_fixed_root_cannot_follow_an_alias_or_reparse(self):
        fixed = self.root / "fixed"; fixed.mkdir()
        outside = self.root / "outside"; outside.mkdir()
        record = outside / "record.json"; record.write_bytes(b"untouched")
        (fixed / "alias").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "link|reparse"):
            adapter.plain(fixed, "alias/record.json")
        with self.assertRaisesRegex(ValueError, "link|reparse|plain directory"):
            adapter.plain(fixed / "alias", "record.json")
        self.assertEqual(record.read_bytes(), b"untouched")

    def test_legacy_modes_and_unknown_next_preserve_every_byte(self):
        self.save(self.c7)
        next_path = Path(str(self.path)+".next")
        external = self.root / "sentinel"; external.write_bytes(b"external")
        record = self.root / "evidence.json"; record.write_bytes(b"evidence")
        next_path.symlink_to(external)
        before = (self.path.read_bytes(), record.read_bytes(), external.read_bytes(), os.readlink(next_path))
        with patch.object(self.selector, "write_exclusive_json") as write, patch.object(self.selector.os, "replace") as move:
            for args in (("--emit-next", str(next_path)), ("--adopt-baseline", str(record)), ("--emit-active",)):
                result, out, error = self.cli(*args)
                self.assertEqual((result, out), (2, "")); self.assertTrue(error)
            write.assert_not_called(); move.assert_not_called()
        self.assertEqual(before, (self.path.read_bytes(), record.read_bytes(), external.read_bytes(), os.readlink(next_path)))

    def test_epoch7_and_epoch8_write_modes_preserve_absent_next(self):
        next_path = Path(str(self.path)+".next")
        record = self.root / "record.json"; record.write_bytes(b"untouched")
        for state in (self.c7, self.c8):
            self.save(state); before = self.path.read_bytes()
            with patch.object(self.selector, "write_exclusive_json") as write, \
                    patch.object(self.selector.os, "replace") as move, patch.object(Path, "unlink") as delete:
                for args in (("--emit-next", str(next_path)), ("--adopt-baseline", str(record))):
                    result, out, error = self.cli(*args)
                    self.assertEqual((result, out), (2, "")); self.assertIn("read-only", error)
                write.assert_not_called(); move.assert_not_called(); delete.assert_not_called()
            self.assertFalse(os.path.lexists(next_path)); self.assertEqual(self.path.read_bytes(), before)
            self.assertEqual(record.read_bytes(), b"untouched")


class SelectorGraphTests(CapabilityFixture):
    """Real validators over synthetic complete originals, with explicit bindings."""
    @classmethod
    def setUpClass(cls):
        CapabilityFixture.setUpClass.__func__(cls)
        for namespace in ("pc020-preparation", "pc020-migration"):
            shutil.copytree(cls.base / namespace, cls.parent / namespace)
        cls.receipt7 = cls.parent / "epoch7-receipt.json"
        h7 = evidence._sha(cls.c7)
        cls.receipt7.write_bytes(evidence.canonical_json(migration._receipt(str(uuid.uuid4()),
            to_sha256=h7, next_sha256=h7, started_at="2026-10-01T00:00:00Z",
            replaced_at="2026-10-01T00:00:01Z", directory_fsynced_at="2026-10-01T00:00:02Z",
            readback_at="2026-10-01T00:00:03Z", status="COMMITTED", error=None)))
        cls.binding = adapter.ControllerBindings(cls.parent, cls.policy, cls.c7, cls.receipt7, cls.root_policy)

    def setUp(self):
        CapabilityFixture.setUp(self)
        self.selector = load_selector()
        self.path = self.parent / "current-selector.json"
        self.path.write_bytes(type(self).c7)

    cli = Schema6ReadTests.cli

    def test_preparation_graph_and_current_policy_missing_cli_gate(self):
        before = self.tree()
        result, out, error = self.cli("--emit-active", bindings=self.binding)
        self.assertEqual(result, 0, error)
        self.assertEqual(json.loads(out)["snapshot_name"], evidence.SNAPSHOT_187)
        result, out, error = self.cli("--validate-candidate", evidence.SNAPSHOT_187, bindings=self.binding)
        self.assertEqual(result, 0, error); self.assertTrue(json.loads(out)["valid"])
        self.assertEqual(self.tree(), before)
        with patch.object(self.selector, "EVIDENCE_ROOT", self.parent):
            result, out, error = self.cli("--emit-active")
        self.assertEqual((result, out), (2, "")); self.assertIn("governance", error)
        with self.assertRaisesRegex(ValueError, "stage"):
            adapter.qualify(type(self).c7, bindings=self.binding, stage="P05_REPAIR_CANDIDATE")

    def test_epoch7_hash_source_and_committed_receipt_refuse(self):
        original = self.receipt7.read_bytes()
        bad = json.loads(original); bad.update(schema_version=1, kind="pc020-canonical-transition-receipt-v1")
        self.receipt7.write_bytes(evidence.canonical_json(bad))
        try:
            result, out, error = self.cli("--emit-active", bindings=self.binding)
            self.assertEqual((result, out), (2, "")); self.assertIn("COMMITTED", error)
        finally: self.receipt7.write_bytes(original)
        bad = json.loads(type(self).c7); bad["preparation_evidence"]["evidence_sha256"] = "0"*64
        self.path.write_bytes(evidence.canonical_json(bad))
        binding = replace(self.binding, epoch7_canonical=self.path.read_bytes())
        result, out, error = self.cli("--emit-active", bindings=binding)
        self.assertEqual((result, out), (2, "")); self.assertIn("hash", error)
        self.path.write_bytes(type(self).c7)
        bad_policy = replace(self.policy, implementation_sources={})
        result, out, error = self.cli("--emit-active", bindings=replace(self.binding, policy=bad_policy))
        self.assertEqual((result, out), (2, "")); self.assertIn("trusted policy", error)

    def test_complete_epoch8_graph_and_negative_branches(self):
        case, canonical, capability = self.scene()
        outcome = self.run_writer(case, canonical, capability)
        self.assertEqual(outcome.status, "COMMITTED")
        self.path = canonical
        root = case / "activation-evidence.json"
        rpath, ipath = outcome.receipt_path, outcome.intent_path
        self.assertEqual(rpath, case / "epoch8-transition-receipt.json")
        self.assertEqual(ipath, case / "epoch8-transition-intent.json")
        # These exact artifacts are actual issuer/writer outputs; no rebuilding
        # or relocating a receipt to make the consumer test pass.
        receipt, intent = json.loads(rpath.read_bytes()), json.loads(ipath.read_bytes())
        before = self.tree()
        result, out, error = self.cli("--emit-active", bindings=self.binding)
        self.assertEqual(result, 0, error); self.assertEqual(json.loads(out)["snapshot_name"], evidence.SNAPSHOT_189)
        result, out, error = self.cli("--validate-candidate", evidence.SNAPSHOT_189, bindings=self.binding)
        self.assertEqual(result, 0, error); self.assertEqual(self.tree(), before)
        for changes in ({"schema_version":2,"kind":"pc020-canonical-transition-receipt-v2"},
                        {"status":"TRANSITION_INDETERMINATE","error":"unknown"}, {"next_sha256":"0"*64},
                        {"workflow_id":"foreign"}, {"directory_fsynced_at":None}):
            rpath.write_bytes(evidence.canonical_json({**receipt, **changes}))
            result, out, error = self.cli("--emit-active", bindings=self.binding)
            self.assertEqual((result, out), (2, "")); self.assertTrue(error)
        rpath.write_bytes(evidence.canonical_json(receipt))
        ipath.write_bytes(evidence.canonical_json({**intent, "transition_id":str(uuid.uuid4())}))
        result, out, error = self.cli("--emit-active", bindings=self.binding)
        self.assertEqual((result, out), (2, "")); self.assertIn("intent", error)
        ipath.write_bytes(evidence.canonical_json(intent))
        report = case / json.loads(root.read_bytes())["candidate_cycles"][1]["report"]["path"]
        original = report.read_bytes(); report.write_bytes(b"{}\n")
        try:
            result, out, error = self.cli("--emit-active", bindings=self.binding)
            self.assertEqual((result, out), (2, "")); self.assertTrue(error)
        finally: report.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
