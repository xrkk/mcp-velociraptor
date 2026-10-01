"""T009 host regression: real issuer/writer/graphs, explicit native I/O seams.

All scene outputs are isolated under PC020_TEST_TEMP_ROOT. Native refresh,
replace and no-follow handles are simulated; these are not Windows evidence.
"""
from __future__ import annotations

from contextlib import ExitStack
import json
import os
import shutil
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from tests import p05_pc020_evidence as evidence
from tests import p05_pc020_transition as migration
from tests import p05_pc021_activation_writer as writer
from tests import p05_pc021_transition_evidence as transition
from tests import p05_selector_readonly as selector
from tests import p06_pc021_consumer as consumer
from tests import pc022_windows_refresh as refresh
from tests.test_p05_pc021_capability import CapabilityFixture
from tests.test_p05_pc021_activation_writer import Epoch8WriterTests


@unittest.skipUnless(os.name == "posix", "explicit host writer simulations")
class HostWriterRegressionTests(CapabilityFixture, Epoch8WriterTests):
    """Run every existing Windows writer case under named host simulations."""
    __unittest_skip__ = False

    @classmethod
    def setUpClass(cls):
        CapabilityFixture.setUpClass.__func__(cls)
        cls.canonical_bytes = cls.c7

    def run_writer(self, case, canonical, capability, transition_id=None):
        return writer.transition_to_epoch8(canonical, case, capability, policy=self.policy,
            root_policy=self.root_policy, transition_id=transition_id)


class TransitionOutputTests(CapabilityFixture):
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

    def assert_unchanged_upstream(self, case, original):
        self.assertEqual(original, {name: (case / name).read_bytes() for name in original})

    def test_actual_outputs_order_qualification_consumer_and_archive(self):
        case, canonical, capability = self.scene()
        upstream = {name:(case/name).read_bytes() for name in ("activation-evidence.json", "issuance-receipt.json")}
        state = writer.issuer._capability_state(capability)
        events = []
        create, read = writer._create_durable, writer._read
        replace, refresh_dir = refresh.windows_replace_file, refresh.windows_refresh_directory
        identify = refresh.handle_directory_identity
        volumes = []
        def volume(path):
            volumes.append(path); return identify(path)
        def created(path, payload):
            self.assertTrue(state.spent)
            self.assertIn(case, volumes); self.assertIn(canonical.parent, volumes)
            events.append("create:"+path.name); create(path, payload)
        def reading(path):
            events.append("read:"+path.name); return read(path)
        def replaced(source, target):
            events.append("replace"); return replace(source, target)
        def refreshed(path):
            events.append("refresh:"+str(path)); return refresh_dir(path)
        with patch.object(writer, "_create_durable", side_effect=created), \
                patch.object(writer, "_read", side_effect=reading), \
                patch.object(refresh, "handle_directory_identity", side_effect=volume), \
                patch.object(refresh, "windows_replace_file", side_effect=replaced), \
                patch.object(refresh, "windows_refresh_directory", side_effect=refreshed):
            result = self.run_writer(case, canonical, capability)
        self.assertEqual(result.status, writer.COMMITTED)
        self.assertEqual(result.intent_path, case/transition.INTENT_NAME)
        self.assertEqual(result.receipt_path, case/transition.RECEIPT_NAME)
        self.assertEqual(result.next_path, Path(str(canonical)+".next"))
        self.assertEqual(len(list(canonical.parent.glob(canonical.name+".*epoch8*"))), 0)
        first_write = next(i for i, event in enumerate(events) if event.startswith("create:"))
        tail = events[first_write:]
        expected = ["create:"+result.next_path.name, "read:"+result.next_path.name,
            "create:"+transition.INTENT_NAME, "read:"+transition.INTENT_NAME,
            "read:"+canonical.name, "replace", "read:"+canonical.name,
            "create:"+transition.RECEIPT_NAME, "read:"+transition.RECEIPT_NAME]
        position = -1
        for event in expected: position = tail.index(event, position+1)
        self.assert_unchanged_upstream(case, upstream)
        before = self.tree()
        bindings = selector.ControllerBindings(self.parent, self.policy, self.c7, self.receipt7, self.root_policy)
        self.assertTrue(selector.qualify(canonical.read_bytes(), bindings=bindings,
            stage="P06_ACTIVE")["content_graph_validated"])
        admitted = consumer.verify_p06_admission(case, epoch7_canonical=self.c7,
            epoch8_canonical=canonical.read_bytes(), epoch8_receipt_path=result.receipt_path,
            policy=self.policy, root_policy=self.root_policy)
        self.assertTrue(admitted["authorizes_p06"]); self.assertEqual(self.tree(), before)
        # Archive the complete immutable A using the existing activation record
        # subtree: both originals and all nested files remain exact bytes.
        archive = self.parent / "restore" / str(uuid.uuid4()) / "activation"
        shutil.copytree(case, archive)
        self.assertEqual({p.relative_to(case).as_posix():p.read_bytes() for p in case.rglob("*") if p.is_file()},
            {p.relative_to(archive).as_posix():p.read_bytes() for p in archive.rglob("*") if p.is_file()})
        output = os.environ.get("T009_TRACE_PATH")
        if output:
            Path(output).write_text(json.dumps({"events":events,"volume_probes":[str(p) for p in volumes],
                "intent":str(result.intent_path),"receipt":str(result.receipt_path)},indent=2))

    def test_consumer_refuses_old_location_and_wrong_id_hash_generation(self):
        case, canonical, capability = self.scene()
        result = self.run_writer(case, canonical, capability)
        original = result.receipt_path.read_bytes()
        old = canonical.parent / f"{canonical.name}.{result.transition_id}.epoch8-receipt.json"
        old.write_bytes(original)
        def admit(path=result.receipt_path):
            return consumer.verify_p06_admission(case, epoch7_canonical=self.c7,
                epoch8_canonical=canonical.read_bytes(), epoch8_receipt_path=path,
                policy=self.policy, root_policy=self.root_policy)
        before = self.tree()
        with self.assertRaisesRegex(consumer.ConsumerError, "fixed activation"): admit(old)
        self.assertEqual(self.tree(), before)
        for fields in ({"transition_id":str(uuid.uuid4())}, {"next_sha256":"0"*64},
                {"workflow_id":"foreign"}, {"kind":"pc020-canonical-transition-receipt-v2"},
                {"readback_at":None}):
            result.receipt_path.write_bytes(evidence.canonical_json({**json.loads(original), **fields}))
            before = self.tree()
            with self.assertRaises(consumer.ConsumerError): admit()
            self.assertEqual(self.tree(), before)
        result.receipt_path.write_bytes(original)
        self.assertEqual(old.read_bytes(), original)

    def test_fixed_collisions_and_unknown_objects_preserve_sentinels(self):
        for kind in ("intent", "receipt", "receipt-link", "intent-directory"):
            with self.subTest(kind=kind):
                case, canonical, capability = self.scene()
                sentinel = self.parent / ("sentinel-"+str(uuid.uuid4())); sentinel.write_bytes(b"foreign")
                path = case / (transition.INTENT_NAME if kind.startswith("intent") else transition.RECEIPT_NAME)
                if kind.endswith("link"): path.symlink_to(sentinel)
                elif kind.endswith("directory"): path.mkdir()
                else: path.write_bytes(b"foreign")
                original = {name:(case/name).read_bytes() for name in ("activation-evidence.json", "issuance-receipt.json")}
                with patch.object(refresh, "windows_replace_file") as replace_file:
                    with self.assertRaises(writer.Epoch8TransitionError) as raised:
                        self.run_writer(case, canonical, capability)
                replace_file.assert_not_called()
                self.assertEqual(raised.exception.outcome.status, writer.FAILED_BEFORE_REPLACE)
                self.assertEqual(raised.exception.outcome.receipt_written, kind.startswith("intent"))
                self.assertIsNone(raised.exception.outcome.next_sha256)
                self.assertEqual(canonical.read_bytes(), self.c7)
                self.assertFalse(Path(str(canonical)+".next").exists())
                self.assertEqual(sentinel.read_bytes(), b"foreign")
                if not kind.endswith("directory"): self.assertEqual(path.read_bytes(), b"foreign")
                self.assert_unchanged_upstream(case, original)

    def test_cross_volume_before_publication_and_drift_before_replace(self):
        for fault in ("cross-volume", "changed-parent"):
            case, canonical, capability = self.scene()
            actual = refresh.handle_directory_identity
            calls = [0]
            def identity(path):
                calls[0] += 1
                volume, file_id = actual(path)
                if path == case and (fault == "cross-volume" or calls[0] >= 6): return volume+1, file_id
                return volume, file_id
            with patch.object(refresh, "handle_directory_identity", side_effect=identity), \
                    patch.object(refresh, "windows_replace_file") as replace_file, \
                    patch.object(writer, "_create_durable", wraps=writer._create_durable) as create:
                with self.assertRaises(writer.Epoch8TransitionError) as raised:
                    self.run_writer(case, canonical, capability)
            replace_file.assert_not_called(); self.assertEqual(canonical.read_bytes(), self.c7)
            self.assertIn("different NTFS volumes", str(raised.exception))
            self.assertFalse(raised.exception.outcome.receipt_written)
            if fault == "cross-volume": self.assertEqual(create.call_count, 0)

    def test_receipt_completion_faults_never_commit_or_overwrite(self):
        for fault in ("write", "flush", "fsync", "close", "refresh", "read", "bytes", "type", "path", "binding"):
            with self.subTest(fault=fault):
                case, canonical, capability = self.scene()
                rpath = case / transition.RECEIPT_NAME
                upstream = {name:(case/name).read_bytes() for name in ("activation-evidence.json", "issuance-receipt.json")}
                create, read, actual_open = writer._create_durable, writer._read, Path.open
                published = []
                class Stream:
                    def __init__(self, stream): self.stream = stream
                    def __enter__(self): self.stream.__enter__(); return self
                    def __exit__(self, *args):
                        value = self.stream.__exit__(*args)
                        if fault == "close": raise OSError("receipt close fault")
                        return value
                    def write(self, data):
                        if fault == "write": self.stream.write(data[:17]); return 0
                        return self.stream.write(data)
                    def flush(self):
                        self.stream.flush()
                        if fault == "flush": raise OSError("receipt flush fault")
                    def fileno(self): return self.stream.fileno()
                def opened(path, mode="r", *args, **kwargs):
                    stream = actual_open(path, mode, *args, **kwargs)
                    return Stream(stream) if path == rpath and mode == "xb" else stream
                def created(path, payload):
                    if path == rpath:
                        published.append(payload)
                        if fault == "fsync":
                            with patch.object(os, "fsync", side_effect=OSError("receipt fsync fault")): create(path,payload)
                            return
                        if fault == "refresh":
                            with patch.object(refresh, "windows_refresh_directory", side_effect=OSError("receipt refresh fault")): create(path,payload)
                            return
                    create(path, payload)
                    if path == rpath:
                        if fault == "bytes": path.write_bytes(payload[:17])
                        if fault == "type": path.unlink(); path.mkdir()
                        if fault == "path":
                            external = self.parent / ("external-"+str(uuid.uuid4())); external.write_bytes(payload)
                            path.unlink(); path.symlink_to(external)
                def reading(path):
                    if path == rpath and fault == "read": raise OSError("receipt read fault")
                    return read(path)
                with ExitStack() as seams:
                    seams.enter_context(patch.object(Path, "open", opened))
                    seams.enter_context(patch.object(writer, "_create_durable", side_effect=created))
                    seams.enter_context(patch.object(writer, "_read", side_effect=reading))
                    if fault == "binding":
                        seams.enter_context(patch.object(transition, "verify_committed_bytes", side_effect=ValueError("binding fault")))
                    with self.assertRaises(writer.Epoch8TransitionError) as raised:
                        self.run_writer(case, canonical, capability)
                self.assertEqual(raised.exception.outcome.status, writer.TRANSITION_INDETERMINATE)
                self.assertFalse(raised.exception.outcome.receipt_written)
                self.assertEqual(len(published), 1)
                self.assertNotEqual(canonical.read_bytes(), self.c7)
                self.assertFalse(Path(str(canonical)+".next").exists())
                self.assert_unchanged_upstream(case, upstream)
                if fault not in ("type", "path", "bytes", "write"):
                    self.assertEqual(rpath.read_bytes(), published[0])
                print("receipt completion fault verified:", fault, flush=True)

    def test_primary_and_failure_receipt_errors_both_preserved(self):
        case, canonical, capability = self.scene()
        create = writer._create_durable
        def failing(path,payload):
            if path.name.endswith(".next"): raise OSError("primary next failure")
            create(path,payload)
            if path.name == transition.RECEIPT_NAME: path.write_bytes(payload[:17])
        with patch.object(writer,"_create_durable",side_effect=failing):
            with self.assertRaises(writer.Epoch8TransitionError) as raised:
                self.run_writer(case,canonical,capability)
        self.assertIn("primary next failure",str(raised.exception))
        self.assertIn("failure receipt readback differs",str(raised.exception))
        self.assertFalse(raised.exception.outcome.receipt_written)
        self.assertEqual(canonical.read_bytes(),self.c7)
        self.assertEqual(raised.exception.outcome.status,writer.FAILED_BEFORE_REPLACE)


if __name__ == "__main__": unittest.main(verbosity=2)
