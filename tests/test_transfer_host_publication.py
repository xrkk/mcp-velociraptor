"""Benign physical publication, recovery, and failure-boundary tests."""

import copy
import dataclasses
import hashlib
import json
import os
import shutil
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from velo_transfer.bundle import create_bundle, prepare_staging, unpack_bundle
from velo_transfer.errors import TransferContentError as Error
from velo_transfer.host_journal import HostJournal
from velo_transfer.host_publication import HostPublication
from velo_transfer import host_publication as publication_module
from velo_transfer import filesystem as filesystem_module
from velo_transfer.manifest import capture_sources, digest_json, directory_identity
from velo_transfer.protocol import prepare_receipt, receipt_digest
from velo_transfer.request import load_request, make_guest_request


@unittest.skipUnless(os.name == "posix", "Linux host publication fixture")
class HostPublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        if not getattr(self, "_source_empty", False):
            (self.source / "子").mkdir(mode=0o700)
            (self.source / "子" / "文件.txt").write_bytes(b"benign publication bytes")
            (self.source / "empty").mkdir(mode=0o700)
        self.delivery = self.root / "delivery"
        self.delivery.mkdir(mode=0o700)
        self.destination = self.delivery / "final"
        self.host = {"machine_id": "a" * 32, "boot_id": str(uuid.uuid4())}
        self.document = {"schema": "velo.transfer.request.v1", "direction": "pull",
            "sources": [{"absolute_path": "E:\\benign\\source", "relative_path": "payload"}],
            "destination_directory": str(self.destination),
            "connection_profile": "/missing/unused-profile.json",
            "expected_vm_identity": {"vm_uuid": str(uuid.uuid4()), "boot_identity": "boot-fixture",
                                     "vm_epoch": "epoch-fixture"},
            "evidence_context": {"producer_complete": True, "producer_quiescent": True,
                                 "references": ["fixture"]},
            "budget": {"max_files": 100, "max_metadata_bytes": 200000,
                       "max_logical_bytes": 1 << 20, "max_package_bytes": 1 << 20,
                       "max_chunk_bytes": 65536, "min_free_bytes": 0,
                       "max_duration_seconds": 60, "request_timeout_seconds": 10},
            "transfer_id": "publication-test"}
        self.spec = self.root / "request.json"
        self.spec.write_text(json.dumps(self.document))
        self.request = load_request(self.spec)
        self.journal = HostJournal(self.request, self.host)
        self.deadline = time.monotonic() + getattr(self, "_deadline_seconds", 55)
        self.budget = self.request.content_budget(self.deadline)
        self.source_specs = [{"absolute_path": str(self.source), "relative_path": "payload"}]
        self.manifest = capture_sources(self.source, self.source_specs, self.budget)
        self.bundle = self.root / "bundle.zip"
        self.package = create_bundle(self.source, self.source_specs, self.manifest,
                                    self.bundle, self.root, self.budget)
        self.descriptor = {"endpoint": "host", "identity": self.host,
                           "canonical_path": str(self.destination)}
        self.guest = make_guest_request(self.request, self.descriptor)
        self.binding = {"protocol_version": "velo.transfer.v1", "transfer_id": self.request.transfer_id,
            "request_digest": self.guest["request_digest"], "direction": "pull",
            **self.document["expected_vm_identity"], "policy_id": "fixture",
            "package_size": self.package["size"], "package_sha256": self.package["sha256"],
            "manifest_sha256": self.package["manifest_sha256"]}
        problem = getattr(self, "_initial_problem", None)
        if problem == "nonpull":
            self.binding["direction"] = "push"
        elif problem == "guest_digest":
            self.guest["request_digest"] = "0" * 64
        elif problem == "guest_vm":
            self.guest["expected_vm_identity"]["vm_epoch"] = "other-epoch"
        elif problem == "host_descriptor":
            self.guest["expected_destination"]["identity"]["machine_id"] = "b" * 32
        elif problem == "binding_digest":
            self.binding["request_digest"] = "0" * 64
        elif problem == "manifest_hash":
            self.binding["manifest_sha256"] = "0" * 64
        self.prepare = prepare_receipt(self.binding, digest_json(self.manifest))
        if problem == "prepare":
            self.prepare["prepare_id"] = "!"
        with self.journal.writer():
            self.journal.create(self.deadline, {"phase": "CREATED", "published_ever": False,
                "begin_attempted": False, "channel": None, "binding": self.binding,
                "guest_request": self.guest, "prepare_receipt": self.prepare,
                "unrelated": {"keep": "value"}})
            ref = self.journal.write_evidence("manifest", self.manifest)
            self.save(manifest_ref=ref)
            def register(path, identity, parent):
                self.save(staging={"staging_directory": path, "staging_identity": identity,
                    "parent_identity": parent, "destination_directory": str(self.destination)})
                return True
            stage = prepare_staging(self.destination, self.delivery, self.budget,
                stage_name=".velo-stage-fixture", register_stage=register)
            self.stage = Path(stage["staging_directory"])
            unpack_bundle(self.bundle, self.root, self.package["size"], self.package["sha256"],
                self.destination, self.delivery, self.budget, staging=stage)
        self.publication = HostPublication(self.journal)

    def save(self, **updates):
        envelope = self.journal.load()
        data = envelope["data"]
        data.update(copy.deepcopy(updates))
        return self.journal.save(envelope["revision"], data)

    def assert_code(self, code, action):
        with self.assertRaises(Error) as caught:
            action()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def resumed(self):
        self.document["resume"] = True
        self.spec.write_text(json.dumps(self.document))
        journal = HostJournal(load_request(self.spec), self.host)
        return journal, HostPublication(journal)

    def persist_intent_without_rename(self):
        with mock.patch.object(publication_module, "publish_directory",
                               side_effect=Error("injected_before_rename")):
            self.assert_code("injected_before_rename", self.publication.publish)
        state = self.journal.load()["data"]
        self.assertIn("publish_intent", state)
        self.assertFalse(state["published_ever"])
        self.assertFalse(self.destination.exists())
        return state["publish_intent"]

    def test_p1_real_bundle_stage_publish_replay_p5_and_copies(self):
        self.assertEqual(hashlib.sha256(self.bundle.read_bytes()).hexdigest(), self.binding["package_sha256"])
        with self.journal.writer():
            stage_id = directory_identity(self.stage)
            first = self.publication.publish()
            original = copy.deepcopy(first)
            self.assertEqual(first, self.publication.publish())
            first["publication_receipt"]["publication_id"] = "changed"
            first["reference"]["sha256"] = "0" * 64
            again = self.publication.publish()
            self.assertEqual(again, original)
            observed = self.publication.verify_published()
            self.assertEqual(observed["publication_receipt_sha256"], receipt_digest(original["publication_receipt"]))
            self.assertEqual(observed["directory_identity"], stage_id)
            self.assertEqual(observed["manifest_sha256"], self.binding["manifest_sha256"])
            self.assertEqual((self.destination / "payload" / "子" / "文件.txt").read_bytes(),
                             (self.source / "子" / "文件.txt").read_bytes())
            self.assertTrue((self.destination / "payload" / "empty").is_dir())
            self.assertTrue(self.source.exists())
            self.assertFalse(self.stage.exists())
            data = self.journal.load()["data"]
            self.assertEqual(data["phase"], "PUBLISHED")
            self.assertNotIn("completion", data)
            self.assertEqual(data["unrelated"], {"keep": "value"})
            self.assertEqual(self.journal.read_evidence(original["reference"]), original["publication_receipt"])
            observed["binding"]["vm_epoch"] = "changed"
            self.assertEqual(self.publication.verify_published()["binding"], self.binding)

    def test_p1_empty_source_directory_has_zero_published_files(self):
        self._source_empty = True
        self.__class__.setUp(self)
        with self.journal.writer():
            result = self.publication.publish()
            self.assertEqual(result["publication_receipt"]["directory_identity"],
                             directory_identity(self.destination))
            self.assertEqual(list((self.destination / "payload").iterdir()), [])
            self.assertEqual(self.publication.verify_published()["manifest_sha256"],
                             self.binding["manifest_sha256"])
            self.assertTrue(self.source.exists())

    def test_p2_writer_and_initial_contract_rejections(self):
        self.assert_code("writer_lock_required", self.publication.publish)
        self.assert_code("writer_lock_required", self.publication.verify_published)
        for problem, code in (("nonpull", "publication_binding_conflict"),
                              ("guest_digest", "publication_binding_conflict"),
                              ("guest_vm", "publication_binding_conflict"),
                              ("host_descriptor", "publication_binding_conflict"),
                              ("binding_digest", "publication_binding_conflict"),
                              ("prepare", "invalid_receipt_id"),
                              ("manifest_hash", "manifest_hash_mismatch")):
            with self.subTest(problem=problem):
                self._initial_problem = problem
                self.__class__.setUp(self)
                with self.journal.writer():
                    self.assert_code(code, self.publication.publish)
                    self.assertTrue(self.stage.exists())
                    self.assertFalse(self.destination.exists())
                    self.assertFalse(self.journal.load()["data"]["published_ever"])
        del self._initial_problem
        self.__class__.setUp(self)
        with self.journal.writer():
            original_stage = self.journal.load()["data"]["staging"]
            for change, code in (({"staging_directory": str(self.root / "outside")},
                                  "invalid_staging_ownership"),
                                 ({"staging_identity": {"device": 1, "inode": 2}},
                                  "destination_changed"),
                                 ({"parent_identity": {"device": 1, "inode": 2}},
                                  "destination_parent_changed")):
                with self.subTest(change=change):
                    self.save(staging={**original_stage, **change})
                    self.assert_code(code, self.publication.publish)
                    self.save(staging=original_stage)
            ref = self.journal.load()["data"]["manifest_ref"]
            self.save(manifest_ref={**ref, "sha256": "0" * 64})
            self.assert_code("evidence_changed", self.publication.publish)
            self.save(manifest_ref=ref)
            self.delivery.chmod(0o777)
            try:
                self.assert_code("untrusted_ancestor", self.publication.publish)
            finally:
                self.delivery.chmod(0o700)
            self.assertTrue(self.stage.exists())
            self.assertFalse(self.destination.exists())

    def test_p3_intent_and_rename_crash_recovery(self):
        with self.journal.writer():
            original_save = self.journal.save
            def fail_intent(revision, data):
                if data.get("publish_intent") is not None:
                    raise Error("injected_intent_persist_failure")
                return original_save(revision, data)
            with mock.patch.object(self.journal, "save", side_effect=fail_intent):
                self.assert_code("injected_intent_persist_failure", self.publication.publish)
            self.assertTrue(self.stage.exists())
            self.assertFalse(self.destination.exists())
            self.assertNotIn("publish_intent", self.journal.load()["data"])
            intent = self.persist_intent_without_rename()
            self.assertTrue(self.stage.exists())
            first = self.publication.publish()
            self.assertEqual(first["publication_receipt"], intent["publication"])
            self.assertEqual(self.publication.publish(), first)
            self.assertEqual(self.journal.load()["data"]["publish_intent"]["publication"]["publication_id"],
                             intent["publication"]["publication_id"])

    def test_p3_same_content_new_inode_and_stage_parent_conflicts(self):
        for mode in ("destination", "stage", "parent"):
            with self.subTest(mode=mode):
                # Isolated independent fixture per mutation.
                self.__class__.setUp(self)
                with self.journal.writer():
                    self.persist_intent_without_rename()
                    if mode == "destination":
                        shutil.copytree(self.stage, self.destination)
                    elif mode == "stage":
                        moved = self.root / "original-stage"
                        self.stage.rename(moved)
                        shutil.copytree(moved, self.stage)
                    else:
                        moved = self.root / "original-delivery"
                        self.delivery.rename(moved)
                        self.delivery.mkdir(mode=0o700)
                    with self.assertRaises(Error):
                        self.publication.publish()
                    self.assertNotIn("publication_receipt", self.journal.load()["data"])
                    self.assertTrue(self.source.exists())

    def test_p4_post_rename_failure_and_new_journal_recovery(self):
        for mode in ("lost_response", "verify_failure", "sync_failure", "evidence_save"):
            with self.subTest(mode=mode):
                self.__class__.setUp(self)
                with self.journal.writer():
                    if mode == "lost_response":
                        real = publication_module.publish_directory
                        def lost(*args, **kwargs):
                            real(*args, **kwargs)
                            raise Error("injected_lost_response", published=True)
                        patch = mock.patch.object(publication_module, "publish_directory", side_effect=lost)
                    elif mode == "verify_failure":
                        real = publication_module.verify_tree
                        def fail_after_rename(path, *args, **kwargs):
                            if Path(path) == self.destination:
                                raise Error("injected_destination_verify_failure")
                            return real(path, *args, **kwargs)
                        patch = mock.patch.object(publication_module, "verify_tree", side_effect=fail_after_rename)
                    elif mode == "sync_failure":
                        real = filesystem_module._fsync_directory
                        def fail_sync(path):
                            if Path(path) == self.delivery and self.destination.exists():
                                raise OSError("injected sync failure")
                            return real(path)
                        patch = mock.patch.object(filesystem_module, "_fsync_directory", side_effect=fail_sync)
                    else:
                        original_save = self.journal.save
                        def fail_receipt(revision, data):
                            if data.get("publication_receipt") is not None:
                                raise Error("injected_receipt_save_failure")
                            return original_save(revision, data)
                        patch = mock.patch.object(self.journal, "save", side_effect=fail_receipt)
                    with patch:
                        with self.assertRaises(Error):
                            self.publication.publish()
                    before = self.journal.load()
                    self.assertTrue(before["data"]["published_ever"])
                    self.assertTrue(self.destination.exists())
                    self.assertEqual(before["data"]["unrelated"], {"keep": "value"})
                    intent = before["data"]["publish_intent"]
                    deadline = before["deadline_monotonic"]
                    if mode == "evidence_save":
                        self.assertNotIn("publication_receipt", before["data"])
                        self.assertTrue((self.journal.task_dir / "evidence" / "publication_receipt.json").exists())
                resumed, publication = self.resumed()
                with resumed.writer():
                    recovered = publication.publish()
                    self.assertEqual(recovered["publication_receipt"], intent["publication"])
                    self.assertEqual(resumed.load()["deadline_monotonic"], deadline)
                    self.assertEqual(resumed.load()["data"]["unrelated"], {"keep": "value"})


    def test_recovery_retries_failed_parent_sync_before_receipt(self):
        original = filesystem_module._fsync_directory
        calls = []
        def fail_parent(path):
            if Path(path) == self.delivery and self.destination.exists():
                calls.append(str(path))
                raise OSError("injected continuing sync failure")
            return original(path)
        with self.journal.writer():
            with mock.patch.object(filesystem_module, "_fsync_directory", side_effect=fail_parent):
                for _ in range(2):
                    error = self.assert_code("post_publish_io_failed", self.publication.publish)
                    self.assertTrue(error.context["published"])
                    state = self.journal.load()["data"]
                    self.assertTrue(state["published_ever"])
                    self.assertNotIn("publication_receipt", state)
            self.assertEqual(len(calls), 2)
            expected = self.journal.load()["data"]["publish_intent"]["publication"]
            result = self.publication.publish()
            self.assertEqual(result["publication_receipt"], expected)


    def test_p5_rename_recovery_rejects_corrupted_published_tree(self):
        with self.journal.writer():
            real = publication_module.publish_directory
            def lose_after_rename(*args, **kwargs):
                real(*args, **kwargs)
                raise Error("injected_lost_response", published=True)
            with mock.patch.object(publication_module, "publish_directory",
                                   side_effect=lose_after_rename):
                self.assert_code("injected_lost_response", self.publication.publish)
            target = self.destination / "payload" / "子" / "文件.txt"
            target.write_bytes(b"X" * len(target.read_bytes()))
            with self.assertRaises(Error):
                self.publication.publish()
            state = self.journal.load()["data"]
            self.assertTrue(state["published_ever"])
            self.assertNotIn("publication_receipt", state)
            self.assertFalse(self.stage.exists())
            self.assertTrue(self.source.exists())

    def test_p5_fresh_destination_damage_and_no_republish(self):
        for mode in ("missing", "bytes", "extra", "fewer", "identity"):
            with self.subTest(mode=mode):
                self.__class__.setUp(self)
                with self.journal.writer():
                    first = self.publication.publish()
                    if mode == "missing":
                        shutil.rmtree(self.destination)
                    elif mode == "bytes":
                        target = self.destination / "payload" / "子" / "文件.txt"
                        target.write_bytes(b"X" * len(target.read_bytes()))
                    elif mode == "extra":
                        (self.destination / "unexpected.bin").write_bytes(b"x")
                    elif mode == "fewer":
                        (self.destination / "payload" / "子" / "文件.txt").unlink()
                    else:
                        moved = self.root / "published-original"
                        self.destination.rename(moved)
                        shutil.copytree(moved, self.destination)
                    with self.assertRaises(Error):
                        self.publication.verify_published()
                    with self.assertRaises(Error):
                        self.publication.publish()
                    state = self.journal.load()["data"]
                    self.assertTrue(state["published_ever"])
                    self.assertEqual(state["publication_receipt"], first["publication_receipt"])
                    self.assertNotIn("completion", state)
                    self.assertTrue(self.source.exists())

    def test_p6_unknown_both_absent_and_no_intent_conflict(self):
        with self.journal.writer():
            intent = self.persist_intent_without_rename()
            shutil.rmtree(self.stage)
            error = self.assert_code("publication_outcome_unknown", self.publication.publish)
            self.assertIsNone(error.context["published"])
            self.assertNotIn("publication_receipt", self.journal.load()["data"])
            self.assertEqual(self.journal.load()["data"]["publish_intent"], intent)
        self.__class__.setUp(self)
        shutil.copytree(self.stage, self.destination)
        with self.journal.writer():
            self.assert_code("destination_exists", self.publication.publish)
            self.assertNotIn("publish_intent", self.journal.load()["data"])

    def test_p7_deadline_budget_and_lost_return_replay(self):
        with self.journal.writer():
            original = self.request.content_budget
            def tightened(deadline):
                return dataclasses.replace(original(deadline), max_files=1)
            with mock.patch.object(type(self.request), "content_budget", side_effect=tightened):
                self.assert_code("file_count_exceeded", self.publication.publish)
            self.assertFalse(self.destination.exists())
            first = self.publication.publish()  # caller discards the first return
            ref = first["reference"]
            repeated = self.publication.publish()
            self.assertEqual(repeated, first)
            self.assertEqual(repeated["reference"], ref)
            self.assertEqual(len(list((self.journal.task_dir / "evidence").glob("publication_receipt.json"))), 1)
        resumed, publication = self.resumed()
        with resumed.writer():
            self.assertEqual(publication.publish(), first)
            self.assertEqual(resumed.read_evidence(ref), first["publication_receipt"])
        self._deadline_seconds = 1.0
        self.__class__.setUp(self)
        time.sleep(max(0, self.deadline - time.monotonic()) + 0.02)
        with self.journal.writer():
            saved = self.journal.load()["deadline_monotonic"]
            self.assert_code("invalid_deadline", self.publication.publish)
            self.assertEqual(self.journal.load()["deadline_monotonic"], saved)
            self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
