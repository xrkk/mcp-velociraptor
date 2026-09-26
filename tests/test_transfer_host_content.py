"""Benign physical host content preparation and failure-boundary checks."""

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

from velo_transfer.bundle import create_bundle
from velo_transfer.errors import TransferContentError as Error
from velo_transfer.host_content import HostContent
from velo_transfer.host_journal import HostJournal
from velo_transfer.host_partial import HostPartial
from velo_transfer.manifest import capture_sources
from velo_transfer.request import load_request, make_guest_request


@unittest.skipUnless(os.name == "posix", "Linux host content fixture")
class HostContentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        (self.source / "子").mkdir(mode=0o700)
        (self.source / "子" / "文件.txt").write_bytes(b"benign bytes")
        (self.source / "empty").mkdir(mode=0o700)
        self.second = self.root / "second.txt"
        self.second.write_bytes(b"other benign bytes")
        self.sibling = self.root / "unlisted.txt"
        self.sibling.write_bytes(b"private sibling")
        self.delivery = self.root / "delivery"
        self.delivery.mkdir(mode=0o700)
        self.destination = self.delivery / "final"
        self.host = {"machine_id": "a" * 32, "boot_id": str(uuid.uuid4())}
        self.deadline = time.monotonic() + 90
        self.document = {"schema": "velo.transfer.request.v1", "direction": "push",
            "sources": [{"absolute_path": str(self.source), "relative_path": "payload"},
                        {"absolute_path": str(self.second), "relative_path": "more.txt"}],
            "destination_directory": "E:\\benign\\final",
            "connection_profile": "/missing/unused-profile.json",
            "expected_vm_identity": {"vm_uuid": str(uuid.uuid4()),
                "boot_identity": "boot-fixture", "vm_epoch": "epoch-fixture"},
            "evidence_context": {"producer_complete": True, "producer_quiescent": True,
                                 "references": ["producer-ref"]},
            "budget": {"max_files": 100, "max_metadata_bytes": 200000,
                       "max_logical_bytes": 1 << 20, "max_package_bytes": 1 << 20,
                       "max_chunk_bytes": 65536, "min_free_bytes": 0,
                       "max_duration_seconds": 120, "request_timeout_seconds": 10},
            "transfer_id": "host-content-test"}
        self.spec = self.root / "request.json"

    def setup_journal(self, direction="push", *, resume=False, package=None,
                      initial_data_hook=None):
        self.document["direction"] = direction
        self.document["resume"] = resume
        if direction == "pull":
            self.document["sources"] = [{"absolute_path": "E:\\benign\\source",
                                         "relative_path": "payload"}]
            self.document["destination_directory"] = str(self.destination)
        self.spec.write_text(json.dumps(self.document))
        journal = HostJournal(load_request(self.spec), self.host)
        if resume:
            return journal, HostContent(journal)
        with journal.writer():
            data = {"phase": "CREATED", "published_ever": False,
                    "begin_attempted": False, "channel": None,
                    "unrelated": {"keep": "original"}}
            if direction == "pull":
                guest = make_guest_request(journal.request,
                    {"endpoint": "host", "identity": self.host,
                     "canonical_path": str(self.destination)})
                data["guest_request"] = guest
                data["binding"] = {"protocol_version": "velo.transfer.v1",
                    "transfer_id": journal.request.transfer_id,
                    "request_digest": guest["request_digest"], "direction": "pull",
                    **self.document["expected_vm_identity"], "policy_id": "fixture",
                    "package_size": package["size"], "package_sha256": package["sha256"],
                    "manifest_sha256": package["manifest_sha256"]}
            if initial_data_hook is not None:
                initial_data_hook(data)
            journal.create(self.deadline, data)
        return journal, HostContent(journal)

    def assert_code(self, code, call):
        with self.assertRaises(Error) as raised:
            call()
        self.assertEqual(raised.exception.code, code)

    def make_pull(self, *, invalid_zip=False, manifest_mismatch=False):
        budget = self.setup_budget()
        sources = [{"absolute_path": str(self.source), "relative_path": "payload"}]
        manifest = capture_sources(self.source.parent, sources, budget, ["producer-ref"])
        path = self.root / "producer.zip"
        package = create_bundle(self.source.parent, sources, manifest, path, self.root, budget)
        if invalid_zip:
            path.write_bytes(b"not a ZIP archive")
            package["size"] = path.stat().st_size
            package["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        if manifest_mismatch:
            package["manifest_sha256"] = "0" * 64
        journal, content = self.setup_journal("pull", package=package)
        with journal.writer():
            partial = HostPartial(journal, journal.load()["data"]["binding"])
            partial.initialize()
            raw = path.read_bytes()
            for offset in range(0, len(raw), 10000):
                chunk = raw[offset:offset + 10000]
                partial.append(offset, chunk, hashlib.sha256(chunk).hexdigest())
        return journal, content, package

    def setup_budget(self):
        from velo_transfer.manifest import Budget
        return Budget(100, 200000, 1 << 20, 1 << 20, 0, self.deadline)

    def test_c1_push_repeat_verify_and_no_sibling(self):
        journal, content = self.setup_journal()
        with journal.writer():
            first = content.prepare_push()
            self.assertEqual(set(first), {"package_path", "package", "manifest_ref", "ownership"})
            self.assertEqual(first["package"]["sha256"],
                hashlib.sha256(Path(first["package_path"]).read_bytes()).hexdigest())
            self.assertEqual(first, content.prepare_push())
            verified = content.verify_push_source()
            self.assertEqual(set(verified), {"identity_digest", "package", "manifest_ref", "ownership"})
            self.assertEqual(verified["identity_digest"], first["package"]["manifest_sha256"])
            manifest = journal.read_evidence(first["manifest_ref"])
            self.assertEqual(manifest["evidence_refs"], ["producer-ref"])
            self.assertEqual({e["path"] for e in manifest["entries"]},
                {"payload", "payload/子", "payload/子/文件.txt", "payload/empty", "more.txt"})
            first["package"]["size"] = -1
            self.assertGreater(content.prepare_push()["package"]["size"], 0)
            self.assertEqual(journal.load()["data"]["unrelated"], {"keep": "original"})
        self.assertEqual(self.sibling.read_bytes(), b"private sibling")
        self.assertEqual((self.source / "子" / "文件.txt").read_bytes(), b"benign bytes")

    def test_c2_source_changes_and_package_identity(self):
        journal, content = self.setup_journal()
        with journal.writer():
            first = content.prepare_push()
            original = journal.load()["data"]["manifest_ref"]
            target = self.source / "子" / "文件.txt"
            target.write_bytes(b"changed byte")
            self.assert_code("source_changed", content.verify_push_source)
            self.assertEqual(journal.load()["data"]["manifest_ref"], original)
            target.write_bytes(b"benign bytes")
            (self.source / "new").write_bytes(b"extra")
            self.assert_code("source_changed", content.prepare_push)
            (self.source / "new").unlink()
            # A new inode with the same bytes is not the captured source.
            target.unlink()
            target.write_bytes(b"benign bytes")
            self.assert_code("source_changed", content.prepare_push)
            package = Path(first["package_path"])
            package.unlink()
            package.write_bytes(b"tampered")
            self.assert_code("source_changed", content.verify_push_source)
            self.assertEqual(journal.load()["data"]["package"], first["package"])

    def test_c2_unknown_package_and_durability_gap(self):
        journal, content = self.setup_journal()
        with journal.writer():
            package = journal.task_dir / "push.zip"
            package.write_bytes(b"foreign")
            self.assert_code("host_package_reconcile_required", content.prepare_push)
            self.assertEqual(package.read_bytes(), b"foreign")
        other, content2 = self.setup_journal_fresh("second-content")
        with other.writer():
            with mock.patch("velo_transfer.host_content._sync_directory", side_effect=OSError("fault")):
                self.assert_code("host_package_durability_unknown", content2.prepare_push)
            self.assert_code("host_package_reconcile_required", content2.prepare_push)
            self.assertIsNone(other.load()["data"].get("package"))

    def setup_journal_fresh(self, transfer_id):
        self.document["transfer_id"] = transfer_id
        return self.setup_journal()

    def test_c2_unknown_links_and_registered_replacement(self):
        journal, content = self.setup_journal()
        with journal.writer():
            package = journal.task_dir / "push.zip"
            package.symlink_to(self.sibling)
            self.assert_code("host_package_reconcile_required", content.prepare_push)
            package.unlink()
            os.link(self.sibling, package)
            self.assert_code("host_package_reconcile_required", content.prepare_push)
            package.unlink()
            first = content.prepare_push()
            package.unlink()
            os.link(self.sibling, package)
            self.assert_code("host_package_ownership_conflict", content.prepare_push)
            self.assertEqual(journal.load()["data"]["package"], first["package"])

    def test_c3_pull_real_partial_and_repeat(self):
        journal, content, package = self.make_pull()
        with journal.writer():
            first = content.prepare_pull()
            self.assertEqual(set(first), {"staging", "package", "manifest_ref"})
            stage = Path(first["staging"]["staging_directory"])
            self.assertEqual((stage / "payload" / "子" / "文件.txt").read_bytes(), b"benign bytes")
            self.assertTrue((stage / "payload" / "empty").is_dir())
            self.assertEqual(first["package"]["sha256"], package["sha256"])
            self.assertEqual(first, content.prepare_pull())
            first["staging"]["staging_identity"]["inode"] = -1
            self.assertNotEqual(first, content.prepare_pull())
            self.assertFalse(self.destination.exists())
            self.assertEqual(journal.load()["data"]["unrelated"], {"keep": "original"})
        self.assertTrue(self.source.exists())

    def test_c4_partial_stage_resume_and_completed_corruption(self):
        journal, content, _ = self.make_pull()
        import velo_transfer.host_content as module
        def partial(*args, **kwargs):
            stage = Path(kwargs["staging"]["staging_directory"])
            (stage / "partial.txt").write_bytes(b"partial")
            raise Error("injected_extract_failure")
        with journal.writer():
            with mock.patch.object(module, "unpack_bundle", side_effect=partial):
                self.assert_code("injected_extract_failure", content.prepare_pull)
            stage = journal.load()["data"]["staging"]
            self.assertTrue((Path(stage["staging_directory"]) / "partial.txt").exists())
            self.assertFalse(journal.load()["data"]["host_pull"]["extraction_complete"])
        resumed, content2 = self.setup_journal("pull", resume=True)
        with resumed.writer():
            result = content2.prepare_pull()
            self.assertEqual(result["staging"]["staging_identity"], stage["staging_identity"])
            target = Path(stage["staging_directory"]) / "payload" / "子" / "文件.txt"
            target.write_bytes(b"bad")
            self.assert_code("tree_content_mismatch", content2.prepare_pull)
            self.assertEqual(target.read_bytes(), b"bad")
            data = resumed.load()["data"]
            data["publish_intent"] = {"fixture": True}
            resumed.save(resumed.load()["revision"], data)
            self.assert_code("publication_already_started", content2.prepare_pull)

    def test_c4_nested_partial_stage_resumes_with_same_identity_and_deadline(self):
        journal, content, package = self.make_pull()
        import velo_transfer.host_content as module

        def partial(*args, **kwargs):
            stage = Path(kwargs["staging"]["staging_directory"])
            parent = stage / "nested"
            parent.mkdir(mode=0o700)
            nested = parent / "inner"
            nested.mkdir(mode=0o700)
            (nested / "first.txt").write_bytes(b"first partial")
            (nested / "second.txt").write_bytes(b"second partial")
            (stage / "nested" / "peer.txt").write_bytes(b"peer partial")
            raise Error("injected_extract_failure")

        with journal.writer():
            with mock.patch.object(module, "unpack_bundle", side_effect=partial):
                self.assert_code("injected_extract_failure", content.prepare_pull)
            staging = journal.load()["data"]["staging"]
            stage = Path(staging["staging_directory"])
            inode = stage.stat().st_ino
            self.assertFalse(journal.load()["data"]["host_pull"]["extraction_complete"])

        resumed, content2 = self.setup_journal("pull", resume=True, package=package)
        with resumed.writer():
            self.assertEqual(resumed.load()["deadline_monotonic"], self.deadline)
            result = content2.prepare_pull()
            self.assertEqual(result["staging"], staging)
            self.assertEqual(stage.stat().st_ino, inode)
            self.assertFalse((stage / "nested").exists())
            self.assertEqual((stage / "payload" / "子" / "文件.txt").read_bytes(),
                             b"benign bytes")
            self.assertTrue((stage / "payload" / "empty").is_dir())
            self.assertEqual(result["package"]["sha256"], package["sha256"])
            self.assertEqual(resumed.load()["deadline_monotonic"], self.deadline)

    def test_c4_registered_link_rejects_without_deleting_other_content(self):
        journal, content, _ = self.make_pull()
        import velo_transfer.host_content as module
        with journal.writer():
            with mock.patch.object(module, "unpack_bundle", side_effect=Error("injected_extract_failure")):
                self.assert_code("injected_extract_failure", content.prepare_pull)
            stage = Path(journal.load()["data"]["staging"]["staging_directory"])
            (stage / "keep.txt").write_bytes(b"keep")
            (stage / "link").symlink_to(self.sibling)
            self.assert_code("link_or_reparse", content.prepare_pull)
            self.assertEqual((stage / "keep.txt").read_bytes(), b"keep")
            self.assertEqual(self.sibling.read_bytes(), b"private sibling")

    def test_c4_fifo_preflight_keeps_nested_content(self):
        journal, content, _ = self.make_pull()
        import velo_transfer.host_content as module
        with journal.writer():
            with mock.patch.object(module, "unpack_bundle", side_effect=Error("injected_extract_failure")):
                self.assert_code("injected_extract_failure", content.prepare_pull)
            stage = Path(journal.load()["data"]["staging"]["staging_directory"])
            nested = stage / "nested"
            nested.mkdir(mode=0o700)
            keep = nested / "keep.txt"
            keep.write_bytes(b"keep")
            fifo = stage / "pipe"
            os.mkfifo(fifo, mode=0o600)
            self.assert_code("stage_reconcile_required", content.prepare_pull)
            self.assertEqual(keep.read_bytes(), b"keep")
            self.assertTrue(fifo.exists())
            self.assertFalse(self.destination.exists())

    def test_c4_nested_directory_replacement_during_cleanup_is_preserved(self):
        journal, content, _ = self.make_pull()
        import velo_transfer.host_content as module
        with journal.writer():
            with mock.patch.object(module, "unpack_bundle", side_effect=Error("injected_extract_failure")):
                self.assert_code("injected_extract_failure", content.prepare_pull)
            stage = Path(journal.load()["data"]["staging"]["staging_directory"])
            nested = stage / "nested"
            nested.mkdir(mode=0o700)
            (nested / "keep.txt").write_bytes(b"keep")
            old = stage / "nested-old"
            original_identity = module.directory_identity
            observations = 0

            def replace_after_preflight(path):
                nonlocal observations
                if Path(path) == stage:
                    observations += 1
                    if observations == 2:
                        nested.rename(old)
                        nested.mkdir(mode=0o700)
                        (nested / "keep.txt").write_bytes(b"foreign")
                return original_identity(path)

            with mock.patch.object(module, "directory_identity", side_effect=replace_after_preflight):
                self.assert_code("stage_reconcile_required", content.prepare_pull)
            self.assertEqual(observations, 2)
            self.assertEqual((old / "keep.txt").read_bytes(), b"keep")
            self.assertEqual((nested / "keep.txt").read_bytes(), b"foreign")
            self.assertFalse(self.destination.exists())

    def test_c4_publication_receipt_rejects_reprepare(self):
        journal, content, _ = self.make_pull()
        with journal.writer():
            current = journal.load()
            data = current["data"]
            data["publication_receipt"] = {"fixture": "persisted"}
            journal.save(current["revision"], data)
            self.assert_code("publication_already_started", content.prepare_pull)
            self.assertIsNone(journal.load()["data"].get("staging"))
            self.assertFalse(self.destination.exists())

    def test_c4_published_ever_rejects_reprepare(self):
        journal, content, _ = self.make_pull()
        with journal.writer():
            current = journal.load()
            data = current["data"]
            data["published_ever"] = True
            journal.save(current["revision"], data)
            self.assert_code("publication_already_started", content.prepare_pull)
            self.assertIsNone(journal.load()["data"].get("staging"))
            self.assertFalse(self.destination.exists())

    def test_c5_wrong_direction_and_writer(self):
        journal, content = self.setup_journal()
        self.assert_code("writer_lock_required", content.prepare_push)
        with journal.writer():
            self.assert_code("invalid_direction", content.prepare_pull)
            envelope = journal.load()
            self.assertEqual(envelope["deadline_monotonic"], self.deadline)

    def test_c2_package_bytes_and_same_hash_new_inode(self):
        journal, content = self.setup_journal()
        with journal.writer():
            first = content.prepare_push()
            package = Path(first["package_path"])
            raw = package.read_bytes()
            package.write_bytes(b"X" + raw[1:])
            self.assert_code("host_package_ownership_conflict", content.prepare_push)
            package.unlink()
            package.write_bytes(raw)
            package.chmod(0o600)
            self.assert_code("host_package_ownership_conflict", content.verify_push_source)
            self.assertEqual(journal.load()["data"]["package"], first["package"])

    def test_c4_unregistered_stage_and_registered_hardlink(self):
        journal, content, _ = self.make_pull()
        stage_name = ".velo-stage-" + hashlib.sha256(journal.request.transfer_id.encode()).hexdigest()[:32]
        unknown = self.destination.parent / stage_name
        unknown.mkdir(mode=0o700)
        (unknown / "foreign.txt").write_bytes(b"foreign")
        with journal.writer():
            self.assert_code("stage_reconcile_required", content.prepare_pull)
            self.assertEqual((unknown / "foreign.txt").read_bytes(), b"foreign")
            self.assertIsNone(journal.load()["data"].get("staging"))
        (unknown / "foreign.txt").unlink()
        unknown.rmdir()
        import velo_transfer.host_content as module
        with journal.writer():
            with mock.patch.object(module, "unpack_bundle", side_effect=Error("injected_extract_failure")):
                self.assert_code("injected_extract_failure", content.prepare_pull)
            stage = Path(journal.load()["data"]["staging"]["staging_directory"])
            (stage / "keep.txt").write_bytes(b"keep")
            os.link(self.sibling, stage / "hardlink")
            self.assert_code("stage_reconcile_required", content.prepare_pull)
            self.assertEqual((stage / "keep.txt").read_bytes(), b"keep")
            self.assertEqual(self.sibling.read_bytes(), b"private sibling")

    def test_c5_pull_corrupt_received_package(self):
        journal, content, _ = self.make_pull()
        with journal.writer():
            partial = HostPartial(journal, journal.load()["data"]["binding"])
            path = partial.partial
            raw = path.read_bytes()
            path.write_bytes(b"X" + raw[1:])
            self.assert_code("partial_corrupt", content.prepare_pull)
            self.assertIsNone(journal.load()["data"].get("host_pull"))

    def test_c5_manifest_mismatch_keeps_incomplete_stage_and_facts(self):
        journal, content, _ = self.make_pull(manifest_mismatch=True)
        with journal.writer():
            self.assert_code("manifest_hash_mismatch", content.prepare_pull)
            envelope = journal.load()
            data = envelope["data"]
            self.assertEqual(envelope["deadline_monotonic"], self.deadline)
            self.assertEqual(data["unrelated"], {"keep": "original"})
            self.assertFalse(data["host_pull"]["extraction_complete"])
            self.assertIsNone(data.get("package"))
            self.assertIsNone(data.get("manifest_ref"))
            self.assertEqual(data["binding"]["manifest_sha256"], "0" * 64)
            self.assertTrue(Path(data["staging"]["staging_directory"]).is_dir())
            self.assertFalse(self.destination.exists())

    def test_c5_binding_and_destination_descriptor_conflicts(self):
        package = {"size": 1, "sha256": "1" * 64, "manifest_sha256": "2" * 64}
        def change_binding(data):
            data["binding"]["request_digest"] = "0" * 64
        journal, content = self.setup_journal("pull", package=package,
                                              initial_data_hook=change_binding)
        with journal.writer():
            self.assert_code("host_pull_binding_conflict", content.prepare_pull)
            self.assertIsNone(journal.load()["data"].get("host_pull"))

        self.document["transfer_id"] = "wrong-destination-descriptor"
        def change_path(data):
            data["guest_request"]["expected_destination"]["canonical_path"] = str(self.delivery / "other")
        journal, content = self.setup_journal("pull", package=package,
                                              initial_data_hook=change_path)
        with journal.writer():
            self.assert_code("host_pull_binding_conflict", content.prepare_pull)
            self.assertIsNone(journal.load()["data"].get("host_pull"))

    def test_c5_stage_preflight_budgets_keep_all_residue(self):
        journal, content, _ = self.make_pull()
        import velo_transfer.host_content as module
        from velo_transfer.manifest import Budget
        from velo_transfer.request import HostRequest
        with journal.writer():
            with mock.patch.object(module, "unpack_bundle", side_effect=Error("injected_extract_failure")):
                self.assert_code("injected_extract_failure", content.prepare_pull)
            stage = Path(journal.load()["data"]["staging"]["staging_directory"])
            nested = stage / "nested"
            nested.mkdir(mode=0o700)
            keep = nested / "keep.txt"
            keep.write_bytes(b"keep")
            (stage / "peer.txt").write_bytes(b"peer")
            observed = HostPartial(journal, journal.load()["data"]["binding"]).verify()
            with mock.patch.object(HostPartial, "verify", return_value=observed):
                for budget, code in ((Budget(1, 200000, 1 << 20, 1 << 20, 0, self.deadline),
                                      "file_count_exceeded"),
                                     (Budget(100, 1, 1 << 20, 1 << 20, 0, self.deadline),
                                      "metadata_budget_exceeded")):
                    with mock.patch.object(HostRequest, "content_budget", return_value=budget):
                        self.assert_code(code, content.prepare_pull)
                    self.assertEqual(keep.read_bytes(), b"keep")
                    self.assertEqual((stage / "peer.txt").read_bytes(), b"peer")
                    self.assertFalse(self.destination.exists())
            self.assertFalse(journal.load()["data"]["host_pull"]["extraction_complete"])

    def test_c4_destination_parent_replacement_rejected(self):
        journal, content, _ = self.make_pull()
        import velo_transfer.host_content as module
        with journal.writer():
            with mock.patch.object(module, "unpack_bundle", side_effect=Error("injected_extract_failure")):
                self.assert_code("injected_extract_failure", content.prepare_pull)
            old = self.root / "delivery-old"
            self.delivery.rename(old)
            self.delivery.mkdir(mode=0o700)
            self.assert_code("host_pull_state_conflict", content.prepare_pull)
            self.assertTrue((old / journal.load()["data"]["host_pull"]["stage_name"]).is_dir())

    def test_c5_fixed_hash_invalid_zip_and_disk_budget(self):
        journal, content, _ = self.make_pull(invalid_zip=True)
        with journal.writer():
            with mock.patch("velo_transfer.manifest.Budget.space", side_effect=Error("disk_budget_exceeded")):
                self.assert_code("disk_budget_exceeded", content.prepare_pull)
            self.assert_code("invalid_package", content.prepare_pull)
            data = journal.load()["data"]
            self.assertFalse(data["host_pull"]["extraction_complete"])
            self.assertIsNone(data.get("package"))
            self.assertIsNone(data.get("manifest_ref"))
            self.assertFalse(self.destination.exists())

    def test_c5_original_deadline_expires(self):
        journal, content = self.setup_journal()
        with journal.writer():
            with mock.patch("velo_transfer.request.time.monotonic", return_value=self.deadline + 1):
                self.assert_code("invalid_deadline", content.prepare_push)
            self.assertIsNone(journal.load()["data"].get("host_push"))

    def test_c2_explicit_source_parent_inode_replaced(self):
        selected = self.root / "selected"
        selected.mkdir(mode=0o700)
        self.source.rename(selected / "source")
        self.document["sources"][0]["absolute_path"] = str(selected / "source")
        journal, content = self.setup_journal()
        with journal.writer():
            first = content.prepare_push()
            old = self.root / "selected-old"
            selected.rename(old)
            selected.mkdir(mode=0o700)
            shutil.copytree(old / "source", selected / "source")
            self.assert_code("source_root_changed", content.prepare_push)
            self.assertEqual(journal.load()["data"]["package"], first["package"])

    def test_c4_registered_stage_inode_replaced(self):
        journal, content, _ = self.make_pull()
        import velo_transfer.host_content as module
        with journal.writer():
            with mock.patch.object(module, "unpack_bundle", side_effect=Error("injected_extract_failure")):
                self.assert_code("injected_extract_failure", content.prepare_pull)
            stage = Path(journal.load()["data"]["staging"]["staging_directory"])
            old = stage.with_name(stage.name + "-old")
            stage.rename(old)
            stage.mkdir(mode=0o700)
            self.assert_code("stage_reconcile_required", content.prepare_pull)
            self.assertTrue(stage.is_dir())
            self.assertTrue(old.is_dir())
