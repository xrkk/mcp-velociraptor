"""Benign Linux filesystem tests for durable host pull package chunks."""

import copy
import hashlib
import json
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from velo_transfer.errors import TransferContentError as Error
from velo_transfer.host_journal import HostJournal
from velo_transfer.host_partial import HostPartial
from velo_transfer import host_partial as partial_module
from velo_transfer.request import load_request, make_guest_request


@unittest.skipUnless(os.name == "posix", "Linux host journal fixture")
class HostPartialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.spec = self.root / "request.json"
        self.host = {"machine_id": "a" * 32, "boot_id": str(uuid.uuid4())}
        self.document = {"schema": "velo.transfer.request.v1", "direction": "pull",
            "sources": [{"absolute_path": "E:\\source\\a.bin", "relative_path": "a.bin"}],
            "destination_directory": str(self.root / "published"),
            "connection_profile": "/missing/private-profile.json",
            "expected_vm_identity": {"vm_uuid": str(uuid.uuid4()), "boot_identity": "boot-1",
                                     "vm_epoch": "epoch-1"},
            "evidence_context": {"producer_complete": True, "producer_quiescent": True,
                                 "references": ["benign-fixture"]},
            "budget": {"max_files": 10, "max_metadata_bytes": 4096,
                       "max_logical_bytes": 1 << 34, "max_package_bytes": 1 << 35,
                       "min_free_bytes": 0, "max_chunk_bytes": 1024,
                       "max_duration_seconds": 60, "request_timeout_seconds": 10},
            "transfer_id": "host-partial-test"}

    def make(self, package=b"abcdef", *, resume=False, package_size=None, package_sha=None,
             direction=None, extra=None):
        self.document["resume"] = resume
        if direction:
            self.document["direction"] = direction
            if direction == "push":
                self.document["sources"] = [{"absolute_path": "/missing/a.bin", "relative_path": "a.bin"}]
                self.document["destination_directory"] = "E:\\published\\batch"
        self.spec.write_text(json.dumps(self.document))
        request = load_request(self.spec)
        destination = {"endpoint": "host" if request.document["direction"] == "pull" else "guest",
            "identity": {"fixture": "local"},
            "canonical_path": request.document["destination_directory"]}
        metadata = None if request.document["direction"] == "pull" else {
            "size": len(package), "sha256": hashlib.sha256(package).hexdigest(),
            "manifest_sha256": "b" * 64}
        guest = make_guest_request(request, destination, metadata)
        vm = request.document["expected_vm_identity"]
        binding = {"protocol_version": "velo.transfer.v1", "transfer_id": request.transfer_id,
            "request_digest": guest["request_digest"], "direction": request.document["direction"],
            "vm_uuid": vm["vm_uuid"], "boot_identity": vm["boot_identity"],
            "vm_epoch": vm["vm_epoch"], "policy_id": "fixture",
            "package_size": len(package) if package_size is None else package_size,
            "package_sha256": package_sha or hashlib.sha256(package).hexdigest(),
            "manifest_sha256": "b" * 64}
        journal = HostJournal(request, self.host)
        if not resume:
            with journal.writer():
                journal.create(time.monotonic() + 45, {"phase": "CREATED", "published_ever": False,
                    "begin_attempted": False, "channel": None, "guest_request": guest,
                    "binding": binding, "unrelated": {"keep": True}})
        return journal, HostPartial(journal, binding), binding

    def assert_code(self, code, call):
        with self.assertRaises(Error) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def test_h1_create_chunks_zero_verify_copy_and_binding(self):
        journal, partial, binding = self.make()
        self.assert_code("writer_lock_required", partial.initialize)
        with journal.writer():
            first = partial.initialize()
            self.assertEqual(first["verified_offset"], 0)
            self.assertEqual(partial.initialize(), first)
            first["ownership"]["directory"]["inode"] = -1
            a = partial.append(0, b"abc", hashlib.sha256(b"abc").hexdigest())
            b = partial.append(3, b"def", hashlib.sha256(b"def").hexdigest())
            self.assertEqual((a["verified_offset"], b["chunk_count"]), (3, 2))
            verified = partial.verify()
            self.assertEqual(verified["sha256"], binding["package_sha256"])
            self.assertEqual(verified["expected_manifest_sha256"], "b" * 64)
            verified["ownership"]["directory"]["inode"] = -1
            self.assertNotEqual(journal.load()["data"]["receive_partial"]["directory"]["inode"], -1)
            self.assertEqual(journal.load()["data"]["unrelated"], {"keep": True})
        resumed, fresh, _ = self.make(resume=True)
        with resumed.writer():
            self.assertEqual(fresh.resume()["verified_offset"], 6)

    def test_h1_zero_nonpull_and_request_conflict(self):
        self.document["transfer_id"] = "zero"
        journal, partial, _ = self.make(b"")
        with journal.writer():
            partial.initialize()
            self.assertEqual(partial.verify()["sha256"], hashlib.sha256(b"").hexdigest())
            data = journal.load()["data"]
            data["guest_request"]["request_digest"] = "0" * 64
            self.assert_code("immutable_fact_changed", lambda: journal.save(journal.load()["revision"], data))
        with self.assertRaises(Error):
            HostPartial(journal, {**partial.binding, "direction": "push"})
        self.document["transfer_id"] = "binding-conflict"
        conflict_journal, conflict_partial, _ = self.make()
        conflict_partial.binding["request_digest"] = "0" * 64
        with conflict_journal.writer():
            self.assert_code("partial_binding_conflict", conflict_partial.initialize)
        self.document["transfer_id"] = "push-test"
        self.assert_code("invalid_binding", lambda: self.make(direction="push"))

    def test_h2_replay_boundaries_and_failed_ack(self):
        journal, partial, _ = self.make()
        digest = hashlib.sha256(b"abc").hexdigest()
        with journal.writer():
            partial.initialize()
            partial.append(0, b"abc", digest)
            original = partial.ledger.stat().st_size
            self.assertEqual(partial.append(0, b"abc", digest)["verified_offset"], 3)
            self.assertEqual(partial.ledger.stat().st_size, original)
            for code, args in (("chunk_hash_mismatch", (3,b"def","0"*64)),
                               ("chunk_offset_conflict", (5,b"d",hashlib.sha256(b"d").hexdigest())),
                               ("chunk_offset_conflict", (1,b"bc",hashlib.sha256(b"bc").hexdigest())),
                               ("chunk_replay_conflict", (0,b"xyz",hashlib.sha256(b"xyz").hexdigest())),
                               ("chunk_budget_exceeded", (3,b"xxxx",hashlib.sha256(b"xxxx").hexdigest()))):
                self.assert_code(code, lambda args=args: partial.append(*args))
            for offset in (True, -1, 1 << 70):
                with self.assertRaises(Error):
                    partial.append(offset, b"a", hashlib.sha256(b"a").hexdigest())
            self.assertEqual(journal.load()["data"]["receive_partial"]["verified_offset"], 3)

    def test_h3_fault_boundaries_resume_and_corrupt_prefix(self):
        for failpoint in ("ledger", "journal"):
            with self.subTest(failpoint=failpoint):
                self.document["transfer_id"] = "fault-" + failpoint
                journal, partial, _ = self.make()
                with journal.writer():
                    partial.initialize()
                    partial.append(0,b"abc",hashlib.sha256(b"abc").hexdigest())
                    if failpoint == "ledger":
                        with partial.partial.open("ab") as stream:
                            stream.write(b"unacked")
                            stream.flush(); os.fsync(stream.fileno())
                    else:
                        with partial.partial.open("ab") as stream:
                            stream.write(b"def")
                            stream.flush(); os.fsync(stream.fileno())
                        with partial.ledger.open("ab") as stream:
                            stream.write(b'{"offset":3,"size":3,"sha256":"' + b"0"*64 + b'"}\n')
                            stream.flush(); os.fsync(stream.fileno())
                resumed, fresh, _ = self.make(resume=True)
                with resumed.writer():
                    self.assertEqual(fresh.resume()["verified_offset"], 3)
                    self.assertEqual(fresh.partial.stat().st_size, 3)
                    self.assertEqual(fresh.ledger.stat().st_size,
                        resumed.load()["data"]["receive_partial"]["ledger_bytes"])
                    with fresh.partial.open("r+b") as stream:
                        stream.seek(0); stream.write(b"X")
                    self.assert_code("partial_corrupt", fresh.resume)

    def test_h4_unknown_and_owned_replacement(self):
        journal, partial, _ = self.make()
        with journal.writer():
            partial.directory.mkdir(mode=0o700)
            self.assert_code("partial_reconcile_required", partial.initialize)
        self.document["transfer_id"] = "owned"
        journal, partial, _ = self.make()
        with journal.writer():
            partial.initialize()
            old = partial.partial
            moved = self.root / "moved"
            old.rename(moved)
            old.write_bytes(b"x")
            old.chmod(0o600)
            with self.assertRaises(Error):
                partial.resume()
            self.assertEqual(moved.read_bytes(), b"")
        self.document["transfer_id"] = "directory-replaced"
        journal, partial, _ = self.make()
        with journal.writer():
            partial.initialize()
            original_dir = self.root / "original-receive"
            partial.directory.rename(original_dir)
            partial.directory.mkdir(mode=0o700)
            self.assert_code("partial_ownership_conflict", partial.resume)
            self.assertTrue((original_dir / "received.part").exists())
        self.document["transfer_id"] = "linked"
        journal, partial, _ = self.make()
        with journal.writer():
            partial.initialize()
            link = self.root / "hardlink"
            os.link(partial.ledger, link)
            with self.assertRaises(Error):
                partial.resume()
            self.assertTrue(link.exists())

    def test_h5_deadline_metadata_disk_and_sparse_tail(self):
        self.document["transfer_id"] = "sparse"
        journal, partial, _ = self.make(b"abc")
        with journal.writer():
            partial.initialize()
            partial.append(0,b"abc",hashlib.sha256(b"abc").hexdigest())
            with partial.partial.open("r+b") as stream:
                stream.truncate((1 << 32) + 17)
                stream.flush(); os.fsync(stream.fileno())
            self.assertEqual(partial.resume()["verified_offset"], 3)
            self.assertEqual(partial.partial.stat().st_size, 3)
            self.assert_code("chunk_budget_exceeded", lambda: partial.append(1 << 70,b"x",hashlib.sha256(b"x").hexdigest()))
        self.document["transfer_id"] = "disk"
        self.document["budget"]["min_free_bytes"] = 1 << 50
        journal, partial, _ = self.make()
        with journal.writer():
            self.assert_code("disk_budget_exceeded", partial.initialize)

    def test_h6_verify_mismatch_and_io_failure(self):
        journal, partial, _ = self.make(b"abc", package_sha="0"*64)
        with journal.writer():
            partial.initialize()
            self.assert_code("package_incomplete", partial.verify)
            with mock.patch("velo_transfer.host_partial.os.fsync", side_effect=OSError("injected")):
                self.assert_code("partial_io_failed", lambda: partial.append(0,b"abc",hashlib.sha256(b"abc").hexdigest()))
            self.assertEqual(journal.load()["data"]["receive_partial"]["verified_offset"], 0)
            partial.resume()
            partial.append(0,b"abc",hashlib.sha256(b"abc").hexdigest())
            self.assert_code("package_hash_mismatch", partial.verify)
            self.assertTrue(partial.partial.exists())


    def test_h3_ledger_corruption_and_short_prefix_remain_intact(self):
        for kind in ("ledger", "short", "discontinuous"):
            with self.subTest(kind=kind):
                self.document["transfer_id"] = "corrupt-" + kind
                journal, partial, _ = self.make()
                digest = hashlib.sha256(b"abc").hexdigest()
                with journal.writer():
                    partial.initialize()
                    partial.append(0, b"abc", digest)
                    before = journal.load()["data"]["receive_partial"]
                    if kind == "ledger":
                        with partial.ledger.open("r+b") as stream:
                            stream.seek(0); stream.write(b"X")
                    elif kind == "short":
                        with partial.partial.open("r+b") as stream:
                            stream.truncate(1)
                    else:
                        raw = partial.ledger.read_bytes().replace(b'"offset":0', b'"offset":1')
                        partial.ledger.write_bytes(raw)
                    self.assert_code("partial_corrupt", partial.resume)
                    self.assertEqual(journal.load()["data"]["receive_partial"], before)
                    self.assertEqual(partial.ledger.stat().st_size, before["ledger_bytes"])

    def test_h4_registered_initialization_and_permissions(self):
        for phase in ("DIRECTORY", "PARTIAL"):
            with self.subTest(phase=phase):
                self.document["transfer_id"] = "init-" + phase.lower()
                journal, partial, _ = self.make()
                with journal.writer():
                    partial.directory.mkdir(mode=0o700)
                    directory = partial.directory.stat()
                    state = {"schema": "velo.transfer.host-partial.v1", "binding": partial.binding,
                             "phase": "DIRECTORY", "directory": {"path": str(partial.directory),
                             "device": directory.st_dev, "inode": directory.st_ino},
                             "partial": None, "ledger": None, "verified_offset": 0,
                             "chunk_count": 0, "ledger_bytes": 0}
                    if phase == "PARTIAL":
                        partial.partial.write_bytes(b"")
                        partial.partial.chmod(0o600)
                        info = partial.partial.stat()
                        state["partial"] = {"path": str(partial.partial),
                            "device": info.st_dev, "inode": info.st_ino, "size": 0,
                            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}
                        state["phase"] = "PARTIAL"
                    current = journal.load()
                    current["data"]["receive_partial"] = state
                    journal.save(current["revision"], current["data"])
                    self.assertEqual(partial.initialize()["verified_offset"], 0)
                    self.assertEqual(journal.load()["data"]["receive_partial"]["phase"], "READY")
        self.document["transfer_id"] = "permission"
        journal, partial, _ = self.make()
        with journal.writer():
            partial.initialize()
            partial.ledger.chmod(0o644)
            self.assert_code("partial_ownership_conflict", partial.resume)
            partial.ledger.chmod(0o600)
            moved = self.root / "ledger-moved"
            partial.ledger.rename(moved)
            partial.ledger.symlink_to(moved)
            self.assert_code("partial_ownership_conflict", partial.resume)
            self.assertTrue(moved.exists())
        self.document["transfer_id"] = "uid-observation"
        journal, partial, _ = self.make()
        with journal.writer():
            partial.initialize()
            state = journal.load()["data"]["receive_partial"]
            with mock.patch("velo_transfer.host_journal.os.geteuid", return_value=os.geteuid() + 1):
                self.assert_code("partial_ownership_conflict", lambda: partial._check_owned(state))

    def test_h5_expiry_and_metadata_limit(self):
        self.document["transfer_id"] = "deadline"
        self.spec.write_text(json.dumps(self.document))
        request = load_request(self.spec)
        guest = make_guest_request(request, {"endpoint": "host", "identity": {"fixture": "local"},
            "canonical_path": request.document["destination_directory"]})
        vm = request.document["expected_vm_identity"]
        binding = {"protocol_version": "velo.transfer.v1", "transfer_id": request.transfer_id,
            "request_digest": guest["request_digest"], "direction": "pull",
            "vm_uuid": vm["vm_uuid"], "boot_identity": vm["boot_identity"],
            "vm_epoch": vm["vm_epoch"], "policy_id": "fixture", "package_size": 1,
            "package_sha256": hashlib.sha256(b"x").hexdigest(), "manifest_sha256": "b"*64}
        journal = HostJournal(request, self.host)
        with journal.writer():
            journal.create(time.monotonic() + 0.02, {"phase": "CREATED",
                "published_ever": False, "begin_attempted": False, "channel": None,
                "guest_request": guest, "binding": binding})
        time.sleep(0.03)
        with journal.writer():
            self.assert_code("invalid_deadline", lambda: HostPartial(journal, binding).initialize())
        self.document["transfer_id"] = "metadata"
        journal, partial, _ = self.make(b"x" * 100)
        with journal.writer():
            partial.initialize()
            failed = False
            for offset in range(100):
                try:
                    partial.append(offset, b"x", hashlib.sha256(b"x").hexdigest())
                except Error as exc:
                    self.assertEqual(exc.code, "metadata_budget_exceeded")
                    self.assertEqual(journal.load()["data"]["receive_partial"]["verified_offset"], offset)
                    failed = True
                    break
            self.assertTrue(failed)

    def test_h6_read_time_replacement_rejected(self):
        journal, partial, _ = self.make(b"abc")
        with journal.writer():
            partial.initialize()
            partial.append(0, b"abc", hashlib.sha256(b"abc").hexdigest())
            original_open = partial_module._open
            calls = {"partial_reads": 0}
            def replace_during_hash(path, info, write=False):
                fd = original_open(path, info, write=write)
                if path == partial.partial and not write:
                    calls["partial_reads"] += 1
                    if calls["partial_reads"] == 2:
                        moved = self.root / "read-replaced"
                        partial.partial.rename(moved)
                        partial.partial.write_bytes(b"abc")
                        partial.partial.chmod(0o600)
                return fd
            with mock.patch.object(partial_module, "_open", side_effect=replace_during_hash):
                self.assert_code("partial_changed", partial.verify)
            self.assertEqual(calls["partial_reads"], 2)
            self.assertEqual(journal.load()["data"]["receive_partial"]["verified_offset"], 3)


    def test_chk_hp_001_created_file_and_directory_identity_are_not_adopted(self):
        for target in ("received.part", "chunks.jsonl"):
            with self.subTest(target=target):
                self.document["transfer_id"] = "creation-" + target.replace(".", "-")
                journal, partial, _ = self.make()
                selected = partial.partial if target == "received.part" else partial.ledger
                moved = self.root / (target + "-original")
                original_sync = partial_module._sync_directory
                swapped = {"done": False}
                def swap_at_sync(parent):
                    original_sync(parent)
                    if parent == partial.directory and selected.exists() and not swapped["done"]:
                        swapped["done"] = True
                        selected.rename(moved)
                        selected.write_bytes(b"FOREIGN-CONTENT")
                        selected.chmod(0o600)
                with journal.writer(), mock.patch.object(partial_module, "_sync_directory",
                                                        side_effect=swap_at_sync):
                    self.assert_code("partial_ownership_conflict", partial.initialize)
                    self.assertTrue(swapped["done"])
                    self.assertEqual(selected.read_bytes(), b"FOREIGN-CONTENT")
                    self.assertTrue(moved.exists())
                    self.assertEqual(journal.load()["data"]["receive_partial"]["phase"],
                                     "DIRECTORY" if target == "received.part" else "PARTIAL")
        self.document["transfer_id"] = "creation-directory"
        journal, partial, _ = self.make()
        old_directory = self.root / "created-directory-original"
        original_sync = partial_module._sync_directory
        def swap_directory(parent):
            original_sync(parent)
            if parent == journal.task_dir and partial.directory.exists():
                partial.directory.rename(old_directory)
                partial.directory.mkdir(mode=0o700)
        with journal.writer(), mock.patch.object(partial_module, "_sync_directory",
                                                side_effect=swap_directory):
            self.assert_code("partial_ownership_conflict", partial.initialize)
            self.assertTrue(old_directory.exists())
            self.assertNotIn("receive_partial", journal.load()["data"])

    def test_chk_hp_002_replay_rejects_same_bytes_new_inode_for_both_files(self):
        for target in ("received.part", "chunks.jsonl"):
            with self.subTest(target=target):
                self.document["transfer_id"] = "replay-" + target.replace(".", "-")
                journal, partial, _ = self.make()
                digest = hashlib.sha256(b"abc").hexdigest()
                with journal.writer():
                    partial.initialize()
                    partial.append(0, b"abc", digest)
                    before = journal.load()["data"]["receive_partial"]
                    selected = partial.partial if target == "received.part" else partial.ledger
                    moved = self.root / (target + "-replay-original")
                    original_replay = partial._replay
                    def swap_before_read(*args):
                        content = selected.read_bytes()
                        selected.rename(moved)
                        selected.write_bytes(content)
                        selected.chmod(0o600)
                        return original_replay(*args)
                    with mock.patch.object(partial, "_replay", side_effect=swap_before_read):
                        self.assert_code("partial_ownership_conflict",
                            lambda: partial.append(0, b"abc", digest))
                    self.assertEqual(journal.load()["data"]["receive_partial"], before)
                    self.assertNotEqual(selected.stat().st_ino, before["partial" if target == "received.part" else "ledger"]["inode"])

    def test_chk_hp_003_verify_rejects_tail_after_resume_even_matching_wrong_hash(self):
        for change in ("extra", "short", "modified"):
            with self.subTest(change=change):
                self.document["transfer_id"] = "verify-" + change
                package_hash = (hashlib.sha256(b"abcX").hexdigest() if change == "extra"
                                else hashlib.sha256(b"abc").hexdigest())
                journal, partial, binding = self.make(b"abc", package_sha=package_hash)
                with journal.writer():
                    partial.initialize()
                    partial.append(0, b"abc", hashlib.sha256(b"abc").hexdigest())
                    original_resume = partial.resume
                    def mutate_after_resume():
                        result = original_resume()
                        with partial.partial.open("r+b") as stream:
                            if change == "extra":
                                stream.seek(0, os.SEEK_END); stream.write(b"X")
                            elif change == "short":
                                stream.truncate(2)
                            else:
                                stream.seek(0); stream.write(b"X")
                        return result
                    with mock.patch.object(partial, "resume", side_effect=mutate_after_resume):
                        expected = "package_size_mismatch" if change != "modified" else "package_hash_mismatch"
                        self.assert_code(expected, partial.verify)
                    self.assertEqual(binding["package_size"], 3)
                    self.assertEqual(journal.load()["data"]["receive_partial"]["verified_offset"], 3)

    def test_chk_hp_004_open_and_pair_close_all_descriptors_on_fstat_failure(self):
        journal, partial, _ = self.make()
        with journal.writer():
            partial.initialize()
            for pair in (False, True):
                with self.subTest(pair=pair):
                    descriptors = []
                    actual_open = os.open
                    actual_fstat = os.fstat
                    calls = {"count": 0}
                    def record_open(*args, **kwargs):
                        fd = actual_open(*args, **kwargs)
                        descriptors.append(fd)
                        return fd
                    def fail_fstat(fd):
                        calls["count"] += 1
                        if calls["count"] == (2 if pair else 1):
                            raise OSError("injected observation failure")
                        return actual_fstat(fd)
                    pinfo = partial.partial.stat()
                    linfo = partial.ledger.stat()
                    with mock.patch.object(partial_module.os, "open", side_effect=record_open), mock.patch.object(
                            partial_module.os, "fstat", side_effect=fail_fstat):
                        if pair:
                            self.assert_code("partial_io_failed", lambda: partial_module._open_pair(
                                partial.partial, pinfo, partial.ledger, linfo))
                        else:
                            self.assert_code("partial_io_failed", lambda: partial_module._open(partial.partial, pinfo))
                    self.assertEqual(len(descriptors), 2 if pair else 1)
                    for fd in descriptors:
                        with self.assertRaises(OSError):
                            actual_fstat(fd)


if __name__ == "__main__":
    unittest.main()
