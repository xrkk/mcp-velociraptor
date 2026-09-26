"""Benign disk-backed host cleanup authorization and crash-window tests."""

import copy
import hashlib
import json
import os
import shutil
import time
import unittest
from pathlib import Path
from unittest import mock

from tests import test_transfer_host_coordinator as coordinator_tests
from velo_transfer.errors import TransferContentError
from velo_transfer.host_cleanup import HostCleanup
from velo_transfer.host_journal import HostJournal


class HostCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def fixture(self, direction="push", *, hold=True, duration=None):
        fixture = coordinator_tests.CoordinatorTests("test_c1_push_pull_one_call_real_host_files_and_resume")
        fixture.setUp()
        for cleanup, args, kwargs in fixture._cleanups:
            self.addCleanup(cleanup, *args, **kwargs)
        fixture._cleanups.clear()
        if duration is not None:
            fixture.document["budget"].update(max_duration_seconds=duration,
                                              request_timeout_seconds=min(duration, 10))
        if hold:
            with mock.patch("velo_transfer.host_coordinator.HostCleanup.clean",
                            side_effect=TransferContentError("fixture_hold")):
                summary = await fixture.run_transfer(direction)
            self.assertEqual((summary["outcome"], summary["exit_code"]), ("cleanup_pending", 5))
            self.assertTrue(fixture.result(summary)["published_ever"])
            self.assertTrue(fixture.journal_data()["guest_cleanup_complete"])
            self.assertFalse(fixture.journal_data()["host_cleanup_complete"])
        return fixture

    def clean(self, fixture, direction="push"):
        request = fixture.setup_request(direction, resume=True)
        journal = HostJournal(request, fixture.host)
        with journal.writer():
            return HostCleanup(journal).clean()

    def update(self, fixture, changes, direction="push"):
        request = fixture.setup_request(direction, resume=True)
        journal = HostJournal(request, fixture.host)
        with journal.writer():
            envelope = journal.load()
            data = envelope["data"]
            changes(data, journal)
            journal.save(envelope["revision"], data)

    def targets(self, fixture, direction="push"):
        data = fixture.journal_data()
        if direction == "push":
            return [Path(data["host_push"]["package_path"])]
        state = data["receive_partial"]
        return [Path(state["partial"]["path"]), Path(state["ledger"]["path"]),
                Path(state["directory"]["path"])]

    async def test_c1_complete_both_directions_real_deletion_and_idempotent_proof(self):
        for direction in ("push", "pull"):
            with self.subTest(direction=direction):
                fixture = await self.fixture(direction, hold=False)
                summary = await fixture.run_transfer(direction)
                result = fixture.result(summary)
                self.assertEqual((summary["outcome"], summary["exit_code"]), ("complete", 0))
                self.assertEqual(result["cleanup"], {"host": True, "guest": True})
                self.assertEqual(result["phase"], "COMPLETE")
                data = fixture.journal_data()
                self.assertEqual(data["phase"], "COMPLETE")
                self.assertEqual(data["completion"], {"destination_verified": True,
                    "guest_cleanup_complete": True, "host_cleanup_complete": True})
                self.assertTrue(all(not path.exists() for path in self.targets(fixture, direction)))
                self.assertEqual((fixture.source / "子" / "文件.txt").read_bytes(), b"benign bytes")
                self.assertEqual(fixture.sibling.read_bytes(), b"private sibling")
                roles = {item["role"]: item["reference"] for item in result["evidence_index"]}
                for role in ("publication_receipt", "guest_cleanup", "destination_verification", "host_cleanup"):
                    self.assertIn(role, roles)
                    evidence_path = Path(summary["result_path"]).parent / (roles[role]["name"] + ".json")
                    self.assertTrue(evidence_path.is_file())
                    evidence = json.loads(evidence_path.read_text())
                    if role == "guest_cleanup":
                        self.assertEqual(evidence["terminal"]["binding"], data["binding"])
                    else:
                        self.assertEqual(evidence["binding"], data["binding"])
                proof = copy.deepcopy(data["host_cleanup_intent"])
                calls = len(fixture.peer.trace)
                repeated = await fixture.run_transfer(direction, resume=True)
                self.assertEqual((repeated["outcome"], repeated["exit_code"]), ("complete", 0))
                self.assertEqual(fixture.journal_data()["host_cleanup_intent"], proof)
                self.assertTrue(all(not path.exists() for path in self.targets(fixture, direction)))
                self.assertEqual([op for op, _ in fixture.peer.trace[calls:]],
                                 ["transfer_status", "transfer_status"])
                if direction == "pull":
                    published = fixture.destination / "payload" / "子" / "文件.txt"
                    self.assertEqual(hashlib.sha256(published.read_bytes()).hexdigest(),
                                     hashlib.sha256(b"benign bytes").hexdigest())

    async def test_c2_missing_evidence_or_false_boolean_never_deletes_push(self):
        for variant in ("publication", "guest", "destination", "guest_false", "package_k", "adapter_pending"):
            with self.subTest(variant=variant):
                fixture = await self.fixture()
                package = self.targets(fixture)[0]
                def alter(data, _journal):
                    if variant == "publication":
                        del data["evidence"]["publication_receipt"]
                    elif variant == "guest":
                        del data["evidence"]["guest_cleanup"]
                    elif variant == "destination":
                        del data["evidence"]["destination_verification"]
                    elif variant == "guest_false":
                        data["guest_cleanup_complete"] = False
                    elif variant == "package_k":
                        data["package"]["sha256"] = "0" * 64
                    else:
                        data["adapter_cleanup_pending"] = True
                self.update(fixture, alter)
                with self.assertRaises(TransferContentError):
                    self.clean(fixture)
                self.assertTrue(package.is_file())
                self.assertIsNone(fixture.journal_data().get("host_cleanup_intent"))
                self.assertEqual((fixture.source / "子" / "文件.txt").read_bytes(), b"benign bytes")

    async def test_c2_worker_or_terminal_change_rejects_actual_gate(self):
        for variant in ("worker_running", "nonce", "releasing", "proof_nonce"):
            with self.subTest(variant=variant):
                fixture = await self.fixture()
                package = self.targets(fixture)[0]
                def alter(data, journal):
                    status = copy.deepcopy(data["guest_status"])
                    if variant == "worker_running":
                        status["worker"]["stopped"] = False
                    elif variant == "nonce":
                        status["worker"]["nonce"] = "other-nonce"
                    elif variant == "proof_nonce":
                        proof = copy.deepcopy(status["destination_verification"])
                        proof["release_worker_nonce"] = "other-nonce"
                        status["destination_verification"] = proof
                        data["evidence"]["destination_verification"] = journal.write_evidence(
                            "altered-proof-nonce", proof)
                    else:
                        status["local_phase"] = "DEST_RELEASING"
                    data["guest_status"] = status
                    data["evidence"]["guest_cleanup"] = journal.write_evidence(
                        "altered-guest-" + variant, status)
                self.update(fixture, alter)
                with self.assertRaises(TransferContentError):
                    self.clean(fixture)
                self.assertTrue(package.exists())
                self.assertIsNone(fixture.journal_data().get("host_cleanup_intent"))

    async def test_c3_push_registered_package_replacement_and_type_fail_closed(self):
        for variant in ("same_hash_new_inode", "changed_bytes", "hardlink", "symlink", "fifo", "missing"):
            with self.subTest(variant=variant):
                fixture = await self.fixture()
                package = self.targets(fixture)[0]
                original = package.read_bytes()
                displaced = package.with_name("displaced.zip")
                if variant == "same_hash_new_inode":
                    package.rename(displaced)
                    package.write_bytes(original)
                    package.chmod(0o600)
                elif variant == "changed_bytes":
                    with package.open("r+b") as stream:
                        stream.seek(0)
                        stream.write(b"X")
                elif variant == "hardlink":
                    os.link(package, displaced)
                elif variant == "symlink":
                    package.rename(displaced)
                    package.symlink_to(displaced)
                elif variant == "fifo":
                    package.rename(displaced)
                    os.mkfifo(package, mode=0o600)
                else:
                    package.unlink()
                with self.assertRaises(TransferContentError):
                    self.clean(fixture)
                self.assertFalse(fixture.journal_data().get("host_cleanup_complete", False))
                self.assertIsNone(fixture.journal_data().get("host_cleanup_intent"))
                if variant != "missing":
                    self.assertTrue(os.path.lexists(package))
                self.assertEqual((fixture.source / "子" / "文件.txt").read_bytes(), b"benign bytes")

    async def test_c3_pull_preflight_preserves_other_registered_objects(self):
        for variant in ("part_replaced", "ledger_replaced", "receive_replaced", "stage_reappeared", "unknown_member"):
            with self.subTest(variant=variant):
                fixture = await self.fixture("pull")
                partial, ledger, directory = self.targets(fixture, "pull")
                stage = Path(fixture.journal_data()["staging"]["staging_directory"])
                if variant == "part_replaced":
                    original = partial.read_bytes()
                    partial.rename(partial.with_name("displaced.part"))
                    partial.write_bytes(original)
                    partial.chmod(0o600)
                elif variant == "ledger_replaced":
                    original = ledger.read_bytes()
                    ledger.rename(ledger.with_name("displaced.ledger"))
                    ledger.write_bytes(original)
                    ledger.chmod(0o600)
                elif variant == "receive_replaced":
                    displaced = directory.with_name("displaced-receive")
                    directory.rename(displaced)
                    directory.mkdir(mode=0o700)
                    for name in ("received.part", "chunks.jsonl"):
                        replacement = directory / name
                        replacement.write_bytes((displaced / name).read_bytes())
                        replacement.chmod(0o600)
                elif variant == "stage_reappeared":
                    stage.mkdir(mode=0o700)
                    (stage / "sentinel").write_bytes(b"outside cleanup ownership")
                else:
                    (directory / "unknown").write_bytes(b"unregistered")
                with self.assertRaises(TransferContentError):
                    self.clean(fixture, "pull")
                self.assertFalse(fixture.journal_data().get("host_cleanup_complete", False))
                self.assertIsNone(fixture.journal_data().get("host_cleanup_intent"))
                self.assertTrue(directory.exists())
                if variant not in ("part_replaced", "receive_replaced"):
                    self.assertTrue(partial.exists())
                if variant not in ("ledger_replaced", "receive_replaced"):
                    self.assertTrue(ledger.exists())
                self.assertEqual((fixture.destination / "payload" / "子" / "文件.txt").read_bytes(),
                                 b"benign bytes")
                if variant == "stage_reappeared":
                    self.assertEqual((stage / "sentinel").read_bytes(), b"outside cleanup ownership")

    async def test_c3_replaced_task_parent_keeps_copied_and_original_receive(self):
        fixture = await self.fixture("pull")
        partial, ledger, directory = self.targets(fixture, "pull")
        task_parent = directory.parent.parent
        displaced = task_parent.with_name("tasks-displaced")
        task_parent.rename(displaced)
        shutil.copytree(displaced, task_parent, copy_function=shutil.copy2)
        with self.assertRaises(TransferContentError):
            self.clean(fixture, "pull")
        self.assertTrue(partial.exists())
        self.assertTrue(ledger.exists())
        self.assertTrue((displaced / directory.parent.name / "receive" / "received.part").exists())
        self.assertEqual((fixture.destination / "payload" / "子" / "文件.txt").read_bytes(),
                         b"benign bytes")

    async def test_c4_push_unlink_after_effect_recovers_missing_authorized_target(self):
        fixture = await self.fixture()
        package = self.targets(fixture)[0]
        original_unlink = os.unlink
        hit = {"done": False}
        def after_unlink(path, *args, **kwargs):
            if path == "push.zip" and not hit["done"]:
                hit["done"] = True
                original_unlink(path, *args, **kwargs)
                raise OSError("after unlink before acknowledge")
            return original_unlink(path, *args, **kwargs)
        with mock.patch("velo_transfer.host_cleanup.os.unlink", after_unlink):
            with self.assertRaisesRegex(TransferContentError, "host_cleanup_io_failed"):
                self.clean(fixture)
        self.assertTrue(hit["done"])
        self.assertFalse(package.exists())
        data = fixture.journal_data()
        self.assertIsNotNone(data["host_cleanup_intent"])
        self.assertFalse(data.get("host_cleanup_complete", False))
        proof = self.clean(fixture)
        self.assertTrue(proof["temporary_files_removed"])
        self.assertTrue(fixture.journal_data()["host_cleanup_complete"])
        self.assertEqual((fixture.source / "子" / "文件.txt").read_bytes(), b"benign bytes")

    async def test_c4_pull_partial_delete_then_replaced_ledger_rejected(self):
        fixture = await self.fixture("pull")
        partial, ledger, directory = self.targets(fixture, "pull")
        original_unlink = os.unlink
        def fail_ledger(path, *args, **kwargs):
            if path == "chunks.jsonl":
                raise OSError("before ledger unlink")
            return original_unlink(path, *args, **kwargs)
        with mock.patch("velo_transfer.host_cleanup.os.unlink", fail_ledger):
            with self.assertRaisesRegex(TransferContentError, "host_cleanup_io_failed"):
                self.clean(fixture, "pull")
        self.assertFalse(partial.exists())
        self.assertTrue(ledger.exists())
        self.assertTrue(directory.exists())
        self.assertIsNotNone(fixture.journal_data()["host_cleanup_intent"])
        old = ledger.read_bytes()
        ledger.rename(ledger.with_name("displaced-ledger"))
        ledger.write_bytes(old)
        ledger.chmod(0o600)
        with self.assertRaises(TransferContentError):
            self.clean(fixture, "pull")
        self.assertTrue(ledger.exists())
        self.assertTrue(directory.exists())
        self.assertEqual((fixture.destination / "payload" / "子" / "文件.txt").read_bytes(),
                         b"benign bytes")

    async def test_c4_pull_rmdir_after_effect_recovers(self):
        fixture = await self.fixture("pull")
        partial, ledger, directory = self.targets(fixture, "pull")
        original_rmdir = os.rmdir
        hit = {"done": False}
        def after_rmdir(path, *args, **kwargs):
            if path == "receive" and not hit["done"]:
                hit["done"] = True
                original_rmdir(path, *args, **kwargs)
                raise OSError("after rmdir before acknowledge")
            return original_rmdir(path, *args, **kwargs)
        with mock.patch("velo_transfer.host_cleanup.os.rmdir", after_rmdir):
            with self.assertRaisesRegex(TransferContentError, "host_cleanup_io_failed"):
                self.clean(fixture, "pull")
        self.assertTrue(hit["done"])
        self.assertTrue(all(not path.exists() for path in (partial, ledger, directory)))
        self.assertIsNotNone(fixture.journal_data()["host_cleanup_intent"])
        self.clean(fixture, "pull")
        self.assertTrue(fixture.journal_data()["host_cleanup_complete"])

    async def test_c4_unlink_before_effect_recovers_same_registered_package(self):
        fixture = await self.fixture()
        package = self.targets(fixture)[0]
        original_unlink = os.unlink
        def before_unlink(path, *args, **kwargs):
            if path == "push.zip":
                raise OSError("before unlink")
            return original_unlink(path, *args, **kwargs)
        with mock.patch("velo_transfer.host_cleanup.os.unlink", before_unlink):
            with self.assertRaisesRegex(TransferContentError, "host_cleanup_io_failed"):
                self.clean(fixture)
        self.assertTrue(package.is_file())
        self.assertIsNotNone(fixture.journal_data()["host_cleanup_intent"])
        self.clean(fixture)
        self.assertFalse(package.exists())

    async def test_c4_rmdir_before_effect_recovers_registered_empty_directory(self):
        fixture = await self.fixture("pull")
        partial, ledger, directory = self.targets(fixture, "pull")
        original_rmdir = os.rmdir
        def before_rmdir(path, *args, **kwargs):
            if path == "receive":
                raise OSError("before rmdir")
            return original_rmdir(path, *args, **kwargs)
        with mock.patch("velo_transfer.host_cleanup.os.rmdir", before_rmdir):
            with self.assertRaisesRegex(TransferContentError, "host_cleanup_io_failed"):
                self.clean(fixture, "pull")
        self.assertFalse(partial.exists())
        self.assertFalse(ledger.exists())
        self.assertTrue(directory.is_dir())
        self.clean(fixture, "pull")
        self.assertFalse(directory.exists())

    async def test_c4_parent_fsync_before_and_after_effect_recover(self):
        for when in ("before", "after"):
            with self.subTest(when=when):
                fixture = await self.fixture()
                package = self.targets(fixture)[0]
                original_fsync = os.fsync
                hit = {"done": False}
                def failed_fsync(fd):
                    if not package.exists() and not hit["done"]:
                        hit["done"] = True
                        if when == "after":
                            original_fsync(fd)
                        raise OSError("after unlink at parent fsync")
                    return original_fsync(fd)
                with mock.patch("velo_transfer.host_cleanup.os.fsync", failed_fsync):
                    with self.assertRaisesRegex(TransferContentError, "host_cleanup_io_failed"):
                        self.clean(fixture)
                self.assertTrue(hit["done"])
                self.assertFalse(package.exists())
                self.assertIsNotNone(fixture.journal_data()["host_cleanup_intent"])
                self.clean(fixture)
                self.assertTrue(fixture.journal_data()["host_cleanup_complete"])

    async def test_c5_destination_damage_after_cleanup_rejects_complete(self):
        fixture = await self.fixture("pull", hold=False)
        original_clean = HostCleanup.clean
        damaged = {"done": False}
        def after_clean(cleaner):
            proof = original_clean(cleaner)
            (fixture.destination / "payload" / "子" / "文件.txt").write_bytes(b"changed after cleanup")
            damaged["done"] = True
            return proof
        with mock.patch("velo_transfer.host_coordinator.HostCleanup.clean", after_clean):
            summary = await fixture.run_transfer("pull")
        self.assertTrue(damaged["done"])
        result = fixture.result(summary)
        self.assertEqual((summary["outcome"], summary["exit_code"]), ("conflict", 4))
        self.assertTrue(result["published_ever"])
        self.assertFalse(result["destination_verified"])
        self.assertTrue(result["cleanup"]["host"])
        self.assertTrue(all(not path.exists() for path in self.targets(fixture, "pull")))
        self.assertEqual((fixture.destination / "payload" / "子" / "文件.txt").read_bytes(),
                         b"changed after cleanup")

    async def test_c5_adapter_control_pending_survives_successful_host_scope(self):
        fixture = await self.fixture()
        package = self.targets(fixture)[0]
        self.update(fixture, lambda data, _: data.update(adapter_cleanup_pending=True))
        summary = await fixture.run_transfer(resume=True)
        self.assertEqual((summary["outcome"], summary["exit_code"]), ("cleanup_pending", 5))
        self.assertTrue(package.is_file())
        self.assertTrue(fixture.journal_data()["adapter_cleanup_pending"])
        self.assertFalse(fixture.journal_data()["host_cleanup_complete"])

    async def test_c5_coordinator_records_real_cleanup_failure_then_resumes(self):
        fixture = await self.fixture(hold=False)
        original_unlink = os.unlink
        def before_unlink(path, *args, **kwargs):
            if path == "push.zip":
                raise OSError("host cleanup before unlink")
            return original_unlink(path, *args, **kwargs)
        with mock.patch("velo_transfer.host_cleanup.os.unlink", before_unlink):
            first = await fixture.run_transfer()
        result = fixture.result(first)
        self.assertEqual((first["outcome"], first["exit_code"]), ("cleanup_pending", 5))
        self.assertIn("host_cleanup_io_failed", result["warnings"])
        self.assertTrue(self.targets(fixture)[0].exists())
        data = fixture.journal_data()
        self.assertIsNotNone(data["host_cleanup_intent"])
        self.assertIn("host_cleanup_failure", data["evidence"])
        self.assertFalse(data["host_cleanup_complete"])
        resumed = await fixture.run_transfer(resume=True)
        self.assertEqual((resumed["outcome"], resumed["exit_code"]), ("complete", 0))
        self.assertFalse(self.targets(fixture)[0].exists())

    async def test_c5_late_adapter_pending_cannot_reuse_prior_complete_claim(self):
        fixture = await self.fixture(hold=False)
        first = await fixture.run_transfer()
        self.assertEqual(first["outcome"], "complete")
        old_proof = copy.deepcopy(fixture.journal_data()["evidence"]["host_cleanup"])
        self.update(fixture, lambda data, _: data.update(adapter_cleanup_pending=True))
        resumed = await fixture.run_transfer(resume=True)
        self.assertNotEqual(resumed["outcome"], "complete")
        self.assertTrue(fixture.journal_data()["adapter_cleanup_pending"])
        self.assertEqual(fixture.journal_data()["evidence"]["host_cleanup"], old_proof)
        self.assertFalse(self.targets(fixture)[0].exists())

    async def test_c5_result_evidence_failure_has_no_complete_or_path(self):
        fixture = await self.fixture(hold=False)
        original = HostJournal.write_evidence
        def failed_result(journal, name, value):
            if name.startswith("result-"):
                raise TransferContentError("evidence_write_failed")
            return original(journal, name, value)
        with mock.patch.object(HostJournal, "write_evidence", failed_result):
            with self.assertRaisesRegex(TransferContentError, "evidence_write_failed"):
                await fixture.run_transfer()
        data = fixture.journal_data()
        self.assertTrue(data["host_cleanup_complete"])
        self.assertNotEqual(data["phase"], "COMPLETE")
        self.assertIsNone(data.get("result_ref"))
        resumed = await fixture.run_transfer(resume=True)
        self.assertEqual((resumed["outcome"], resumed["exit_code"]), ("complete", 0))

    async def test_c5_final_cas_failure_does_not_publish_complete(self):
        fixture = await self.fixture(hold=False)
        original = HostJournal.save
        def failed_final(journal, revision, data):
            if data.get("phase") == "COMPLETE":
                raise TransferContentError("stale_revision")
            return original(journal, revision, data)
        with mock.patch.object(HostJournal, "save", failed_final):
            with self.assertRaisesRegex(TransferContentError, "stale_revision"):
                await fixture.run_transfer()
        data = fixture.journal_data()
        self.assertTrue(data["host_cleanup_complete"])
        self.assertNotEqual(data["phase"], "COMPLETE")
        self.assertIsNone(data.get("result_ref"))
        resumed = await fixture.run_transfer(resume=True)
        self.assertEqual((resumed["outcome"], resumed["exit_code"]), ("complete", 0))

    async def test_c5_deadline_expires_after_actual_cleanup_before_complete(self):
        fixture = await self.fixture(hold=False, duration=1)
        original = HostCleanup.clean
        completed = {"done": False}
        def after_cleanup(cleaner):
            proof = original(cleaner)
            completed["done"] = True
            time.sleep(1.1)
            return proof
        with mock.patch("velo_transfer.host_coordinator.HostCleanup.clean", after_cleanup):
            summary = await fixture.run_transfer()
        self.assertTrue(completed["done"])
        result = fixture.result(summary)
        self.assertEqual(summary["outcome"], "incomplete")
        self.assertIn("deadline_exceeded", result["warnings"])
        self.assertTrue(result["cleanup"]["host"])
        self.assertNotEqual(fixture.journal_data()["phase"], "COMPLETE")
        self.assertFalse(self.targets(fixture)[0].exists())
        deadline = fixture.journal_envelope()["deadline_monotonic"]
        repeated = await fixture.run_transfer(resume=True)
        self.assertEqual(repeated["outcome"], "incomplete")
        self.assertEqual(fixture.journal_envelope()["deadline_monotonic"], deadline)

    async def test_c6_source_change_after_guest_release_does_not_reinterpret_snapshot(self):
        fixture = await self.fixture(hold=False)
        original = HostCleanup.clean
        changed = {"done": False}
        def before_cleanup(cleaner):
            source = fixture.source / "子" / "文件.txt"
            source.write_bytes(b"new source after authorized release")
            changed["done"] = True
            return original(cleaner)
        with mock.patch("velo_transfer.host_coordinator.HostCleanup.clean", before_cleanup):
            summary = await fixture.run_transfer()
        self.assertTrue(changed["done"])
        self.assertEqual((summary["outcome"], summary["exit_code"]), ("complete", 0))
        self.assertEqual((fixture.source / "子" / "文件.txt").read_bytes(),
                         b"new source after authorized release")
        self.assertFalse(self.targets(fixture)[0].exists())
        self.assertEqual(fixture.result(summary)["source_stability"], "stable_at_required_check")
