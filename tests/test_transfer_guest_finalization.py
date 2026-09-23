"""Benign real-file and real-worker tests for push post-cleanup proof."""

import base64
import copy
import hashlib
import os
import shutil
import time
import unittest
from pathlib import Path
from unittest import mock

from tests import test_transfer_guest as guest_tests
from velo_transfer import capture_sources, create_bundle
from velo_transfer.errors import TransferContentError as Error
from velo_transfer.guest_service import GuestTransferService
from velo_transfer.protocol import publication_receipt, source_validation_receipt
from velo_transfer import guest_service as guest_module
from velo_transfer.guest_worker import same_process


@unittest.skipUnless(os.name == "posix", "isolated POSIX fork fixture")
class FinalizationTests(unittest.TestCase):
    budget = guest_tests.GuestTests.budget
    request = guest_tests.GuestTests.request
    wait_phase = guest_tests.GuestTests.wait_phase

    def setUp(self):
        guest_tests.GuestTests.setUp(self)

    def published_push(self, transfer_id="proof"):
        source = self.host / (transfer_id + "-source.bin")
        source.write_bytes(b"benign-finalization-" + transfer_id.encode())
        sources = [{"absolute_path": str(source), "relative_path": "content.bin"}]
        manifest = capture_sources(self.host, sources, self.budget())
        bundle = self.host / (transfer_id + ".zip")
        package = create_bundle(self.host, sources, manifest, bundle, self.host, self.budget())
        destination = self.write / (transfer_id + "-final")
        request = self.request("push", sources, destination,
            {key: package[key] for key in ("size", "sha256", "manifest_sha256")},
            transfer_id=transfer_id)
        self.service.transfer_begin(request)
        raw = bundle.read_bytes()
        for offset in range(0, len(raw), 1 << 20):
            chunk = raw[offset:offset + (1 << 20)]
            self.service.transfer_chunk(transfer_id, request["request_digest"], offset, len(chunk),
                base64.b64encode(chunk).decode(), hashlib.sha256(chunk).hexdigest())
        self.service.transfer_finish(transfer_id, request["request_digest"], "prepare")
        prepared = self.wait_phase(request, "DEST_PREPARED")
        prepare = prepared["terminal"]["prepare_receipt"]
        source_check = source_validation_receipt(prepare["binding"], prepare,
                                                   hashlib.sha256(b"host-check").hexdigest())
        self.service.transfer_finish(transfer_id, request["request_digest"], "commit",
            prepare_receipt=prepare, source_validation_receipt=source_check)
        published = self.wait_phase(request, "DEST_PUBLISHED")
        return request, destination, prepare, published["terminal"]["publication_receipt"], source

    def release(self, request, prepare, publication):
        return self.service.transfer_finish(request["transfer_id"], request["request_digest"],
            "release", prepare_receipt=prepare, publication_receipt=publication)

    def stopped_status(self, request):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            value = self.service.transfer_status(request["transfer_id"], request["request_digest"])
            if value["worker"] and value["worker"]["stopped"]:
                return value
            time.sleep(0.02)
        self.fail("release worker did not stop")

    def assert_authorized_unreleased(self, request, publication):
        status = self.stopped_status(request)
        self.assertEqual(status["local_phase"], "DEST_RELEASING")
        self.assertEqual(status["terminal"]["publication_receipt"], publication)
        self.assertIsNotNone(status["terminal"]["release_authorization"])
        self.assertEqual(status["terminal"]["operations"]["release"]["status"], "IN_PROGRESS")
        return status

    def test_v1_normal_proof_replay_and_response_copy(self):
        request, destination, prepare, publication, source = self.published_push()
        self.release(request, prepare, publication)
        status = self.wait_phase(request, "DEST_RELEASED")
        task = self.work / "tasks" / request["transfer_id"]
        self.assertFalse((task / "received.part").exists())
        self.assertFalse((task / "chunks.jsonl").exists())
        self.assertEqual((destination / "content.bin").read_bytes(), source.read_bytes())
        proof = status["destination_verification"]
        self.assertEqual(set(proof), {"schema", "binding", "release_operation_id",
            "publication_receipt_sha256", "directory_identity", "parent_identity",
            "manifest_sha256", "release_worker_nonce", "verification_phase"})
        self.assertEqual(proof["binding"], publication["binding"])
        self.assertEqual(proof["publication_receipt_sha256"], hashlib.sha256(
            guest_module.canonical_json(publication)).hexdigest())
        self.assertEqual(proof["directory_identity"], publication["directory_identity"])
        self.assertEqual(proof["verification_phase"], "post_cleanup")
        self.assertEqual(proof["release_worker_nonce"], status["worker"]["nonce"])
        self.assertTrue(status["worker"]["stopped"])
        proof["binding"]["vm_epoch"] = "mutated"
        self.assertEqual(self.release(request, prepare, publication)["operation"]["status"], "DONE")
        again = self.service.transfer_status(request["transfer_id"], request["request_digest"])
        self.assertEqual(again["destination_verification"]["binding"], publication["binding"])
        self.assertEqual(again["terminal"]["publication_receipt"], publication)

    def test_v2_changed_bytes_and_same_content_replacement_after_cleanup(self):
        for mode in ("bytes", "identity"):
            with self.subTest(mode=mode):
                request, destination, prepare, publication, source = self.published_push("changed-" + mode)
                original = GuestTransferService._verify_push_destination
                def corrupt_and_verify(service, state, terminal, budget):
                    if mode == "bytes":
                        target = destination / "content.bin"
                        target.write_bytes(b"X" * len(source.read_bytes()))
                    else:
                        moved = self.write / (request["transfer_id"] + "-old")
                        destination.rename(moved)
                        shutil.copytree(moved, destination)
                    return original(service, state, terminal, budget)
                with mock.patch.object(GuestTransferService, "_verify_push_destination", corrupt_and_verify):
                    self.release(request, prepare, publication)
                    status = self.assert_authorized_unreleased(request, publication)
                self.assertIsNone(status["destination_verification"])
                self.assertIn(status["error"], ("tree_content_mismatch", "destination_changed"))
                task = self.work / "tasks" / request["transfer_id"]
                self.assertFalse((task / "received.part").exists())
                self.assertFalse((task / "chunks.jsonl").exists())
                self.assertEqual(self.service.transfer_status(request["transfer_id"],
                    request["request_digest"])["local_phase"], "DEST_RELEASING")
                self.assertTrue(source.exists())

    def test_v3_partial_and_full_cleanup_crashes_resume_same_action(self):
        for mode in ("partial", "before_proof"):
            with self.subTest(mode=mode):
                request, destination, prepare, publication, source = self.published_push("crash-" + mode)
                task = self.work / "tasks" / request["transfer_id"]
                if mode == "partial":
                    original = GuestTransferService._remove_owned_temporary
                    def crash_after_first(service, state, name):
                        original(service, state, name)
                        if name == "received.part":
                            os._exit(77)
                    patch = mock.patch.object(GuestTransferService, "_remove_owned_temporary", crash_after_first)
                else:
                    patch = mock.patch.object(GuestTransferService, "_verify_push_destination",
                                              lambda *args: os._exit(78))
                with patch:
                    self.release(request, prepare, publication)
                    failed = self.assert_authorized_unreleased(request, publication)
                self.assertIsNone(failed["destination_verification"])
                self.assertTrue((task / "manifest.json").exists())
                self.assertEqual((destination / "content.bin").read_bytes(), source.read_bytes())
                if mode == "partial":
                    self.assertFalse((task / "received.part").exists())
                    self.assertTrue((task / "chunks.jsonl").exists())
                else:
                    self.assertFalse((task / "received.part").exists())
                    self.assertFalse((task / "chunks.jsonl").exists())
                old_nonce = failed["worker"]["nonce"]
                resumed = GuestTransferService(self.policy, _observation=self.observation,
                    _acl_verifier=lambda path, kind: True)
                self.addCleanup(resumed.shutdown)
                self.service = resumed
                self.release(request, prepare, publication)
                done = self.wait_phase(request, "DEST_RELEASED")
                self.assertNotEqual(done["worker"]["nonce"], old_nonce)
                self.assertEqual(done["destination_verification"]["release_worker_nonce"],
                                 done["worker"]["nonce"])
                self.assertEqual(done["terminal"]["publication_receipt"], publication)
                self.assertTrue(source.exists())

    def test_v4_proof_saved_before_stop_and_mutation_rejection(self):
        request, destination, prepare, publication, _ = self.published_push("saved-proof")
        original = GuestTransferService._save
        def crash_after_proof(service, store, envelope, state):
            saved = original(service, store, envelope, state)
            if (state["phase"] == "DEST_RELEASING" and
                    state.get("destination_verification") is not None and
                    state["owner"]["pid"] == os.getpid() and
                    not state["owner"]["stopped"]):
                os._exit(79)
            return saved
        with mock.patch.object(GuestTransferService, "_save", crash_after_proof):
            self.release(request, prepare, publication)
            done = self.wait_phase(request, "DEST_RELEASED")
        self.assertEqual(done["destination_verification"]["release_worker_nonce"],
                         done["worker"]["nonce"])
        self.assertEqual(done["terminal"]["publication_receipt"], publication)

        mutations = {
            "binding": lambda p: p["binding"].update(vm_epoch="wrong"),
            "receipt": lambda p: p.update(publication_receipt_sha256="0" * 64),
            "directory": lambda p: p["directory_identity"].update(inode=999999),
            "parent": lambda p: p["parent_identity"].update(inode=999999),
            "manifest": lambda p: p.update(manifest_sha256="0" * 64),
            "operation": lambda p: p.update(release_operation_id="wrong"),
            "nonce": lambda p: p.update(release_worker_nonce="wrong"),
            "phase": lambda p: p.update(verification_phase="before_cleanup"),
        }
        for kind, mutate in mutations.items():
            with self.subTest(kind=kind):
                req, dest, pre, pub, _ = self.published_push("tamper-" + kind)
                with mock.patch.object(GuestTransferService, "_save", crash_after_proof):
                    self.release(req, pre, pub)
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        raw = self.service._load(req["transfer_id"], req["request_digest"])["state"]
                        owner = raw["owner"]
                        if (raw.get("destination_verification") is not None and
                                not same_process(owner["pid"], owner["birth"])):
                            break
                        time.sleep(0.02)
                    else:
                        self.fail("proof not saved or worker not stopped")
                self.service._reconcile_exit(req["transfer_id"], req["request_digest"])
                store = self.service._store()
                with store.writer():
                    envelope = self.service._load(req["transfer_id"], req["request_digest"], store)
                    state = envelope["state"]
                    proof = copy.deepcopy(state["destination_verification"])
                    mutate(proof)
                    state["destination_verification"] = proof
                    store.save(req["transfer_id"], envelope["binding"], envelope["revision"], state)
                status = self.service.transfer_status(req["transfer_id"], req["request_digest"])
                self.assertEqual(status["local_phase"], "DEST_RELEASING")
                self.assertEqual(status["error"], "destination_verification_invalid")
                self.assertIsNotNone(status["terminal"]["release_authorization"])
                self.assertEqual(status["terminal"]["publication_receipt"], pub)

    def test_transient_writer_contention_preserves_proof_and_error(self):
        original_save = GuestTransferService._save
        for outcome in ("proof", "error"):
            with self.subTest(outcome=outcome):
                request, _, prepare, publication, _ = self.published_push("writer-" + outcome)
                attempts = {"count": 0}
                def contend_once(service, store, envelope, state):
                    selected = (state.get("destination_verification") is not None
                                if outcome == "proof" else
                                state.get("error") == "verification_injected_fault")
                    if selected and attempts["count"] == 0:
                        attempts["count"] += 1
                        raise Error("writer_busy")
                    return original_save(service, store, envelope, state)
                verification = (mock.patch.object(GuestTransferService,
                    "_verify_push_destination", side_effect=Error("verification_injected_fault"))
                    if outcome == "error" else mock.patch.object(GuestTransferService,
                    "_verify_push_destination", GuestTransferService._verify_push_destination))
                with mock.patch.object(GuestTransferService, "_save", contend_once), verification:
                    self.release(request, prepare, publication)
                    status = (self.wait_phase(request, "DEST_RELEASED") if outcome == "proof"
                              else self.assert_authorized_unreleased(request, publication))
                if outcome == "proof":
                    self.assertEqual(status["destination_verification"]["release_worker_nonce"],
                                     status["worker"]["nonce"])
                else:
                    self.assertEqual(status["error"], "verification_injected_fault")
                    self.assertIsNone(status["destination_verification"])

    def test_v5_worker_error_deadline_legacy_and_pull(self):
        request, destination, prepare, publication, _ = self.published_push("worker-error")
        with mock.patch.object(GuestTransferService, "_verify_push_destination",
                               side_effect=Error("verification_injected_fault")):
            self.release(request, prepare, publication)
            failed = self.assert_authorized_unreleased(request, publication)
        self.assertEqual(failed["error"], "verification_injected_fault")
        self.assertIsNone(failed["destination_verification"])
        store = self.service._store()
        with store.writer():
            envelope = self.service._load(request["transfer_id"], request["request_digest"], store)
            state = envelope["state"]
            state["deadline_monotonic"] = time.monotonic() - 1  # isolated expired-state injection
            store.save(request["transfer_id"], envelope["binding"], envelope["revision"], state)
        with self.assertRaises(Error) as caught:
            self.release(request, prepare, publication)
        self.assertEqual(caught.exception.code, "deadline_or_cancelled")
        expired = self.service.transfer_status(request["transfer_id"], request["request_digest"])
        self.assertEqual(expired["local_phase"], "DEST_RELEASING")
        self.assertIsNone(expired["destination_verification"])

        legacy, _, old_prepare, old_publication, _ = self.published_push("old-record")
        self.release(legacy, old_prepare, old_publication)
        self.wait_phase(legacy, "DEST_RELEASED")
        with store.writer():
            envelope = self.service._load(legacy["transfer_id"], legacy["request_digest"], store)
            state = envelope["state"]
            state["destination_verification"] = None  # isolated legacy-tombstone fixture
            store.save(legacy["transfer_id"], envelope["binding"], envelope["revision"], state)
        old = self.service.transfer_status(legacy["transfer_id"], legacy["request_digest"])
        self.assertEqual(old["local_phase"], "DEST_RELEASED")
        self.assertIsNone(old["destination_verification"])

        source = self.read / "pull-source.txt"
        source.write_bytes(b"pull-benign")
        pull = self.request("pull", [{"absolute_path": str(source),
            "relative_path": "pull-source.txt"}], self.host / "pull-final", transfer_id="pull-final")
        self.service.transfer_begin(pull)
        self.wait_phase(pull, "SOURCE_READY")
        self.service.transfer_finish(pull["transfer_id"], pull["request_digest"], "prepare")
        prepared = self.wait_phase(pull, "SOURCE_PREPARED")
        receipt = prepared["terminal"]["prepare_receipt"]
        publication = publication_receipt(receipt["binding"], receipt,
            pull["expected_destination"], {"device": 1, "inode": 2})
        self.release(pull, receipt, publication)
        released = self.wait_phase(pull, "SOURCE_RELEASED")
        self.assertIsNone(released["destination_verification"])
        self.assertEqual(released["terminal"]["publication_receipt"], publication)


if __name__ == "__main__":
    unittest.main()
