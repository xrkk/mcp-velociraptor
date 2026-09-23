"""Deterministic terminal-protocol faults; no networking or filesystem claims."""

import copy
import unittest

from velo_transfer.errors import TransferContentError
from velo_transfer.protocol import (GuestTerminal, PROTOCOL_VERSION, prepare_receipt,
                                    publication_receipt, publish_intent, recover_publication,
                                    source_validation_receipt, validate_binding)


def binding(direction="pull"):
    return {"protocol_version": PROTOCOL_VERSION, "transfer_id": "benign-batch-1",
            "request_digest": "a" * 64, "direction": direction, "vm_uuid": "test-vm",
            "boot_identity": "boot-1", "vm_epoch": "epoch-1", "policy_id": "test-policy",
            "package_size": 100, "package_sha256": "b" * 64, "manifest_sha256": "c" * 64}


def destination(direction="pull"):
    return {"endpoint": "host" if direction == "pull" else "guest",
            "identity": {"machine": "host-1" if direction == "pull" else "test-vm"},
            "canonical_path": "/evidence/batch-1" if direction == "pull" else "E:\\evidence\\batch-1"}


class ProtocolTests(unittest.TestCase):
    def prepared(self, direction="pull"):
        state = GuestTerminal(binding(direction), destination(direction))
        operation = state.begin_action("prepare")
        receipt = prepare_receipt(state.binding, "d" * 64, "prepare-fixed")
        state.complete_prepare(operation["operation_id"], receipt)
        return state, receipt

    def assert_rejected_without_mutation(self, state, callback, code=None):
        before = state.snapshot()
        with self.assertRaises(TransferContentError) as caught:
            callback()
        if code:
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(state.snapshot(), before)

    def restored(self, state):
        return GuestTerminal.restore(state.snapshot(), state.binding, state.destination)

    def test_prepare_response_loss_replays_same_receipt_without_advancing(self):
        state, receipt = self.prepared()
        replay = self.restored(state).begin_action("prepare")
        self.assertEqual(replay["result"]["prepare_receipt"], receipt)
        self.assertEqual(state.local_phase, "SOURCE_PREPARED")
        self.assertIsNone(state.release_authorization)
        self.assertIsNone(state.publication)
        self.assert_rejected_without_mutation(state, lambda: state.begin_action("commit"), "action_not_allowed")

    def test_pull_publication_conflict_leaves_source_prepared(self):
        state, receipt = self.prepared()
        # Host publication fails. No release is sent to the guest.
        current = self.restored(state)
        self.assertEqual(current.local_phase, "SOURCE_PREPARED")
        self.assertIsNone(current.release_authorization)
        self.assertEqual(current.begin_action("prepare")["result"]["prepare_receipt"], receipt)

    def test_pull_release_requires_durable_authorization_and_preserves_tombstone(self):
        state, prepare = self.prepared()
        published = publication_receipt(state.binding, prepare, state.destination,
                                        {"device": 3, "inode": 4}, "publish-fixed")
        op = state.begin_action("release", prepare_receipt=prepare, publication_receipt=published)
        self.assert_rejected_without_mutation(state,
            lambda: state.complete_release(op["operation_id"], {"temporary_files_removed": True, "workers_stopped": True}),
            "release_not_authorized")
        state = self.restored(state)  # release request received, response lost, checks still needed
        self.assertEqual(state.local_phase, "SOURCE_PREPARED")
        auth = state.authorize_release(op["operation_id"])
        state = self.restored(state)  # cleanup authorized durably; later source changes irrelevant
        self.assertEqual(state.authorize_release(op["operation_id"]), auth)
        self.assert_rejected_without_mutation(state,
            lambda: state.fail_action("release", op["operation_id"], "source_changed"), "release_already_authorized")
        self.assert_rejected_without_mutation(state,
            lambda: state.complete_release(op["operation_id"], {"temporary_files_removed": False, "workers_stopped": True}),
            "cleanup_incomplete")
        state.complete_release(op["operation_id"], {"temporary_files_removed": True, "workers_stopped": True})
        recovered = self.restored(state)  # remote files deleted, final response lost
        replay = recovered.begin_action("release", prepare_receipt=prepare, publication_receipt=published)
        self.assertEqual(replay["operation_id"], op["operation_id"])
        self.assertEqual(replay["status"], "DONE")
        self.assertEqual(recovered.status()["state_scope"], "guest_source")
        self.assertEqual(recovered.status()["publication_evidence"], "host_reported_publication")
        self.assertEqual(recovered.local_phase, "SOURCE_RELEASED")
        self.assertNotIn("COMPLETE", repr(recovered.status()))

    def test_source_change_before_release_acceptance_retains_no_authorization(self):
        state, prepare = self.prepared()
        receipt = publication_receipt(state.binding, prepare, state.destination, {"device": 1, "inode": 2})
        op = state.begin_action("release", prepare_receipt=prepare, publication_receipt=receipt)
        state.fail_action("release", op["operation_id"], "source_changed")
        recovered = self.restored(state)
        self.assertEqual(recovered.local_phase, "SOURCE_CHANGED")
        self.assertIsNone(recovered.release_authorization)
        self.assertEqual(recovered.begin_action("release", prepare_receipt=prepare,
                         publication_receipt=receipt)["status"], "FAILED")
        self.assert_rejected_without_mutation(recovered,
            lambda: recovered.authorize_release(op["operation_id"]), "operation_mismatch")

    def test_push_commit_and_release_replay_are_distinct(self):
        state, prepare = self.prepared("push")
        validated = source_validation_receipt(state.binding, prepare, "e" * 64)
        commit = state.begin_action("commit", prepare_receipt=prepare, source_validation_receipt=validated)
        state = self.restored(state)
        receipt = publication_receipt(state.binding, prepare, state.destination, {"device": 1, "inode": 9})
        state.complete_commit(commit["operation_id"], receipt)
        state = self.restored(state)
        self.assertEqual(state.begin_action("commit", prepare_receipt=prepare,
                         source_validation_receipt=validated)["status"], "DONE")
        self.assertEqual(state.local_phase, "DEST_PUBLISHED")
        self.assertIsNone(state.release_authorization)
        wrong = dict(receipt, publication_id="another")
        self.assert_rejected_without_mutation(state,
            lambda: state.begin_action("release", prepare_receipt=prepare, publication_receipt=wrong),
            "receipt_binding_mismatch")
        release = state.begin_action("release", prepare_receipt=prepare, publication_receipt=receipt)
        state.authorize_release(release["operation_id"])
        state.complete_release(release["operation_id"], {"temporary_files_removed": True, "workers_stopped": True})
        state = self.restored(state)
        state.begin_action("commit", prepare_receipt=prepare, source_validation_receipt=validated)
        self.assertEqual(state.local_phase, "DEST_RELEASED")
        self.assertEqual(state.status()["publication_evidence"], "guest_verified_destination")

    def test_every_binding_field_and_target_rejected_even_terminal(self):
        state, prepare = self.prepared()
        receipt = publication_receipt(state.binding, prepare, state.destination, {"device": 1, "inode": 2})
        op = state.begin_action("release", prepare_receipt=prepare, publication_receipt=receipt)
        state.authorize_release(op["operation_id"])
        state.complete_release(op["operation_id"], {"temporary_files_removed": True, "workers_stopped": True})
        for field, value in state.binding.items():
            with self.subTest(field=field):
                wrong = copy.deepcopy(receipt)
                wrong["binding"][field] = value + 1 if isinstance(value, int) else value + "x"
                self.assert_rejected_without_mutation(state,
                    lambda: state.begin_action("release", prepare_receipt=prepare, publication_receipt=wrong))
        for section, field in (("destination", "canonical_path"), (None, "prepare_receipt_sha256"),
                                (None, "manifest_sha256"), (None, "publication_id")):
            wrong = copy.deepcopy(receipt)
            target = wrong[section] if section else wrong
            target[field] += "x"
            self.assert_rejected_without_mutation(state,
                lambda: state.begin_action("release", prepare_receipt=prepare, publication_receipt=wrong))
        self.assert_rejected_without_mutation(state,
            lambda: state.begin_action("prepare", unexpected=True), "invalid_action_input")

    def test_rename_crash_requires_intent_real_identity_and_all_content(self):
        state, prepare = self.prepared()
        intent = publish_intent(state.binding, prepare, state.destination,
                                {"device": 1, "inode": 2}, {"device": 1, "inode": 3}, "stable-publication")
        args = dict(verified_identity={"device": 1, "inode": 2}, verified_parent_identity={"device": 1, "inode": 3},
                    verified_manifest_sha256=state.binding["manifest_sha256"])
        result = recover_publication(intent, state.binding, prepare, state.destination, **args)
        self.assertEqual(result["publication_id"], "stable-publication")
        for key, value in (("verified_identity", {"device": 1, "inode": 99}),
                           ("verified_parent_identity", {"device": 1, "inode": 4}),
                           ("verified_manifest_sha256", "f" * 64)):
            with self.subTest(key=key), self.assertRaises(TransferContentError):
                recover_publication(intent, state.binding, prepare, state.destination, **dict(args, **{key: value}))

    def test_corrupt_snapshot_and_false_completion_are_rejected(self):
        state, _ = self.prepared()
        for key, value in (("local_phase", "SOURCE_RELEASED"), ("prepare_receipt", None),
                           ("release_authorization", {"operation_id": "invented"})):
            broken = state.snapshot(); broken[key] = value
            with self.subTest(key=key), self.assertRaises(TransferContentError):
                GuestTerminal.restore(broken, state.binding, state.destination)
        broken = state.snapshot()
        broken["operations"]["prepare"]["input_digest"] = "0" * 64
        with self.assertRaises(TransferContentError):
            GuestTerminal.restore(broken, state.binding, state.destination)
        different_epoch = dict(state.binding, vm_epoch="new-epoch")
        with self.assertRaises(TransferContentError):
            GuestTerminal.restore(state.snapshot(), different_epoch, state.destination)

    def test_in_progress_identity_survives_reload_and_outputs_are_copies(self):
        state = GuestTerminal(binding(), destination())
        pending = state.begin_action("prepare")
        restored = self.restored(state)
        self.assertEqual(restored.begin_action("prepare"), pending)
        pending["status"] = "DONE"
        self.assertEqual(restored.begin_action("prepare")["status"], "IN_PROGRESS")
        self.assert_rejected_without_mutation(restored,
            lambda: restored.complete_prepare("wrong-operation", prepare_receipt(state.binding, "d" * 64)),
            "operation_mismatch")

    def test_binding_and_receipt_types_are_strict(self):
        for value in (True, -1, 1.5, "100"):
            with self.subTest(value=value), self.assertRaises(TransferContentError):
                validate_binding(dict(binding(), package_size=value))
        with self.assertRaises(TransferContentError):
            prepare_receipt(binding(), "d" * 64, 0)


if __name__ == "__main__":
    unittest.main()
