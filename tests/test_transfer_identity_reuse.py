"""Operation-scoped identity observation reuse in cancellable worker budgets.

A cancellable budget opens with one full observation; cancel checks reuse only
that observation while still re-reading protected state every time. Mutating
paths (_store without a reused observation) must keep observing fresh.
"""

import json
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from velo_transfer.errors import TransferContentError as Error
from velo_transfer import guest_service as guest_module
from velo_transfer.guest_service import GuestTransferService, request_digest
from velo_transfer.windows_platform import WindowsObservation


class IdentityReuseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.read = self.root / "read"
        self.write = self.root / "write"
        self.work = self.root / "work"
        for path in (self.read, self.write, self.work):
            path.mkdir(mode=0o700)
        self.uuid = str(uuid.uuid4())
        self.observation = WindowsObservation("Windows", self.uuid, "boot-fixture")
        self.limits = {"max_files": 100, "max_metadata_bytes": 100000,
                       "max_logical_bytes": 12 * 1024 * 1024,
                       "max_package_bytes": 14 * 1024 * 1024,
                       "min_free_bytes": 0, "max_chunk_bytes": 1 << 20,
                       "max_state_bytes": 65536, "max_duration_seconds": 60}
        self.policy = self.root / "policy.json"
        self.policy.write_text(json.dumps({"schema": "velo.transfer.policy.v1",
            "policy_id": "fixture", "expected_vm_uuid": self.uuid,
            "read_roots": [str(self.read)], "write_roots": [str(self.write)],
            "work_root": str(self.work), "limits": self.limits}))
        self.policy.chmod(0o600)
        self.calls = []
        self.observations = [self.observation]
        def counting_observe():
            self.calls.append(time.monotonic())
            return self.observations.pop(0) if self.observations else self.observation
        patcher = mock.patch.object(guest_module, "observe_windows", counting_observe)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.service = GuestTransferService(self.policy, _observation=None,
                                            _acl_verifier=lambda path, kind: True)
        self.addCleanup(self.service.shutdown)

    def push_request(self, transfer_id="trial"):
        payload = self.read / "payload.bin"
        payload.write_bytes(b"x" * 4096)
        value = {"protocol_version": "velo.transfer.v1", "transfer_id": transfer_id,
            "direction": "push",
            "sources": [{"absolute_path": str(payload), "relative_path": "payload.bin"}],
            "expected_destination": {"endpoint": "guest", "identity": {"test": "local"},
                                     "canonical_path": str(self.write / "dest")},
            "expected_vm_identity": {"vm_uuid": self.uuid, "boot_identity": "boot-fixture",
                                     "vm_epoch": "fixture-epoch"},
            "evidence_context": {"producer_complete": True, "producer_quiescent": True,
                                 "references": ["fixture-producer-record"]},
            "budget": {key: self.limits[key] for key in ("max_files", "max_metadata_bytes",
                "max_logical_bytes", "max_package_bytes", "min_free_bytes",
                "max_chunk_bytes", "max_duration_seconds")},
            "package": {"size": 4096, "sha256": "0" * 64, "manifest_sha256": "1" * 64}}
        value["request_digest"] = request_digest(value)
        return value

    def begun_state(self, request):
        self.service.transfer_begin(request)
        return self.service._load(request["transfer_id"],
                                  request["request_digest"])["state"]

    def test_cancel_closure_reuses_single_observation(self):
        req = self.push_request()
        state = self.begun_state(req)
        before = len(self.calls)
        budget = self.service._budget(state, cancel=True)
        opened = len(self.calls)
        self.assertEqual(opened - before, 1, "budget open must observe exactly once")
        for _ in range(25):
            budget.check()
        self.assertEqual(len(self.calls), opened,
                         "cancel checks must not re-observe identity")

    def test_cancel_still_reads_protected_state(self):
        req = self.push_request()
        state = self.begun_state(req)
        budget = self.service._budget(state, cancel=True)
        budget.check()
        store = self.service._store()
        with store.writer():
            envelope = self.service._load(req["transfer_id"], req["request_digest"], store)
            envelope["state"]["cancelled"] = True
            self.service._save(store, envelope, envelope["state"])
        with self.assertRaises(Error) as caught:
            budget.check()
        self.assertEqual(caught.exception.code, "transfer_cancelled")

    def test_deadline_exceeded_still_enforced(self):
        req = self.push_request()
        state = self.begun_state(req)
        state["deadline_monotonic"] = time.monotonic() - 1
        budget = self.service._budget(state, cancel=True)
        with self.assertRaises(Error) as caught:
            budget.check()
        self.assertEqual(caught.exception.code, "deadline_exceeded")

    def test_policy_tamper_detected_during_reuse(self):
        req = self.push_request()
        state = self.begun_state(req)
        budget = self.service._budget(state, cancel=True)
        budget.check()
        self.policy.write_text("{ not-json", encoding="utf-8")
        with self.assertRaises(Error):
            budget.check()

    def test_boot_change_rejected_at_next_operation_open(self):
        req = self.push_request()
        state = self.begun_state(req)
        budget = self.service._budget(state, cancel=True)
        budget.check()
        self.observations.append(WindowsObservation("Windows", self.uuid, "boot-changed"))
        with self.assertRaises(Error) as caught:
            self.service._budget(state, cancel=True)
        self.assertEqual(caught.exception.code, "vm_identity_mismatch")

    def test_store_path_observes_fresh_every_time(self):
        req = self.push_request()
        state = self.begun_state(req)
        budget = self.service._budget(state, cancel=True)
        budget.check()
        before = len(self.calls)
        for _ in range(3):
            self.service._store()
        self.assertEqual(len(self.calls) - before, 3,
                         "mutating store path must observe identity each time")

    def test_binding_conflict_detected_through_reuse(self):
        req = self.push_request()
        state = self.begun_state(req)
        budget = self.service._budget(state, cancel=True)
        budget.check()
        task_state = self.work / "tasks" / "trial" / "state.json"
        raw = json.loads(task_state.read_text(encoding="utf-8"))
        raw["binding"]["request_digest"] = "2" * 64
        task_state.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(Error) as caught:
            budget.check()
        self.assertIn(caught.exception.code,
                      ("task_binding_conflict", "state_changed", "invalid_state",
                       "state_hash_mismatch"))

    def test_sequential_operations_each_observe_once(self):
        req = self.push_request()
        state = self.begun_state(req)
        before = len(self.calls)
        first = self.service._budget(state, cancel=True)
        first.check()
        second = self.service._budget(state, cancel=True)
        second.check()
        self.assertEqual(len(self.calls) - before, 2,
                         "two worker operations need two fresh observations")


if __name__ == "__main__":
    unittest.main()
