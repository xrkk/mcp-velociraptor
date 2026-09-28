"""Batched chunk protocol (transfer_chunks): guest-side semantics.

One observation, writer and journal save per batch; per-chunk budget, hash
and ledger records; strict sequential offsets; cancellation and malformed
batches fail closed; recovery stays on the existing partial-identity path.
"""

import base64
import hashlib
import json
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from velo_transfer import guest_service as guest_module
from velo_transfer.errors import TransferContentError as Error
from velo_transfer.guest_service import GuestTransferService, request_digest
from velo_transfer.windows_platform import WindowsObservation


class BatchChunkTests(unittest.TestCase):
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
                       "max_state_bytes": 65536, "max_duration_seconds": 60,
                       "max_batch_chunks": 8}
        self.policy = self.root / "policy.json"
        self.policy.write_text(json.dumps({"schema": "velo.transfer.policy.v1",
            "policy_id": "fixture", "expected_vm_uuid": self.uuid,
            "read_roots": [str(self.read)], "write_roots": [str(self.write)],
            "work_root": str(self.work), "limits": self.limits}))
        self.policy.chmod(0o600)
        self.calls = []
        def counting_observe():
            self.calls.append(time.monotonic())
            return self.observation
        patcher = mock.patch.object(guest_module, "observe_windows", counting_observe)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.service = GuestTransferService(self.policy, _observation=None,
                                            _acl_verifier=lambda path, kind: True)
        self.addCleanup(self.service.shutdown)

    def push_request(self, payload: bytes, transfer_id="trial"):
        payload_file = self.read / "payload.bin"
        payload_file.write_bytes(payload)
        value = {"protocol_version": "velo.transfer.v1", "transfer_id": transfer_id,
            "direction": "push",
            "sources": [{"absolute_path": str(payload_file), "relative_path": "payload.bin"}],
            "expected_destination": {"endpoint": "guest", "identity": {"test": "local"},
                                     "canonical_path": str(self.write / "dest")},
            "expected_vm_identity": {"vm_uuid": self.uuid, "boot_identity": "boot-fixture",
                                     "vm_epoch": "fixture-epoch"},
            "evidence_context": {"producer_complete": True, "producer_quiescent": True,
                                 "references": ["fixture-producer-record"]},
            "budget": {key: self.limits[key] for key in ("max_files", "max_metadata_bytes",
                "max_logical_bytes", "max_package_bytes", "min_free_bytes",
                "max_chunk_bytes", "max_duration_seconds")},
            "package": {"size": len(payload), "sha256": "0" * 64, "manifest_sha256": "1" * 64}}
        value["request_digest"] = request_digest(value)
        return value

    def batch(self, payload: bytes, offset: int, chunk_size: int):
        items = []
        position = offset
        while position < len(payload):
            count = min(chunk_size, len(payload) - position)
            raw = payload[position:position + count]
            items.append({"count": count,
                          "data_base64": base64.b64encode(raw).decode("ascii"),
                          "chunk_sha256": hashlib.sha256(raw).hexdigest()})
            position += count
        return items

    def test_push_batch_completes_and_observes_once(self):
        payload = bytes(range(256)) * 64  # 16 KiB
        req = self.push_request(payload)
        self.service.transfer_begin(req)
        digest = req["request_digest"]
        before = len(self.calls)
        response = self.service.transfer_chunks("trial", digest, 0, chunks=self.batch(payload, 0, 4096))
        self.assertEqual(response["verified_offset"], len(payload))
        self.assertEqual(response["accepted"], 4)
        self.assertEqual(len(self.calls) - before, 1,
                         "one batch must perform exactly one full observation")
        status = self.service.transfer_status("trial", digest)
        self.assertEqual(status["local_phase"], "DEST_RECEIVED")
        self.assertEqual(status["verified_offset"], len(payload))
        partial = self.work / "tasks" / "trial" / "received.part"
        self.assertEqual(partial.read_bytes(), payload)

    def test_push_batch_wrong_offset_rejected(self):
        payload = b"z" * 8192
        req = self.push_request(payload)
        self.service.transfer_begin(req)
        digest = req["request_digest"]
        with self.assertRaises(Error) as caught:
            self.service.transfer_chunks("trial", digest, 4096, chunks=self.batch(payload, 4096, 4096))
        self.assertEqual(caught.exception.code, "chunk_offset_conflict")

    def test_push_batch_hash_mismatch_rejected_without_advance(self):
        payload = b"a" * 8192
        req = self.push_request(payload)
        self.service.transfer_begin(req)
        digest = req["request_digest"]
        items = self.batch(payload, 0, 4096)
        items[1]["chunk_sha256"] = "0" * 64
        with self.assertRaises(Error) as caught:
            self.service.transfer_chunks("trial", digest, 0, chunks=items)
        self.assertEqual(caught.exception.code, "chunk_hash_mismatch")
        status = self.service.transfer_status("trial", digest)
        self.assertEqual(status["verified_offset"], 0,
                         "a failed batch must not advance the durable offset")

    def test_push_batch_cancel_fails_closed(self):
        payload = b"b" * 8192
        req = self.push_request(payload)
        self.service.transfer_begin(req)
        digest = req["request_digest"]
        # Simulate an external cancellation on protected state.
        store = self.service._store()
        with store.writer():
            envelope = self.service._load("trial", digest, store)
            envelope["state"]["cancelled"] = True
            self.service._save(store, envelope, envelope["state"])
        with self.assertRaises(Error) as caught:
            self.service.transfer_chunks("trial", digest, 0, chunks=self.batch(payload, 0, 4096))
        self.assertEqual(caught.exception.code, "transfer_cancelled")

    def test_push_batch_over_policy_limit_rejected(self):
        payload = b"c" * 4096
        req = self.push_request(payload)
        self.service.transfer_begin(req)
        items = [{"count": 1, "data_base64": base64.b64encode(b"x").decode("ascii"),
                  "chunk_sha256": hashlib.sha256(b"x").hexdigest()}] * 9  # > max_batch_chunks 8
        with self.assertRaises(Error) as caught:
            self.service.transfer_chunks("trial", req["request_digest"], 0, chunks=items)
        self.assertEqual(caught.exception.code, "invalid_chunk")

    def test_batch_requires_policy_grant(self):
        self.limits.pop("max_batch_chunks")
        policy2 = self.root / "policy2.json"
        policy2.write_text(json.dumps({"schema": "velo.transfer.policy.v1",
            "policy_id": "fixture", "expected_vm_uuid": self.uuid,
            "read_roots": [str(self.read)], "write_roots": [str(self.write)],
            "work_root": str(self.work), "limits": self.limits}))
        policy2.chmod(0o600)
        plain = GuestTransferService(policy2, _observation=None,
                                     _acl_verifier=lambda path, kind: True)
        self.addCleanup(plain.shutdown)
        payload = b"d" * 4096
        req = self.push_request(payload)
        plain.transfer_begin(req)
        with self.assertRaises(Error) as caught:
            plain.transfer_chunks("trial", req["request_digest"], 0,
                                  chunks=self.batch(payload, 0, 4096))
        self.assertEqual(caught.exception.code, "batch_not_allowed")


if __name__ == "__main__":
    unittest.main()
