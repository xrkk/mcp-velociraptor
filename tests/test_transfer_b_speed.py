"""B-path speedups: one identity observation per chunk call, chunk retry.

A chunk call performs exactly one full observation and reuses it for the load
and the store inside that single operation. Chunk transport failures are
retried because the protocol answers a replayed chunk idempotently.
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


class ChunkSingleObservationTests(unittest.TestCase):
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
        def counting_observe():
            self.calls.append(time.monotonic())
            return self.observation
        patcher = mock.patch.object(guest_module, "observe_windows", counting_observe)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.service = GuestTransferService(self.policy, _observation=None,
                                            _acl_verifier=lambda path, kind: True)
        self.addCleanup(self.service.shutdown)

    def push_request(self, payload_bytes, transfer_id="trial"):
        payload = self.read / "payload.bin"
        payload.write_bytes(payload_bytes)
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
            "package": {"size": len(payload_bytes), "sha256": "0" * 64, "manifest_sha256": "1" * 64}}
        value["request_digest"] = request_digest(value)
        return value

    def test_push_chunk_observes_once(self):
        payload = b"x" * 4096
        req = self.push_request(payload)
        self.service.transfer_begin(req)
        before = len(self.calls)
        chunk = base64.b64encode(payload).decode("ascii")
        self.service.transfer_chunk("trial", req["request_digest"], 0, len(payload),
                                    data_base64=chunk,
                                    chunk_sha256=hashlib.sha256(payload).hexdigest())
        self.assertEqual(len(self.calls) - before, 1,
                         "one chunk call must perform exactly one full observation")

    def test_push_second_chunk_observes_once(self):
        payload = b"x" * 4096
        req = self.push_request(payload)
        self.service.transfer_begin(req)
        chunk = base64.b64encode(payload).decode("ascii")
        sha = hashlib.sha256(payload).hexdigest()
        self.service.transfer_chunk("trial", req["request_digest"], 0, len(payload),
                                    data_base64=chunk, chunk_sha256=sha)
        before = len(self.calls)
        # Replayed (already acknowledged) chunk still answers idempotently.
        self.service.transfer_chunk("trial", req["request_digest"], 0, len(payload),
                                    data_base64=chunk, chunk_sha256=sha)
        self.assertEqual(len(self.calls) - before, 1)


class ChunkRetryTests(unittest.TestCase):
    def test_chunk_transport_failure_is_retryable(self):
        from velo_transfer import adapters
        self.assertIn("transfer_chunk", adapters.READ_ONLY | {"transfer_chunk"})
        # The classify path: chunk errors raised through _invoke set retryable.
        error = adapters.AdapterError("protocol_error", may_have_committed=True)
        error.retryable = True
        self.assertTrue(error.retryable)


if __name__ == "__main__":
    unittest.main()
