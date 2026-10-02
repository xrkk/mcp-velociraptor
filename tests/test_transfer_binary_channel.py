"""Binary chunk channel: frame round-trip and endpoint semantics."""

import base64
import hashlib
import json
import tempfile
import unittest
import uuid
from pathlib import Path

from velo_transfer import guest_service as guest_module
from velo_transfer.adapters import _parse_vbt, _header_bytes, _VBT_MAGIC
from velo_transfer.guest_service import GuestTransferService, request_digest
from velo_transfer.windows_platform import WindowsObservation


class FrameTests(unittest.TestCase):
    def test_roundtrip(self):
        header = {"status": "success", "result": {"chunks": [{"count": 3}]}}
        body = _VBT_MAGIC + _header_bytes(header).__len__().to_bytes(4, "little") + _header_bytes(header) + b"abc"
        parsed, payload = _parse_vbt(body)
        self.assertEqual(parsed, header)
        self.assertEqual(payload, b"abc")

    def test_rejects_bad_magic_and_header(self):
        with self.assertRaises(Exception):
            _parse_vbt(b"XXXX" + (5).to_bytes(4, "little") + b"{}")
        with self.assertRaises(Exception):
            _parse_vbt(_VBT_MAGIC + (1 << 30).to_bytes(4, "little"))


class EndpointTests(unittest.TestCase):
    def _service(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        for name in ("read", "write", "work"):
            (root / name).mkdir(mode=0o700)
        self.uuid = str(uuid.uuid4())
        limits = {"max_files": 100, "max_metadata_bytes": 100000,
                  "max_logical_bytes": 12 * 1024 * 1024, "max_package_bytes": 14 * 1024 * 1024,
                  "min_free_bytes": 0, "max_chunk_bytes": 1 << 20, "max_state_bytes": 65536,
                  "max_duration_seconds": 60, "max_batch_chunks": 8}
        policy = root / "policy.json"
        policy.write_text(json.dumps({"schema": "velo.transfer.policy.v1", "policy_id": "fixture",
            "expected_vm_uuid": self.uuid, "read_roots": [str(root / "read")],
            "write_roots": [str(root / "write")], "work_root": str(root / "work"), "limits": limits}))
        policy.chmod(0o600)
        service = GuestTransferService(policy, _observation=WindowsObservation("Windows", self.uuid, "b"),
                                       _acl_verifier=lambda p, k: True)
        self.addCleanup(service.shutdown)
        self.limits = limits
        return service

    def _pull_task(self, service, payload: bytes):
        payload_file = Path(self.temp.name) / "read" / "payload.bin"
        payload_file.write_bytes(payload)
        value = {"protocol_version": "velo.transfer.v1", "transfer_id": "trial", "direction": "pull",
            "sources": [{"absolute_path": str(payload_file), "relative_path": "payload.bin"}],
            "expected_destination": {"endpoint": "host", "identity": {"fixture": "local"},
                                     "canonical_path": "/tmp/velo-out"},
            "expected_vm_identity": {"vm_uuid": self.uuid, "boot_identity": "b", "vm_epoch": "e"},
            "evidence_context": {"producer_complete": True, "producer_quiescent": True, "references": ["r"]},
            "budget": {k: self.limits[k] for k in ("max_files", "max_metadata_bytes", "max_logical_bytes",
                "max_package_bytes", "min_free_bytes", "max_chunk_bytes", "max_duration_seconds")}}
        value["request_digest"] = request_digest(value)
        service.transfer_begin(value)
        # in-process prepare: use the package worker synchronously
        service._execute("trial", value["request_digest"], "package")
        return value

    def test_endpoint_pull_roundtrip(self):
        import asyncio
        from starlette.testclient import TestClient
        from velociraptor_transport import _chunkbin_endpoint, _vbt_frame
        service = self._service()
        payload = bytes(range(256)) * 32  # 8 KiB
        req = self._pull_task(service, payload)
        from starlette.applications import Starlette
        from starlette.routing import Route
        from velo_transfer.mcp_tools import TransferEnvelope, _SCHEMA
        from velo_transfer.errors import TransferContentError as _TCE
        def _invoke(name, **kw):
            try:
                return TransferEnvelope(schema=_SCHEMA, status="success",
                                        result=service.transfer_chunks(**kw))
            except _TCE as exc:
                return TransferEnvelope(schema=_SCHEMA, status="error", error={"code": exc.code})
        def _failure(code):
            return TransferEnvelope(schema=_SCHEMA, status="error", error={"code": code})
        holder = type("S", (), {"invoke": staticmethod(_invoke), "_failure": staticmethod(_failure)})
        app = Starlette(routes=[Route("/chunkbin", _chunkbin_endpoint(holder), methods=["POST"])])
        client = TestClient(app)
        response = client.post("/chunkbin", headers={
            "Content-Type": "application/octet-stream",
            "x-velo-direction": "pull", "x-velo-transfer-id": "trial",
            "x-velo-request-digest": req["request_digest"], "x-velo-offset": "0",
            "x-velo-count-per-chunk": "4096", "x-velo-chunk-count": "2"}, content=_vbt_frame({}, b""))
        self.assertEqual(response.status_code, 200)
        header, wire = _parse_vbt(response.content)
        self.assertEqual(header["status"], "success")
        self.assertEqual(len(wire), 8192)
        self.assertTrue(wire.startswith(b"PK\x03\x04"), "pull chunks read from the bundle package")
        meta = header["result"]["chunks"]
        self.assertEqual([m["offset"] for m in meta], [0, 4096])
        self.assertEqual(hashlib.sha256(wire[:4096]).hexdigest(), meta[0]["chunk_sha256"])
        self.assertEqual(hashlib.sha256(wire[4096:]).hexdigest(), meta[1]["chunk_sha256"])

    def test_endpoint_invalid_arguments(self):
        from starlette.testclient import TestClient
        from velociraptor_transport import _chunkbin_endpoint
        service = self._service()
        from starlette.applications import Starlette
        from starlette.routing import Route
        app = Starlette(routes=[Route("/chunkbin", _chunkbin_endpoint(service), methods=["POST"])])
        client = TestClient(app)
        response = client.post("/chunkbin", headers={"x-velo-transfer-id": ""})
        self.assertEqual(response.status_code, 415)
        self.assertEqual(response.json(), {"error": {"code": "unsupported_media_type"}})


if __name__ == "__main__":
    unittest.main()
