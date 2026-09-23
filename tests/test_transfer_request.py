"""Benign host request grammar and actual guest begin contract tests."""

import copy
import json
import math
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator

from velo_transfer.errors import TransferContentError as Error
from velo_transfer.guest_service import request_digest
from velo_transfer.manifest import Budget, digest_json
from velo_transfer.request import load_request, make_guest_request
from velo_transfer.adapters import SCHEMAS


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "request.json"
        self.uuid = str(uuid.uuid4())

    def document(self, direction="push"):
        return {"schema": "velo.transfer.request.v1", "direction": direction,
            "sources": [{"absolute_path": "/uncreated/资料 零.bin" if direction == "push" else
                         "E:\\uncreated\\资料 零.bin", "relative_path": "资料/零.bin"}],
            "destination_directory": "E:\\Delivery\\batch" if direction == "push" else
                                     "/uncreated/delivery/batch",
            "connection_profile": "/uncreated/private/profile.json",
            "expected_vm_identity": {"vm_uuid": self.uuid.upper(), "boot_identity": "boot-1",
                                     "vm_epoch": "epoch-1"},
            "evidence_context": {"producer_complete": True, "producer_quiescent": True,
                                 "references": ["producer-log"]},
            "budget": {"max_files": 10, "max_metadata_bytes": 10000,
                       "max_logical_bytes": 0, "max_package_bytes": 1 << 34,
                       "min_free_bytes": 0, "max_chunk_bytes": 1 << 20,
                       "max_duration_seconds": 60, "request_timeout_seconds": 15}}

    def load(self, value):
        self.path.write_text(json.dumps(value, ensure_ascii=False))
        return load_request(self.path)

    def assert_code(self, code, value):
        with self.assertRaises(Error) as caught:
            self.load(value)
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn(str(self.root), str(caught.exception))

    def test_push_pull_large_budget_deadline_and_no_io_side_effect(self):
        for direction in ("push", "pull"):
            with self.subTest(direction=direction):
                doc = self.document(direction)
                with mock.patch("velo_transfer.request.uuid.uuid4", return_value=uuid.UUID(int=1)):
                    request = self.load(doc)
                self.assertEqual(request.transfer_id, "00000000000000000000000000000001")
                self.assertEqual(request.document["expected_vm_identity"]["vm_uuid"], self.uuid)
                self.assertEqual(request.guest_budget["max_logical_bytes"], 0)
                self.assertEqual(request.guest_budget["max_package_bytes"], 1 << 34)
                self.assertEqual(request.request_timeout_seconds, 15)
                deadline = time.monotonic() + 33
                content = request.content_budget(deadline)
                self.assertIsInstance(content, Budget)
                self.assertEqual(content.deadline_monotonic, deadline)
                self.assertEqual(content.max_expansion_ratio, 1_000_000)
                self.assertEqual(request.work_root, self.root / ".velo-transfer")
                self.assertFalse(request.work_root.exists())
                self.assertFalse(Path(doc["connection_profile"]).exists())
                self.assertEqual(request.document, request.document)

    def test_actual_guest_schema_and_digest_both_directions(self):
        for direction in ("push", "pull"):
            with self.subTest(direction=direction):
                request = self.load(self.document(direction))
                target = {"endpoint": "guest" if direction == "push" else "host",
                          "identity": {"node": "known"},
                          "canonical_path": request.document["destination_directory"]}
                package = {"size": (1 << 32) + 7, "sha256": "a" * 64,
                           "manifest_sha256": "b" * 64} if direction == "push" else None
                actual = make_guest_request(request, target, package)
                self.assertTrue(Draft202012Validator(
                    SCHEMAS["transfer_begin"]["inputSchema"]).is_valid({"request": actual}))
                self.assertEqual(actual["request_digest"], request_digest(actual))
                self.assertEqual(actual["budget"], request.guest_budget)
                self.assertNotIn("request_timeout_seconds", actual["budget"])
                target["identity"]["node"] = "modified"
                if package:
                    package["size"] = 1
                self.assertEqual(actual["expected_destination"]["identity"]["node"], "known")
                if direction == "push":
                    self.assertEqual(actual["package"]["size"], (1 << 32) + 7)

    def test_resume_intent_and_immutable_copies(self):
        doc = self.document()
        doc["transfer_id"] = "Batch.1"
        doc["resume"] = True
        first = self.load(doc)
        expected = digest_json({key: value for key, value in first.document.items()
                                if key not in ("transfer_id", "resume")})
        self.assertEqual(first.intent_digest, expected)
        another = copy.deepcopy(doc)
        another["transfer_id"] = "Batch.2"
        another["resume"] = False
        self.assertEqual(self.load(another).intent_digest, expected)
        first.document["sources"][0]["relative_path"] = "changed"
        first.guest_budget["max_files"] = 1
        self.assertEqual(first.document["sources"][0]["relative_path"], "资料/零.bin")
        self.assertEqual(first.guest_budget["max_files"], 10)
        self.assertEqual(first.transfer_id, "Batch.1")
        doc["budget"]["max_files"] = 9
        self.assertNotEqual(self.load(doc).intent_digest, expected)

    def test_document_shape_and_json_file_errors(self):
        for change, code in (({"extra": 1}, "invalid_request"), ({"direction": "copy"}, "invalid_direction"),
                             ({"sources": []}, "sources_required"), ({"resume": 1}, "invalid_resume")):
            with self.subTest(change=change):
                doc = self.document()
                doc.update(change)
                self.assert_code(code, doc)
        doc = self.document()
        doc["resume"] = True
        self.assert_code("resume_requires_transfer_id", doc)
        self.path.write_text('{"schema":1,"schema":2}')
        with self.assertRaises(Error) as caught:
            load_request(self.path)
        self.assertEqual(caught.exception.code, "duplicate_json_key")
        for raw in (b"\xff", b'{"x":NaN}', b'{"x":Infinity}', b"{"):
            self.path.write_bytes(raw)
            with self.assertRaises(Error) as caught:
                load_request(self.path)
            self.assertEqual(caught.exception.code, "invalid_json")
        self.path.write_bytes(b"x" * ((1 << 20) + 1))
        with self.assertRaises(Error) as caught:
            load_request(self.path)
        self.assertEqual(caught.exception.code, "spec_too_large")

    def test_extreme_values_and_non_utf8_have_stable_errors(self):
        doc = self.document()
        doc["budget"]["request_timeout_seconds"] = 10 ** 400
        self.assert_code("invalid_budget", doc)
        doc = self.document()
        doc["sources"][0]["absolute_path"] = "/untrusted/\ud800"
        for raw in (json.dumps(doc).encode("utf-8"),
                    json.dumps(self.document()).encode("utf-16"),
                    json.dumps(self.document()).encode("utf-32"),
                    b'{"overflow":1e999}'):
            self.path.write_bytes(raw)
            with self.assertRaises(Error) as caught:
                load_request(self.path)
            self.assertEqual(caught.exception.code, "invalid_json")
        request = self.load(self.document())
        with self.assertRaises(Error) as caught:
            request.content_budget(10 ** 400)
        self.assertEqual(caught.exception.code, "invalid_deadline")
        with self.assertRaises(Error) as caught:
            make_guest_request(request, {"endpoint": "guest", "identity": {"node": "\ud800"},
                "canonical_path": request.document["destination_directory"]},
                {"size": 0, "sha256": "a" * 64, "manifest_sha256": "b" * 64})
        self.assertEqual(caught.exception.code, "invalid_destination")

    def test_spec_file_identity_and_missing_sources(self):
        self.load(self.document())
        self.assertFalse(Path("/uncreated/资料 零.bin").exists())
        alias = self.root / "alias.json"
        alias.symlink_to(self.path)
        with self.assertRaises(Error) as caught:
            load_request(alias)
        self.assertEqual(caught.exception.code, "invalid_spec_file")
        alias.unlink()
        os.link(self.path, alias)
        with self.assertRaises(Error) as caught:
            load_request(self.path)
        self.assertEqual(caught.exception.code, "invalid_spec_file")
        alias.unlink()
        original = os.fstat
        with mock.patch("velo_transfer.request.os.fstat", wraps=original) as observed:
            def changed(fd):
                result = original(fd)
                if observed.call_count > 1:
                    self.path.write_text("replaced")
                return result
            observed.side_effect = changed
            with self.assertRaises(Error) as caught:
                load_request(self.path)
            self.assertEqual(caught.exception.code, "spec_changed")

    def test_paths_collisions_and_evidence(self):
        bad = ("/x/../y", "/x//y", "/x/./y", "/x/CON", "/x/has:ads", "/x/trailing. ")
        for path in bad:
            doc = self.document()
            doc["sources"][0]["absolute_path"] = path
            self.assert_code("invalid_source_path", doc)
        for path in ("\\\\host\\share\\x", "\\\\?\\C:\\x", "C:\\x\\..\\y",
                     "C:\\x\\NUL", "C:\\x\\bad:ads", "C:\\x\\a\\", "C:\\x/y"):
            doc = self.document("pull")
            doc["sources"][0]["absolute_path"] = path
            self.assert_code("invalid_source_path", doc)
        for relative in ("资料/零.bin", "资料/子", "资料/子/file"):
            doc = self.document()
            doc["sources"][0]["relative_path"] = "资料"
            doc["sources"].append({"absolute_path": "/another", "relative_path": relative})
            self.assert_code("path_collision", doc)
        doc = self.document()
        doc["sources"].append({"absolute_path": "/another", "relative_path": "资料/零.BIN"})
        self.assert_code("path_collision", doc)
        doc = self.document()
        doc["evidence_context"]["producer_quiescent"] = False
        self.assert_code("producer_evidence_missing", doc)
        doc = self.document()
        doc["evidence_context"]["references"] = []
        self.assert_code("producer_evidence_missing", doc)
        doc = self.document()
        doc["sources"][0]["extra"] = "untrusted"
        self.assert_code("invalid_source_spec", doc)
        for field, value, code in (("connection_profile", "relative.json", "invalid_connection_profile"),
                                    ("destination_directory", "\\\\server\\share", "invalid_destination_path")):
            doc = self.document()
            doc[field] = value
            self.assert_code(code, doc)
        for transfer_id in ("guest-internal-lease", "CON", "a/b", "!bad"):
            doc = self.document()
            doc["transfer_id"] = transfer_id
            with self.assertRaises(Error):
                self.load(doc)
        doc = self.document()
        doc["budget"]["max_files"] = 0
        self.assert_code("invalid_budget", doc)
        doc = self.document()
        doc["budget"]["max_files"] = True
        self.assert_code("invalid_budget", doc)
        doc = self.document()
        doc["budget"]["max_metadata_bytes"] = 2
        self.assert_code("metadata_budget_exceeded", doc)
        doc = self.document()
        doc["budget"]["max_files"] = 1
        doc["sources"].append({"absolute_path": "/another", "relative_path": "second"})
        self.assert_code("file_count_exceeded", doc)

    def test_budget_deadline_and_guest_conversion_rejections(self):
        for timeout in (-1, 301, True, 61):
            doc = self.document()
            doc["budget"]["request_timeout_seconds"] = timeout
            self.assert_code("invalid_budget", doc)
        doc = self.document()
        doc["budget"]["request_timeout_seconds"] = math.inf
        self.assert_code("invalid_json", doc)
        request = self.load(self.document())
        for deadline in (float("inf"), time.monotonic() - 1, True):
            with self.assertRaises(Error) as caught:
                request.content_budget(deadline)
            self.assertEqual(caught.exception.code, "invalid_deadline")
        good = {"endpoint": "guest", "identity": {"node": "known"},
                "canonical_path": request.document["destination_directory"]}
        for target in ({**good, "endpoint": "host"}, {**good, "canonical_path": "E:\\Other"}):
            with self.assertRaises(Error):
                make_guest_request(request, target, {"size": 0, "sha256": "a" * 64,
                                                     "manifest_sha256": "b" * 64})
        for package in (None, {"size": True, "sha256": "a" * 64, "manifest_sha256": "b" * 64},
                        {"size": 1 << 35, "sha256": "a" * 64, "manifest_sha256": "b" * 64},
                        {"size": 0, "sha256": "A" * 64, "manifest_sha256": "b" * 64}):
            with self.assertRaises(Error):
                make_guest_request(request, good, package)
        pull = self.load(self.document("pull"))
        with self.assertRaises(Error):
            make_guest_request(pull, {"endpoint": "host", "identity": {"node": "known"},
                                      "canonical_path": pull.document["destination_directory"]},
                               {"size": 0, "sha256": "a" * 64, "manifest_sha256": "b" * 64})


if __name__ == "__main__":
    unittest.main()
