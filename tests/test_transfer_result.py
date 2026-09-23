"""Benign declared-result fixtures; no file, guest or journal is opened."""

import copy
import json
import re
import unittest
from pathlib import Path

from velo_transfer.errors import TransferContentError as Error
from velo_transfer.manifest import canonical_json
from velo_transfer.result import (decode_result, encode_result, result_exit_code,
                                  result_summary, validate_result)

LIMITS = {"max_files": 20, "max_metadata_bytes": 200_000}
HASH = "a" * 64


def result(direction="push"):
    roles = ("publication_receipt", "destination_verification", "host_cleanup", "guest_cleanup")
    return {"schema": "velo.transfer.result.v1", "outcome": "complete",
            "transfer_id": "task-1", "request_digest": "b" * 64,
            "direction": direction, "channel": "velo", "fallback_reason": None,
            "source_vm_identity": None if direction == "push" else
                {"vm_uuid": "123e4567-e89b-42d3-a456-426614174000",
                 "boot_identity": "boot-1", "vm_epoch": "epoch-1"},
            "destination_identity": {"endpoint": "guest" if direction == "push" else "host",
                                     "identity": {"node": "verified"},
                                     "canonical_path": "E:\\Delivery\\batch" if direction == "push"
                                     else "/evidence/incoming/batch"},
            "package_sha256": "c" * 64, "package_size": (1 << 32) + 7,
            "manifest_sha256": "d" * 64, "resumed_bytes": 0,
            "files": [{"source": "/evidence/资料.bin" if direction == "push" else
                       "E:\\Export\\资料.bin", "relative_path": "资料/零.bin",
                       "destination": "E:\\Delivery\\batch\\资料\\零.bin" if direction == "push" else
                       "/evidence/incoming/batch/资料/零.bin", "size": (1 << 32) + 5,
                       "sha256": "e" * 64}],
            "source_stability": "stable_at_required_check", "phase": "COMPLETE",
            "last_phase": "CLEANING", "published_ever": True,
            "destination_verified": True, "cleanup": {"host": True, "guest": True},
            "publication_receipt_sha256": HASH, "warnings": [],
            "evidence_index": [{"role": role, "reference": {"name": role, "size": 32,
                                "sha256": HASH if role == "publication_receipt" else "f" * 64,
                                "device": 1, "inode": index + 10, "mtime_ns": 100}}
                               for index, role in enumerate(roles)]}


class ResultTests(unittest.TestCase):
    def check(self, document):
        return validate_result(document, **LIMITS)

    def rejects(self, document, code=None):
        with self.assertRaises(Error) as caught:
            self.check(document)
        if code:
            self.assertEqual(code, caught.exception.code)
        self.assertEqual(str(caught.exception), caught.exception.code)

    def test_complete_push_pull_canonical_roundtrip_copy_and_summary(self):
        for direction in ("push", "pull"):
            with self.subTest(direction=direction):
                original = result(direction)
                encoded = encode_result(original, **LIMITS)
                self.assertEqual(encoded, canonical_json(original))
                decoded = decode_result(encoded, **LIMITS)
                decoded["files"][0]["relative_path"] = "changed"
                self.assertEqual(original["files"][0]["relative_path"], "资料/零.bin")
                self.assertEqual(result_exit_code(original, **LIMITS), 0)
                summary = result_summary(original, "/protected/tasks/task-1/result.json", **LIMITS)
                self.assertEqual(set(summary), {"schema", "transfer_id", "phase", "outcome",
                                                "exit_code", "published_ever", "result_path", "file_count"})
                self.assertEqual(summary["file_count"], 1)
                self.assertNotIn("files", summary)
                self.assertNotIn("warnings", summary)
                self.assertNotIn("资料", str(summary))
                self.assertEqual(self.check(original), original)

    def test_five_outcomes_and_unknown_publication(self):
        base = result()
        rejected = copy.deepcopy(base)
        rejected.update(outcome="rejected", phase="FAILED", last_phase="CREATED", direction=None,
                        transfer_id=None, request_digest=None, channel=None,
                        destination_identity=None, source_vm_identity=None,
                        package_sha256=None, package_size=None, manifest_sha256=None,
                        published_ever=False, publication_receipt_sha256=None,
                        destination_verified=None, evidence_index=[], files=[])
        incomplete = copy.deepcopy(rejected)
        incomplete.update(outcome="incomplete", phase="VERIFYING", direction="push",
                          published_ever=None)
        conflict = copy.deepcopy(base)
        conflict.update(outcome="conflict", phase="CONFLICT", destination_verified=False)
        cleanup = copy.deepcopy(base)
        cleanup.update(outcome="cleanup_pending", phase="CLEANING",
                       destination_verified=None, cleanup={"host": True, "guest": None})
        for document, expected in ((base, 0), (rejected, 2), (incomplete, 3),
                                   (conflict, 4), (cleanup, 5)):
            self.assertEqual(result_exit_code(document, **LIMITS), expected)
        self.assertIsNone(incomplete["published_ever"])
        self.assertTrue(conflict["published_ever"])

    def test_success_requires_global_facts_and_pull_source(self):
        base = result()
        changes = [
            {"phase": "PUBLISHED"}, {"published_ever": None},
            {"destination_verified": None}, {"cleanup": {"host": True, "guest": None}},
            {"publication_receipt_sha256": None}, {"package_size": None},
            {"request_digest": None}, {"source_stability": "unknown"},
            {"source_stability": "changed_before_required_check"},
            {"evidence_index": base["evidence_index"][:3]},
        ]
        for change in changes:
            with self.subTest(change=change):
                document = copy.deepcopy(base); document.update(change)
                self.rejects(document)
        pull = result("pull"); pull["source_vm_identity"] = None
        self.rejects(pull, "result_completion_unproven")
        push = result(); push["source_vm_identity"] = result("pull")["source_vm_identity"]
        self.rejects(push, "invalid_result_vm_identity")
        after_release = result()
        after_release["source_stability"] = "changed_after_authorized_release"
        self.assertEqual(result_exit_code(after_release, **LIMITS), 0)
        after_release["destination_verified"] = False
        after_release["phase"] = "CONFLICT"; after_release["outcome"] = "conflict"
        self.assertEqual(result_exit_code(after_release, **LIMITS), 4)

    def test_outcome_contradictions(self):
        base = result()
        for change in ({"outcome": "incomplete"}, {"outcome": "rejected"},
                       {"outcome": "conflict"}):
            document = copy.deepcopy(base); document.update(change); self.rejects(document)
        rejected = copy.deepcopy(base); rejected.update(outcome="rejected", phase="FAILED",
                                                        published_ever=True)
        self.rejects(rejected)
        rejected["published_ever"] = False
        self.rejects(rejected)  # A publication receipt contradicts definite nonpublication.
        cleanup = copy.deepcopy(base); cleanup.update(outcome="cleanup_pending", phase="PUBLISHED")
        self.rejects(cleanup)
        cleanup["cleanup"]["guest"] = None; cleanup["destination_verified"] = False
        self.rejects(cleanup)
        cleanup["destination_verified"] = None
        self.assertEqual(result_exit_code(cleanup, **LIMITS), 5)
        cleanup["phase"] = "VERIFYING"
        self.rejects(cleanup)

    def test_publication_facts_remain_consistent_across_failure_outcomes(self):
        for phase, last_phase, receipt_known in (
                ("PUBLISHED", "VERIFYING", False),
                ("FAILED", "CLEANING", False),
                ("CONFLICT", "VERIFYING", True)):
            for published in (False, None):
                with self.subTest(phase=phase, published=published):
                    document = result()
                    document.update(outcome="incomplete", phase=phase,
                                    last_phase=last_phase, published_ever=published)
                    if not receipt_known:
                        document["publication_receipt_sha256"] = None
                        document["evidence_index"] = []
                    self.rejects(document, "result_publication_contradiction")
        for key in ("transfer_id", "request_digest", "channel", "destination_identity"):
            document = result()
            document.update(outcome="cleanup_pending", phase="CLEANING",
                            cleanup={"host": True, "guest": None})
            document[key] = None
            self.rejects(document, "result_publication_binding_missing")
        document = result()
        document.update(outcome="incomplete", phase="VERIFYING", last_phase="TRANSFERRING",
                        published_ever=None, publication_receipt_sha256=None,
                        destination_verified=None, cleanup={"host": None, "guest": None},
                        evidence_index=[])
        self.assertEqual(result_exit_code(document, **LIMITS), 3)
        self.assertIsNone(self.check(document)["published_ever"])
        # A recovered exclusive rename can be proven before a publication receipt
        # is durable; retain that known publication and its binding, without 0.
        document.update(published_ever=True, phase="PUBLISHED")
        self.assertEqual(result_exit_code(document, **LIMITS), 3)

    def test_package_files_and_paths(self):
        base = result()
        base["files"] = []
        base["package_size"] = 0
        self.assertEqual(result_exit_code(base, **LIMITS), 0)
        base["resumed_bytes"] = 1
        self.rejects(base, "invalid_result_resumed_bytes")
        base["resumed_bytes"] = 0
        base["package_size"] = True
        self.rejects(base)
        base = result()
        for name in ("资料/零.bin", "资料/零.BIN", "资料"):
            document = copy.deepcopy(base)
            document["files"].append({**document["files"][0], "relative_path": name})
            self.rejects(document, "result_path_collision")
        for name in ("../escape", "a\\b", "a//b", "NUL", "a/./b"):
            document = copy.deepcopy(base); document["files"][0]["relative_path"] = name
            self.rejects(document)
        base["files"][0]["source"] = "bad\ud800"
        self.rejects(base)

    def test_evidence_receipts_and_exact_fields(self):
        base = result()
        base["evidence_index"][0]["reference"]["sha256"] = "f" * 64
        self.rejects(base, "result_receipt_mismatch")
        for mutation in (lambda d: d.update(extra="raw tool output"),
                         lambda d: d["warnings"].extend(["dup", "dup"]),
                         lambda d: d["warnings"].append("raw error\nsecret"),
                         lambda d: d["evidence_index"].append(copy.deepcopy(d["evidence_index"][0])),
                         lambda d: d["evidence_index"][0]["reference"].update(path="/external"),
                         lambda d: d["cleanup"].update(extra=True)):
            document = result(); mutation(document); self.rejects(document)

    def test_json_budget_duplicate_nonfinite_depth_cycle_and_summary_path(self):
        base = result(); encoded = encode_result(base, **LIMITS)
        with self.assertRaises(Error):
            decode_result(encoded, max_files=True, max_metadata_bytes=200000)
        with self.assertRaises(Error):
            decode_result(encoded, max_files=20, max_metadata_bytes=len(encoded)-1)
        with self.assertRaises(Error) as caught:
            decode_result(b'{"schema":1,"schema":2}', **LIMITS)
        self.assertEqual(caught.exception.code, "duplicate_result_key")
        for raw in (b'{"x":NaN}', b'{"x":1e999}', b'\xff', b'{"x":"\\ud800"}'):
            with self.subTest(raw=raw), self.assertRaises(Error):
                decode_result(raw, **LIMITS)
        for field in ("phase", "last_phase", "source_stability"):
            document = result(); document[field] = []
            self.rejects(document)
        for bad in (float("nan"), float("inf"), 10 ** 100000):
            document = result(); document["package_size"] = bad
            self.rejects(document)
        cycle = result(); cycle["warnings"].append(cycle)
        self.rejects(cycle)
        deep = result(); node = []
        for _ in range(40): node = [node]
        deep["warnings"] = node
        self.rejects(deep)
        for path in ("relative/result.json", "/root/../result.json", "/root//result.json",
                     "/root/\nresult.json", "/root/\ud800"):
            with self.subTest(path=path), self.assertRaises(Error):
                result_summary(result(), path, **LIMITS)

    def test_every_public_output_revalidates_and_evidence_numbers_are_strict(self):
        invalid = result(); invalid["cleanup"]["guest"] = None
        for action in (lambda: encode_result(invalid, **LIMITS),
                       lambda: result_exit_code(invalid, **LIMITS),
                       lambda: result_summary(invalid, "/private/result.json", **LIMITS)):
            with self.assertRaises(Error): action()
        for field in ("size", "device", "inode", "mtime_ns"):
            document = result(); document["evidence_index"][0]["reference"][field] = True
            self.rejects(document)
        document = result(); document["files"][0]["size"] = 0
        self.assertEqual(result_exit_code(document, **LIMITS), 0)
        document["files"][0]["destination"] = "bad\ud800"
        self.rejects(document)

    def test_documented_full_json_examples_decode(self):
        docs = (Path(__file__).resolve().parents[1] / "docs/transfer-result.md").read_text()
        blocks = re.findall(r"```json\n(.*?)\n```", docs, re.S)
        self.assertEqual(len(blocks), 6)
        self.assertEqual([result_exit_code(decode_result(block.encode(), **LIMITS), **LIMITS)
                          for block in blocks], [0, 0, 2, 3, 4, 5])

    def test_limits_windows_fallback_and_no_console_data(self):
        base = result(); base["channel"] = "windows"
        self.rejects(base)
        base["fallback_reason"] = "velo_unavailable"
        self.assertEqual(result_exit_code(base, **LIMITS), 0)
        with self.assertRaises(Error):
            validate_result(base, max_files=0, max_metadata_bytes=200000)
        with self.assertRaises(Error):
            validate_result(base, max_files=1, max_metadata_bytes=500)
        base["files"].append({**base["files"][0], "relative_path": "second.bin"})
        with self.assertRaises(Error):
            validate_result(base, max_files=1, max_metadata_bytes=200000)


if __name__ == "__main__":
    unittest.main()
