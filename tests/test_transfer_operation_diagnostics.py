"""MCP preflight failures retain native diagnostics without leaking wire arguments."""

import errno
import json
import os
from pathlib import Path
import unittest
from unittest import mock

from tests import test_transfer_guest as fixture
from velo_transfer.mcp_tools import TransferToolService


class OperationDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        fixture.GuestTests.setUp(self)
        self.manager = TransferToolService(factory=lambda: self.service)
        self.addCleanup(self.manager.shutdown)

    def test_preflight_denial_retains_native_path_before_task_creation(self):
        source = self.read / "管理员拒绝.txt"
        source.write_bytes(b"PRIVATE_CONTENT_DO_NOT_LOG")
        request = fixture.GuestTests.request(self, "pull", [{
            "absolute_path": str(source), "relative_path": source.name}], self.host / "out")
        request["evidence_context"]["references"] = ["PRIVATE_REFERENCE_DO_NOT_LOG"]
        from velo_transfer.guest_service import request_digest
        request["request_digest"] = request_digest(request)
        real_stat = Path.lstat
        def denied_stat(path, *args, **kwargs):
            if path == source:
                exc = PermissionError(errno.EACCES, "Access is denied", str(source))
                exc.winerror = 5
                raise exc
            return real_stat(path, *args, **kwargs)
        with mock.patch.object(Path, "lstat", denied_stat):
            response = self.manager.invoke("transfer_begin", request=request).model_dump(by_alias=True)
        self.assertEqual(response["error"], {"code": "source_unavailable"})
        log = self.work / "operation-errors.jsonl"
        self.assertTrue(log.is_file(), "preflight must retain the failure before creating a task")
        record = json.loads(log.read_bytes())
        self.assertEqual(record["operation"], "transfer_begin")
        self.assertEqual(record["transfer_id"], request["transfer_id"])
        self.assertEqual(record["request_digest"], request["request_digest"])
        context = record["error"]["context"]
        self.assertEqual(context["path"], str(source))
        self.assertEqual(context["operation"], "lstat")
        self.assertEqual(context["errno"], errno.EACCES)
        self.assertEqual(context["winerror"], 5)
        self.assertIn("Access is denied", context["os_error"])
        self.assertNotIn("PRIVATE_", log.read_text())
        self.assertNotIn(str(source), json.dumps(response))
        self.assertFalse((self.work / "tasks").exists())
        if os.name == "posix":
            self.assertEqual(log.stat().st_mode & 0o077, 0)

        # A later rejected request retains the earlier failure and creates no task.
        outside = self.root / "outside.txt"
        outside.write_bytes(b"benign")
        other = fixture.GuestTests.request(self, "pull", [{
            "absolute_path": str(outside), "relative_path": outside.name}], self.host / "out2", transfer_id="later")
        self.assertEqual(self.manager.invoke("transfer_begin", request=other).error,
                         {"code": "path_outside_root"})
        records = [json.loads(line) for line in log.read_bytes().splitlines()]
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0], record)
        self.assertEqual(records[1]["transfer_id"], "later")
        self.assertFalse((self.work / "tasks").exists())

    @unittest.skipUnless(os.name == "posix", "portable symlink fixture")
    def test_log_link_cannot_modify_an_unrelated_file(self):
        unrelated = self.root / "private.txt"
        unrelated.write_bytes(b"preserve")
        (self.work / "operation-errors.jsonl").symlink_to(unrelated)
        with self.assertLogs("velo_transfer.mcp_tools", level="ERROR") as logs:
            response = self.manager.invoke("transfer_status", transfer_id="missing", request_digest="0" * 64)
        self.assertEqual(response.error, {"code": "task_not_found"})
        self.assertEqual(unrelated.read_bytes(), b"preserve")
        self.assertIn("transfer_operation_log_failed", "\n".join(logs.output))

    def test_full_log_preserves_evidence_and_wire_failure(self):
        from velo_transfer.operation_diagnostics import MAX_LOG_BYTES
        log = self.work / "operation-errors.jsonl"
        log.write_bytes(b"x" * MAX_LOG_BYTES)
        log.chmod(0o600)
        with self.assertLogs("velo_transfer.mcp_tools", level="ERROR"):
            response = self.manager.invoke("transfer_status", transfer_id="missing", request_digest="0" * 64)
        self.assertEqual(response.error, {"code": "task_not_found"})
        self.assertEqual(log.read_bytes(), b"x" * MAX_LOG_BYTES)


if __name__ == "__main__":
    unittest.main()
