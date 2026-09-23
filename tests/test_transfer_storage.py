"""Durable store tests using isolated benign directories and owned short processes."""

import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from velo_transfer.errors import TransferContentError as Error
from velo_transfer.policy import POLICY_SCHEMA, load_policy
from velo_transfer.storage import TaskStore


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.read, self.write, self.work = (self.root / name for name in ("read", "write", "work"))
        for path in (self.read, self.write, self.work):
            path.mkdir(mode=0o700)
        self.vm_uuid = str(uuid.uuid4())
        self.policy_path = self.root / "policy.json"
        self.policy_path.write_text(json.dumps({
            "schema": POLICY_SCHEMA, "policy_id": "test-policy", "expected_vm_uuid": self.vm_uuid,
            "read_roots": [str(self.read)], "write_roots": [str(self.write)],
            "work_root": str(self.work), "limits": {
                "max_files": 100, "max_metadata_bytes": 100000,
                "max_logical_bytes": 10000000, "max_package_bytes": 12000000,
                "min_free_bytes": 0, "max_chunk_bytes": 1048576,
                "max_state_bytes": 65536, "max_duration_seconds": 30}}))
        self.policy_path.chmod(0o600)
        self.policy = load_policy(self.policy_path,
            observation={"os_name": "Windows", "vm_uuid": self.vm_uuid},
            verify_windows_acl=lambda path, kind: True).policy
        self.store = TaskStore(self.policy)
        self.binding = {"request_digest": "a" * 64, "policy_id": self.policy.policy_id,
                        "vm_uuid": self.vm_uuid, "boot_identity": "boot-1", "vm_epoch": "epoch-1"}

    def error(self, code, action):
        with self.assertRaises(Error) as caught:
            action()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def state_path(self):
        return self.work / "tasks" / "task-1" / "state.json"

    def test_create_load_save_cas_binding_and_tombstone(self):
        self.error("writer_lock_required", lambda: self.store.create("task-1", self.binding, {}))
        with self.store.writer():
            created = self.store.create("task-1", self.binding, {"phase": "CREATED"})
            self.assertEqual(created["revision"], 0)
            self.assertEqual(self.store.create("task-1", self.binding, {"phase": "WRONG"}), created)
            other = dict(self.binding, request_digest="b" * 64)
            self.error("task_binding_conflict", lambda: self.store.create("task-1", other, {}))
            changed = self.store.save("task-1", self.binding, 0,
                {"phase": "SOURCE_RELEASED", "tombstone": {"receipt": "retained"}})
            self.error("stale_revision", lambda: self.store.save("task-1", self.binding, 0, {}))
        created["state"]["phase"] = "tampered"
        changed["state"]["tombstone"]["receipt"] = "tampered"
        loaded = self.store.load("task-1", self.binding)
        self.assertEqual(loaded["revision"], 1)
        self.assertEqual(loaded["state"]["tombstone"]["receipt"], "retained")
        self.assertTrue(self.state_path().exists())
        self.error("invalid_transfer_id", lambda: self.store.load("../escape", self.binding))
        self.error("invalid_transfer_id", lambda: self.store.load("CON", self.binding))

    def test_corrupt_truncated_symlink_and_budget(self):
        with self.store.writer():
            self.store.create("task-1", self.binding, {"value": 1})
        path = self.state_path()
        good = path.read_bytes()
        path.write_bytes(good[:-1])
        self.error("invalid_state", lambda: self.store.load("task-1", self.binding))
        path.write_bytes(good.replace(b'"value":1', b'"value":2'))
        self.error("state_hash_mismatch", lambda: self.store.load("task-1", self.binding))
        path.write_bytes(good + b"x" * self.policy.limits["max_state_bytes"])
        self.error("state_budget_exceeded", lambda: self.store.load("task-1", self.binding))
        path.unlink()
        path.symlink_to(self.policy_path)
        self.error("link_or_reparse", lambda: self.store.load("task-1", self.binding))
        path.unlink()
        path.write_bytes(good)
        path.chmod(0o600)
        with self.store.writer():
            self.error("invalid_state", lambda: self.store.save("task-1", self.binding, 0,
                {"bad": object()}))
            self.error("invalid_state", lambda: self.store.save("task-1", self.binding, 0,
                {"bad": float("nan")}))
            self.error("state_budget_exceeded", lambda: self.store.save("task-1", self.binding, 0,
                {"large": "x" * 70000}))
        self.error("deadline_exceeded", lambda: TaskStore(self.policy, deadline_monotonic=0))

    def test_faults_reconcile_old_and_new_complete_revisions(self):
        from velo_transfer import storage
        with self.store.writer():
            self.store.create("task-1", self.binding, {"phase": "old"})
            real_replace = storage._replace
            with mock.patch.object(storage.os, "fsync", side_effect=OSError("before replace")):
                self.error("storage_write_failed", lambda: self.store.save("task-1", self.binding,
                    0, {"phase": "new"}))
            self.assertEqual(self.store.load("task-1", self.binding)["revision"], 0)
            with mock.patch.object(storage, "_replace", side_effect=OSError("replace failed")):
                self.error("storage_write_failed", lambda: self.store.save("task-1", self.binding,
                    0, {"phase": "new"}))
            self.assertEqual(self.store.load("task-1", self.binding)["revision"], 0)
            def replaced_then_failed(src, dst):
                real_replace(src, dst)
                raise OSError("post replace")
            with mock.patch.object(storage, "_replace", side_effect=replaced_then_failed):
                self.error("storage_durability_unknown", lambda: self.store.save("task-1",
                    self.binding, 0, {"phase": "new"}))
            self.assertEqual(self.store.load("task-1", self.binding)["revision"], 1)
            self.error("stale_revision", lambda: self.store.save("task-1", self.binding, 0, {}))
            with mock.patch.object(storage, "_sync_directory", side_effect=OSError("after replace")):
                self.error("storage_durability_unknown", lambda: self.store.save("task-1",
                    self.binding, 1, {"phase": "newer"}))
            self.assertEqual(self.store.load("task-1", self.binding)["revision"], 2)


    def test_protocol_snapshot_roundtrip_and_mismatched_replay(self):
        from velo_transfer.protocol import GuestTerminal, PROTOCOL_VERSION
        full = {"protocol_version": PROTOCOL_VERSION, "transfer_id": "task-1",
                "request_digest": self.binding["request_digest"], "direction": "pull",
                "vm_uuid": self.vm_uuid, "boot_identity": self.binding["boot_identity"],
                "vm_epoch": self.binding["vm_epoch"], "policy_id": self.binding["policy_id"],
                "package_size": 3, "package_sha256": "b" * 64,
                "manifest_sha256": "c" * 64}
        destination = {"endpoint": "host", "identity": {"machine": "host-1"},
                       "canonical_path": "/evidence/task-1"}
        terminal = GuestTerminal(full, destination)
        terminal.begin_action("prepare")
        with self.store.writer():
            self.store.create("task-1", self.binding, {"terminal": terminal.snapshot()})
        loaded = self.store.load("task-1", self.binding)
        restored = GuestTerminal.restore(loaded["state"]["terminal"], full, destination)
        self.assertEqual(restored.snapshot(), terminal.snapshot())
        self.error("task_binding_conflict", lambda: self.store.load("task-1",
            dict(self.binding, vm_epoch="different")))


    def test_failed_initial_create_is_not_reset_as_fresh_task(self):
        from velo_transfer import storage
        with self.store.writer():
            with mock.patch.object(storage, "_replace", side_effect=OSError("before replace")):
                self.error("storage_reconcile_required", lambda: self.store.create(
                    "task-1", self.binding, {"phase": "CREATED"}))
            self.error("task_incomplete", lambda: self.store.load("task-1", self.binding))
            self.error("task_incomplete", lambda: self.store.create("task-1", self.binding, {}))
            self.assertTrue((self.work / "tasks" / "task-1").exists())
            self.assertFalse(self.state_path().exists())

    def test_stage_registration_snapshot_precedes_content(self):
        from velo_transfer import Budget, prepare_staging
        final = self.write / "final"
        stage_name = ".velo-stage-task-1"
        with self.store.writer():
            self.store.create("task-1", self.binding,
                {"stage_intent": {"destination": str(final), "stage_name": stage_name}})
            def register(path, identity, parent):
                loaded = self.store.load("task-1", self.binding)
                self.assertEqual(loaded["state"]["stage_intent"]["stage_name"], stage_name)
                self.assertEqual(list(Path(path).iterdir()), [])
                self.store.save("task-1", self.binding, loaded["revision"],
                    {"stage_intent": loaded["state"]["stage_intent"],
                     "stage_identity": identity, "parent_identity": parent})
                return True
            stage = prepare_staging(final, self.write, Budget(100, 100000, 100000,
                100000, 0, time.monotonic() + 30), stage_name=stage_name,
                register_stage=register, verify_windows_acl=lambda path: True)
        self.assertEqual(self.store.load("task-1", self.binding)["state"]["stage_identity"],
                         stage["staging_identity"])

    def test_real_process_lock_contention_and_crash_release(self):
        script = """import sys
import time
from velo_transfer.policy import load_policy
from velo_transfer.storage import TaskStore
p = load_policy(sys.argv[1], observation={"os_name": "Windows", "vm_uuid": sys.argv[2]},
                verify_windows_acl=lambda path, kind: True).policy
s = TaskStore(p)
with s.writer():
    print("LOCKED", flush=True)
    time.sleep(float(sys.argv[3]))
"""
        # A real separate interpreter owns only this test's lock; the parent records PID.
        child = subprocess.Popen([sys.executable, "-c", script, str(self.policy_path), self.vm_uuid, "30"],
            cwd=Path(__file__).resolve().parent.parent, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        self.assertGreater(child.pid, 0)
        try:
            line = child.stdout.readline().strip()
            if line != "LOCKED":
                raise AssertionError(f"child failed before lock: {line}; {child.stderr.read()}")
            self.error("writer_busy", lambda: self._try_writer())
        finally:
            if child.poll() is None:
                child.terminate()
            child.communicate(timeout=5)
        self.assertIsNotNone(child.returncode)
        print(f"owned lock child terminated: pid={child.pid} exit={child.returncode}")
        normal = subprocess.Popen([sys.executable, "-c", script, str(self.policy_path),
            self.vm_uuid, "0.05"], cwd=Path(__file__).resolve().parent.parent,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout, stderr = normal.communicate(timeout=5)
            self.assertEqual(normal.returncode, 0, stderr)
            self.assertIn("LOCKED", stdout)
            print(f"owned lock child exited: pid={normal.pid} exit={normal.returncode}")
        finally:
            if normal.poll() is None:
                normal.terminate()
                normal.communicate(timeout=5)
        with self.store.writer():
            self.store.create("task-1", self.binding, {"after_crash": True})

    def _try_writer(self):
        with self.store.writer():
            pass

    @unittest.skipUnless(os.name == "nt", "Windows msvcrt locking process test")
    def test_windows_writer_lock(self):
        with self.store.writer():
            other = TaskStore(self.policy)
            with self.assertRaises(Error) as caught:
                with other.writer():
                    pass
            self.assertEqual(caught.exception.code, "writer_busy")

    def test_invalid_deadline_and_foreign_vm_refused_before_creation(self):
        for value in (float("nan"), float("inf"), True):
            self.error("invalid_deadline", lambda: TaskStore(self.policy, deadline_monotonic=value))
        self.error("deadline_outside_policy", lambda: TaskStore(self.policy,
            deadline_monotonic=time.monotonic() + 1000000))
        with self.store.writer():
            self.error("vm_identity_mismatch", lambda: self.store.create("foreign",
                dict(self.binding, vm_uuid=str(uuid.uuid4())), {}))
        self.assertFalse((self.work / "tasks" / "foreign").exists())

    def test_overbudget_input_refused_before_copy_encoding_or_directory_creation(self):
        from velo_transfer import storage
        with self.store.writer():
            with mock.patch.object(storage, "canonical_json", side_effect=AssertionError("encoding before bound")):
                self.error("state_budget_exceeded", lambda: self.store.create("oversized",
                    self.binding, {"large": "x" * 1000000}))
                self.error("state_budget_exceeded", lambda: self.store.create("oversized",
                    self.binding, [None] * 10001))
            self.assertFalse((self.work / "tasks" / "oversized").exists())
            self.assertEqual(self.store.create("oversized", self.binding, {"corrected": True})["revision"], 0)
            cyclic = []; cyclic.append(cyclic)
            self.error("state_budget_exceeded", lambda: self.store.save("oversized", self.binding, 0, cyclic))
            self.error("invalid_state", lambda: self.store.save("oversized", self.binding, 0, {"bad": "\ud800"}))
            self.assertEqual(self.store.save("oversized", self.binding, 0,
                {"unicode": "中文", "escape": "\n\t\b\f\r\\\"\x00", "finite": 1.5})["revision"], 1)


if __name__ == "__main__":
    unittest.main()
