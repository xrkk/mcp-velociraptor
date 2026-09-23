"""Owned short-lived worker and cross-instance lease tests."""

import os
import signal
import subprocess
import sys
import time
import unittest

from velo_transfer.errors import TransferContentError as Error
from velo_transfer.guest_service import GuestTransferService
from velo_transfer.guest_worker import process_birth, same_process, terminate_verified
from velo_transfer.guest_worker import read_activation
from tests import test_transfer_guest as guest_test


class WorkerTests(unittest.TestCase):
    def setUp(self):
        guest_test.GuestTests.setUp(self)
        self.service.shutdown()
        self.service = GuestTransferService(self.policy, _observation=self.observation,
            _acl_verifier=lambda path, kind: True, _worker_delay=0.4)
        self.addCleanup(self.service.shutdown)

    def test_fast_begin_busy_other_instance_and_reap(self):
        source = self.read / "source.txt"
        source.write_bytes(b"benign")
        request = guest_test.GuestTests.request(self, "pull", [{"absolute_path": str(source),
            "relative_path": "source.txt"}], self.host / "result")
        started = time.monotonic()
        first = self.service.transfer_begin(request)
        self.assertLess(time.monotonic() - started, 0.3)
        self.assertEqual(first["local_phase"], "SOURCE_PREPARING")
        other = GuestTransferService(self.policy, _observation=self.observation,
                                     _acl_verifier=lambda path, kind: True)
        competing = guest_test.GuestTests.request(self, "push", [{"absolute_path": "C:/remote",
            "relative_path": "remote"}], self.write / "other", {
                "size": 10, "sha256": "0" * 64, "manifest_sha256": "0" * 64}, "other")
        with self.assertRaises(Error) as caught:
            other.transfer_begin(competing)
        self.assertEqual(caught.exception.code, "worker_busy")
        ready = guest_test.GuestTests.wait_phase(self, request, "SOURCE_READY")
        self.assertTrue(ready["worker"]["stopped"])
        self.assertEqual(ready["worker"]["transfer_id"], "trial")
        self.service.shutdown()
        self.assertFalse(self.service._owned)
        self.assertFalse(same_process(first["worker"]["pid"], first["worker"]["birth"]))
        print("guest worker reaped:", first["worker"]["pid"], first["worker"]["birth"])

    def test_wrong_birth_never_kills_owned_process(self):
        source = self.read / "source.txt"
        source.write_bytes(b"benign")
        request = guest_test.GuestTests.request(self, "pull", [{"absolute_path": str(source),
            "relative_path": "source.txt"}], self.host / "result")
        owner = self.service.transfer_begin(request)["worker"]
        forged = dict(owner, birth="linux-impossible")
        with self.assertRaises(Error) as caught:
            self.service._stop_registered(forged, request["request_digest"])
        self.assertEqual(caught.exception.code, "worker_ownership_mismatch")
        guest_test.GuestTests.wait_phase(self, request, "SOURCE_READY")
        self.service.shutdown()

    @unittest.skipUnless(os.name == "posix", "POSIX owned-worker kill fixture")
    def test_reconcile_dead_owned_process_without_duplicate_worker(self):
        source = self.read / "source.txt"
        source.write_bytes(b"benign")
        request = guest_test.GuestTests.request(self, "pull", [{"absolute_path": str(source),
            "relative_path": "source.txt"}], self.host / "result")
        owner = self.service.transfer_begin(request)["worker"]
        self.assertTrue(same_process(owner["pid"], owner["birth"]))
        os.kill(owner["pid"], signal.SIGKILL)
        os.waitpid(owner["pid"], 0)
        self.service._owned.pop(owner["pid"], None)
        self.assertFalse(same_process(owner["pid"], owner["birth"]))
        print("guest crash fixture reaped:", owner["pid"], owner["birth"])
        retried = self.service.transfer_begin(request)
        self.assertEqual(retried["local_phase"], "SOURCE_PREPARING")
        self.assertNotEqual(retried["worker"]["nonce"], owner["nonce"])
        guest_test.GuestTests.wait_phase(self, request, "SOURCE_READY")
        self.service.shutdown()

    def test_abort_stops_only_owned_worker_and_retains_source(self):
        source = self.read / "source.txt"
        source.write_bytes(b"benign")
        request = guest_test.GuestTests.request(self, "pull", [{"absolute_path": str(source),
            "relative_path": "source.txt"}], self.host / "result")
        owner = self.service.transfer_begin(request)["worker"]
        result = self.service.transfer_abort("trial", request["request_digest"])
        self.assertTrue(result["worker"]["stopped"])
        self.assertEqual(result["error"], "transfer_cancelled")
        self.assertFalse(same_process(owner["pid"], owner["birth"]))
        self.assertEqual(source.read_bytes(), b"benign")

    def test_fresh_instance_aborts_registered_worker(self):
        self.service._worker_delay = 2
        source = self.read / "source.txt"
        source.write_bytes(b"benign")
        request = guest_test.GuestTests.request(self, "pull", [{"absolute_path": str(source),
            "relative_path": "source.txt"}], self.host / "result")
        owner = self.service.transfer_begin(request)["worker"]
        other = GuestTransferService(self.policy, _observation=self.observation,
                                     _acl_verifier=lambda path, kind: True)
        self.addCleanup(other.shutdown)
        result = other.transfer_abort("trial", request["request_digest"])
        self.assertTrue(result["worker"]["stopped"])
        self.assertEqual(result["error"], "transfer_cancelled")
        self.assertFalse(same_process(owner["pid"], owner["birth"]))
        self.service._reap_local(owner)
        self.assertNotIn(owner["pid"], self.service._owned)

    @unittest.skipUnless(os.name == "posix", "POSIX pipe activation fixture")
    def test_partial_activation_line_has_deadline(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b"some")
            with os.fdopen(read_fd, "rb", buffering=0) as incoming:
                started = time.monotonic()
                with self.assertRaises(Error) as caught:
                    read_activation(incoming, "some-nonce", timeout=0.15)
                self.assertEqual(caught.exception.code, "worker_activation_timeout")
                self.assertLess(time.monotonic() - started, 0.5)
        finally:
            os.close(write_fd)

    @unittest.skipUnless(os.name == "nt", "native Windows process-handle fixture")
    def test_windows_handle_birth_and_bounded_stop(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            birth = process_birth(child.pid)
            self.assertTrue(same_process(child.pid, birth))
            self.assertFalse(terminate_verified(child.pid, "windows-wrong", timeout=1))
            self.assertTrue(same_process(child.pid, birth))
            self.assertTrue(terminate_verified(child.pid, birth, timeout=2))
            child.wait(timeout=2)
            self.assertFalse(same_process(child.pid, birth))
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=2)

    def test_fixed_deadline_is_not_refreshed_by_status(self):
        self.service._worker_delay = 1.2
        source = self.read / "source.txt"
        source.write_bytes(b"benign")
        request = guest_test.GuestTests.request(self, "pull", [{"absolute_path": str(source),
            "relative_path": "source.txt"}], self.host / "result")
        request["budget"]["max_duration_seconds"] = 1
        from velo_transfer.guest_service import request_digest
        request["request_digest"] = request_digest(request)
        self.service.transfer_begin(request)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status = self.service.transfer_status("trial", request["request_digest"])
            if status["worker"]["stopped"]:
                break
            time.sleep(0.02)
        else:
            self.fail("deadline worker did not stop")
        self.assertEqual(status["error"], "deadline_exceeded")
        self.assertEqual(status["local_phase"], "SOURCE_PREPARING")
        self.assertEqual(self.service.transfer_status("trial", request["request_digest"])["error"],
                         "deadline_exceeded")


if __name__ == "__main__":
    unittest.main()
