"""Policy validation on isolated benign local roots."""

import json
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

from velo_transfer.errors import TransferContentError as Error
from velo_transfer.policy import load_policy, POLICY_SCHEMA, MAX_POLICY_BYTES


class PolicyTests(unittest.TestCase):
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
        self.observation = {"os_name": "Windows", "vm_uuid": self.uuid}
        self.data = {"schema": POLICY_SCHEMA, "policy_id": "test-policy",
                     "expected_vm_uuid": self.uuid,
                     "read_roots": [str(self.read)], "write_roots": [str(self.write)],
                     "work_root": str(self.work),
                     "limits": {"max_files": 100, "max_metadata_bytes": 100000,
                                "max_logical_bytes": 10000000, "max_package_bytes": 12000000,
                                "min_free_bytes": 0, "max_chunk_bytes": 1048576,
                                "max_state_bytes": 65536, "max_duration_seconds": 30}}
        self.path = self.root / "policy.json"
        self.write_policy()

    def write_policy(self):
        self.path.write_text(json.dumps(self.data))
        self.path.chmod(0o600)

    def load(self, **kwargs):
        kwargs.setdefault("verify_windows_acl", lambda path, kind: True)
        return load_policy(self.path, observation=self.observation, **kwargs).policy

    def rejects(self, code, action):
        with self.assertRaises(Error) as caught:
            action()
        self.assertEqual(caught.exception.code, code)

    def test_disabled_invalid_and_bounded_input(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(load_policy().enabled)
        self.rejects("source_unavailable", lambda: load_policy(self.root / "missing",
            observation=self.observation))
        self.path.write_bytes(b"{" * (MAX_POLICY_BYTES + 1))
        self.rejects("policy_too_large", self.load)
        self.path.write_bytes(b'{"schema":')
        self.rejects("invalid_policy", self.load)
        self.path.write_bytes(b'{"schema":1,"schema":2}')
        self.rejects("duplicate_policy_key", self.load)
        for change in ({"extra": 1}, {"expected_vm_uuid": self.uuid.upper()},
                       {"limits": {**self.data["limits"], "max_files": True}},
                       {"limits": {**self.data["limits"], "max_chunk_bytes": -1}},
                       {"limits": {**self.data["limits"], "max_duration_seconds": 0}}):
            self.data.update(change)
            self.write_policy()
            self.rejects("invalid_vm_identity" if "expected_vm_uuid" in change else "invalid_policy", self.load)
            self.data = {key: value for key, value in self.data.items() if key != "extra"}
            self.data["expected_vm_uuid"] = self.uuid
            self.data["limits"] = {"max_files": 100, "max_metadata_bytes": 100000,
                "max_logical_bytes": 10000000, "max_package_bytes": 12000000,
                "min_free_bytes": 0, "max_chunk_bytes": 1048576,
                "max_state_bytes": 65536, "max_duration_seconds": 30}
        self.write_policy()
        self.path.write_bytes(self.path.read_bytes().replace(b'"max_files": 100', b'"max_files": NaN'))
        self.rejects("invalid_policy", self.load)

    def test_identity_permissions_and_roots(self):
        self.rejects("vm_identity_unavailable", lambda: load_policy(self.path))
        self.rejects("wrong_operating_system", lambda: load_policy(self.path,
            observation={"os_name": "Linux", "vm_uuid": self.uuid}))
        self.rejects("vm_identity_mismatch", lambda: load_policy(self.path,
            observation={"os_name": "Windows", "vm_uuid": str(uuid.uuid4())}))
        if os.name == "posix":
            self.path.chmod(0o666)
            self.rejects("insecure_permissions", self.load)
            self.path.chmod(0o600)
            self.work.chmod(0o777)
            self.rejects("insecure_permissions", self.load)
            self.work.chmod(0o700)
        link = self.root / "linked"
        link.symlink_to(self.read, target_is_directory=True)
        self.data["read_roots"] = [str(link)]
        self.write_policy()
        self.rejects("link_or_reparse", self.load)
        self.data["read_roots"] = [str(self.read)]
        self.write_policy()
        if os.name == "nt":
            self.rejects("windows_acl_not_verified", lambda: load_policy(self.path,
                observation=self.observation, guest=True))
            self.rejects("windows_acl_not_verified", lambda: load_policy(self.path,
                observation=self.observation, guest=True,
                verify_windows_acl=lambda path, kind: False))

    def test_paths_revalidate_and_budget(self):
        self.data["limits"].pop("max_chunk_bytes")
        self.write_policy()
        self.assertEqual(self.load().limits["max_chunk_bytes"], 1048576)
        policy = self.load()
        file = self.read / "file"
        file.write_bytes(b"x")
        self.assertEqual(policy.resolve_local(file, "read"), file)
        self.assertEqual(policy.resolve_local(self.write / "new", "write", allow_missing_leaf=True),
                         self.write / "new")
        self.rejects("path_outside_root", lambda: policy.resolve_local(self.root / "read-alias" / "x", "read"))
        self.rejects("invalid_local_path", lambda: policy.resolve_local(str(self.read) + "/../write/x", "read"))
        self.rejects("source_unavailable", lambda: policy.resolve_local(self.write / "no-parent" / "new",
            "write", allow_missing_leaf=True))
        link = self.read / "link"
        link.symlink_to(file)
        self.rejects("link_or_reparse", lambda: policy.resolve_local(link, "read"))
        self.assertEqual(policy.content_budget(deadline_monotonic=time.monotonic() + 10).max_files, 100)
        old_read = self.root / "read-old"
        self.read.rename(old_read)
        self.read.mkdir(mode=0o700)
        self.rejects("root_changed", policy.revalidate)
        self.read.rmdir()
        old_read.rename(self.read)
        self.data["policy_id"] = "changed"
        self.write_policy()
        self.rejects("policy_changed", policy.revalidate)

    def test_deadline_must_be_finite_and_within_policy(self):
        policy = self.load()
        for value, code in ((float("nan"), "invalid_deadline"), (float("inf"), "invalid_deadline"),
                            (True, "invalid_deadline"), ("30", "invalid_deadline"),
                            (time.monotonic() + 1000, "deadline_outside_policy"),
                            (10 ** 500, "deadline_outside_policy"), (0, "deadline_exceeded")):
            with self.subTest(value=str(value)[:40]):
                self.rejects(code, lambda: policy.content_budget(deadline_monotonic=value))

    @unittest.skipUnless(os.name == "posix", "POSIX ancestor ownership test")
    def test_replaceable_policy_ancestor_rejected(self):
        public = self.root / "public"
        public.mkdir(mode=0o777)
        public.chmod(0o777)
        private = public / "private"
        private.mkdir(mode=0o700)
        candidate = private / "policy.json"
        candidate.write_bytes(self.path.read_bytes())
        candidate.chmod(0o600)
        self.rejects("insecure_permissions", lambda: load_policy(candidate, observation=self.observation))
        public.chmod(0o700)
        self.assertTrue(load_policy(candidate, observation=self.observation).enabled)


if __name__ == "__main__":
    unittest.main()
