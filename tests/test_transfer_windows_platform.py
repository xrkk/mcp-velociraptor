"""Windows platform adapter tests; native probes run only on Windows."""

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from velo_transfer.errors import TransferContentError as Error
from velo_transfer import windows_platform as platform

TRUSTED = "S-1-5-18"
CURRENT = "S-1-5-21-1-2-3-1001"
OTHER = "S-1-5-11"
GOOD_UUID = "12345678-1234-1234-1234-123456789abc"
GOOD_BOOT = "2026-09-23T08:00:00.0000000Z"


def identity_bytes(uuids=None, boots=None):
    return json.dumps({"uuids": [GOOD_UUID] if uuids is None else uuids,
                       "boots": [GOOD_BOOT] if boots is None else boots}).encode()


def ace(ace_type=0, flags=0, mask=0x001F01FF, authority=5, subauth=(18,)):
    sid = bytes((1, len(subauth))) + authority.to_bytes(6, "big")
    sid += b"".join(struct.pack("<I", part) for part in subauth)
    return struct.pack("<BBHI", ace_type, flags, 8 + len(sid), mask) + sid


class IdentityTests(unittest.TestCase):
    def assert_code(self, code, action):
        with self.assertRaises(Error) as caught:
            action()
        self.assertEqual(caught.exception.code, code)

    def test_parse_success_stable_boot_and_policy_shape(self):
        observed = platform.parse_identity(identity_bytes(uuids=[GOOD_UUID.upper()]))
        self.assertEqual(observed.vm_uuid, GOOD_UUID)
        self.assertEqual(observed.for_policy(), {"os_name": "Windows", "vm_uuid": GOOD_UUID})
        self.assertEqual(observed.boot_identity,
                         platform.parse_identity(identity_bytes()).boot_identity)
        self.assertTrue(observed.boot_identity.startswith("winboot-"))

    def test_parse_rejects_absent_multiple_bad_and_duplicate(self):
        bad = [identity_bytes(uuids=[]), identity_bytes(uuids=[GOOD_UUID, GOOD_UUID]),
               identity_bytes(boots=[]), identity_bytes(boots=[GOOD_BOOT, GOOD_BOOT]),
               identity_bytes(uuids=["00000000-0000-0000-0000-000000000000"]),
               identity_bytes(uuids=["invalid"]), identity_bytes(boots=["unknown"]),
               identity_bytes(boots=["1999-01-01T00:00:00.0000000Z"]),
               b'{"uuids":[],"uuids":[],"boots":[]}', b'{', b'[]', b'NaN',
               b'X' * 4097]
        for raw in bad:
            with self.subTest(raw=raw[:40]):
                self.assert_code("windows_identity_invalid", lambda: platform.parse_identity(raw))

    @unittest.skipIf(os.name == "nt", "Linux unsupported-platform check")
    def test_real_observer_and_acl_default_fail_closed_on_non_windows(self):
        self.assert_code("windows_platform_unsupported", platform.observe_windows)
        self.assert_code("windows_platform_unsupported", platform.WindowsAclVerifier)

    def test_bounded_subprocess_exit_timeout_and_overflow_reap(self):
        children = []
        original = subprocess.Popen
        def owned(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child
        with mock.patch.object(platform.subprocess, "Popen", side_effect=owned):
            command = [sys.executable, "-c", "import sys;sys.stdout.write('ok')"]
            self.assertEqual(platform._capture_bounded(command, timeout_seconds=2,
                                                       max_output=8), b"ok")
            self.assert_code("windows_identity_command_failed", lambda: platform._capture_bounded(
                [sys.executable, "-c", "import sys;sys.exit(7)"],
                timeout_seconds=2, max_output=8))
            self.assert_code("windows_identity_output_limit", lambda: platform._capture_bounded(
                [sys.executable, "-c", "import sys;sys.stdout.write('X'*8192);sys.stdout.flush()"],
                timeout_seconds=2, max_output=16))
            self.assert_code("windows_identity_output_limit", lambda: platform._capture_bounded(
                [sys.executable, "-c", "import sys;sys.stderr.write('Y'*8192);sys.stderr.flush()"],
                timeout_seconds=2, max_output=16))
            self.assert_code("windows_identity_timeout", lambda: platform._capture_bounded(
                [sys.executable, "-c", "import time;time.sleep(5)"],
                timeout_seconds=0.05, max_output=16))
        self.assertEqual(len(children), 5)
        self.assertTrue(all(child.poll() is not None for child in children))
        self.assertTrue(all(child.stdout.closed and child.stderr.closed for child in children))
        print("bounded identity child exit codes:", [child.returncode for child in children])


class AclTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.parent = self.root / "parent"
        self.parent.mkdir()
        self.stage = self.parent / ".velo-stage-test"
        self.stage.mkdir()
        self.final = self.parent / "final"
        self.final.mkdir()
        self.file = self.root / "policy.json"
        self.file.write_bytes(b"{}")
        self.default = platform.AclSnapshot(TRUSTED, (platform.Ace(0, 0, 0x001F01FF, TRUSTED),))
        self.snapshots = {}
        self.verifier = platform.WindowsAclVerifier(_reader=self.read,
                                                    _current_sid=CURRENT)

    def read(self, path):
        return self.snapshots.get(path, self.default)

    def assert_code(self, code, action):
        with self.assertRaises(Error) as caught:
            action()
        self.assertEqual(caught.exception.code, code)

    def test_policy_and_content_callback_shape(self):
        self.assertIs(self.verifier(self.file, "policy"), True)
        self.assertIs(self.verifier(self.root, "work"), True)
        callback = self.verifier.content_callback(self.stage, self.parent, self.final)
        self.assertIs(callback(self.stage), True)
        self.assertIs(callback(self.parent), True)
        self.assertIs(callback(self.final), True)
        self.assert_code("windows_acl_path_invalid", lambda: callback(self.file))
        self.assert_code("windows_acl_kind_invalid", lambda: self.verifier(self.root, "unknown"))
        self.assert_code("invalid_trusted_sid", lambda: platform.WindowsAclVerifier(
            extra_trusted_sids=["S-1-5-11", "S-1-5-11"], _reader=self.read,
            _current_sid=CURRENT))

    def test_untrusted_write_read_owner_null_and_deny_does_not_cancel(self):
        bad_write = platform.Ace(0, 0, 0x0002, OTHER)
        deny = platform.Ace(1, 0, 0x0002, OTHER)
        self.snapshots[self.file] = platform.AclSnapshot(TRUSTED,
            (deny, bad_write, platform.Ace(0, 0, 0x001F01FF, TRUSTED)))
        self.assert_code("windows_acl_untrusted_write", lambda: self.verifier(self.file, "policy"))
        self.snapshots[self.file] = platform.AclSnapshot(TRUSTED,
            (platform.Ace(0, 0, 0x02000000, OTHER),))
        self.assert_code("windows_acl_unsupported", lambda: self.verifier(self.file, "policy"))
        self.snapshots[self.file] = platform.AclSnapshot(TRUSTED,
            (platform.Ace(0, 0, 0x0001, OTHER), platform.Ace(0, 0, 0x001F01FF, TRUSTED)))
        self.assertIs(self.verifier(self.file, "policy"), True)
        self.assert_code("windows_acl_untrusted_read", lambda: self.verifier(self.file, "state"))
        self.snapshots[self.file] = platform.AclSnapshot(OTHER, (platform.Ace(0, 0, 0x001F01FF, TRUSTED),))
        self.assert_code("windows_acl_untrusted_owner", lambda: self.verifier(self.file, "policy"))
        self.snapshots[self.file] = platform.AclSnapshot(TRUSTED, (), False)
        self.assert_code("windows_acl_unprotected", lambda: self.verifier(self.file, "policy"))

    def test_ancestor_parent_inheritance_unknown_and_change(self):
        self.snapshots[self.parent] = platform.AclSnapshot(TRUSTED,
            (platform.Ace(0, 0, 0x0040, OTHER),))
        self.assert_code("windows_acl_untrusted_write", lambda: self.verifier(self.stage, "stage"))
        self.snapshots[self.parent] = platform.AclSnapshot(TRUSTED,
            (platform.Ace(0, 0x0B, 0x0002, OTHER),))
        self.assert_code("windows_acl_untrusted_write", lambda: self.verifier(self.stage, "stage"))
        self.snapshots[self.parent] = platform.AclSnapshot(TRUSTED,
            (platform.Ace(5, 0, 0, OTHER),))
        self.assert_code("windows_acl_unsupported", lambda: self.verifier(self.stage, "stage"))
        self.snapshots.clear()
        calls = {}
        def changing(path):
            calls[path] = calls.get(path, 0) + 1
            if path == self.stage and calls[path] > 1:
                return platform.AclSnapshot(CURRENT, self.default.aces)
            return self.default
        verifier = platform.WindowsAclVerifier(_reader=changing, _current_sid=CURRENT)
        self.assert_code("windows_acl_changed", lambda: verifier(self.stage, "stage"))
        link = self.root / "link"
        link.symlink_to(self.stage, target_is_directory=True)
        self.assert_code("link_or_reparse", lambda: self.verifier(link, "stage"))
        self.snapshots[self.root] = platform.AclSnapshot(TRUSTED,
            (platform.Ace(0, 0, 0x0004, OTHER),))
        self.assert_code("windows_acl_untrusted_write", lambda: self.verifier(self.stage, "stage"))
        self.snapshots.clear()
        original = platform._fingerprint
        calls.clear()
        def replaced(path):
            value = original(path)
            calls[path] = calls.get(path, 0) + 1
            if path == self.stage and calls[path] > 1:
                return (value[0], value[1] + 1, value[2], value[3])
            return value
        with mock.patch.object(platform, "_fingerprint", side_effect=replaced):
            self.assert_code("windows_acl_path_changed", lambda: self.verifier(self.stage, "stage"))

    def test_ace_parser_bounds_and_allowlist(self):
        parsed = platform._decode_ace(ace())
        self.assertEqual(parsed.sid, TRUSTED)
        self.assertEqual(parsed.mask, 0x001F01FF)
        for raw in (b"", ace()[:-1], ace(ace_type=5), ace(flags=0x80),
                    ace(flags=0x08), ace()[:4] + b"\0" * 12):
            with self.subTest(raw=raw[:8]):
                self.assert_code(("windows_acl_unsupported" if len(raw) >= 16 else
                                  "windows_acl_malformed"), lambda: platform._decode_ace(raw))
        extra = platform.WindowsAclVerifier(extra_trusted_sids=[OTHER],
            _reader=self.read, _current_sid=CURRENT)
        self.snapshots[self.file] = platform.AclSnapshot(TRUSTED,
            (platform.Ace(0, 0, 0x0002, OTHER),))
        self.assertIs(extra(self.file, "policy"), True)

    def test_unknown_mask_refused_for_trusted_and_deny_aces(self):
        for sid in (TRUSTED, OTHER):
            for ace_type in (0, 1):
                with self.subTest(sid=sid, ace_type=ace_type):
                    self.snapshots[self.file] = platform.AclSnapshot(TRUSTED,
                        (platform.Ace(ace_type, 0, 0x02000000, sid),))
                    self.assert_code("windows_acl_unsupported", lambda: self.verifier(self.file, "policy"))

    @unittest.skipUnless(os.name == "nt", "real Windows APIs require Windows")
    def test_real_windows_read_only_identity_token_and_acl(self):
        observed = platform.observe_windows()
        self.assertEqual(observed.os_name, "Windows")
        self.assertEqual(len(observed.vm_uuid), 36)
        self.assertTrue(observed.boot_identity.startswith("winboot-"))
        self.assertTrue(platform.current_process_sid().startswith("S-1-"))
        actual = platform._read_security(Path(__file__))
        self.assertTrue(actual.owner_sid.startswith("S-1-"))
        self.assertIsInstance(actual.aces, tuple)
        verifier = platform.WindowsAclVerifier()
        try:
            result = verifier(Path(__file__), "policy")
        except Error as exc:
            self.assertTrue(exc.code.startswith("windows_acl_"))
        else:
            self.assertIs(result, True)


if __name__ == "__main__":
    unittest.main()
