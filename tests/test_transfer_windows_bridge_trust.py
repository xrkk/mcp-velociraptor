"""Windows fallback bridge: deployment-granted extra trusted SIDs.

The Windows adapter launches guest_cli under the Windows-MCP account; the
work root carries an explicit deployment ACE for the velociraptor MCP service
SID. The bridge passes deployment-configured SIDs so guest_cli's verifier
trusts that ACE; nothing else changes and malformed grants fail closed.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from velo_transfer import windows_commands as wc
from velo_transfer.connection import load_connection_profile
from velo_transfer.errors import TransferContentError as Error
from velo_transfer.guest_service import _extra_trusted_sids

SVC = "S-1-5-80-4013063987-319881826-3712505395-1397637294-3432939775"
OTHER = "S-1-5-21-1000-2000-3000-4000"


class ExtraTrustedSidParsingTests(unittest.TestCase):
    def env(self, **kwargs):
        patcher = mock.patch.dict(os.environ, kwargs, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_absent_and_empty_grant_nothing(self):
        self.env(VELOCIRAPTOR_TRANSFER_EXTRA_TRUSTED_SIDS="")
        self.assertEqual(_extra_trusted_sids(), ())
        os.environ.pop("VELOCIRAPTOR_TRANSFER_EXTRA_TRUSTED_SIDS", None)
        self.assertEqual(_extra_trusted_sids(), ())

    def test_valid_sids_parsed(self):
        self.env(VELOCIRAPTOR_TRANSFER_EXTRA_TRUSTED_SIDS=f"{SVC};{OTHER}")
        self.assertEqual(_extra_trusted_sids(), (SVC, OTHER))

    def test_malformed_fails_closed(self):
        for value in ("not-a-sid", f"{SVC};junk", "S-1-", SVC + ";" + SVC):
            self.env(VELOCIRAPTOR_TRANSFER_EXTRA_TRUSTED_SIDS=value)
            with self.assertRaises(Error) as caught:
                _extra_trusted_sids()
            self.assertEqual(caught.exception.code, "invalid_trusted_sid")

    def test_empty_segments_normalize(self):
        self.env(VELOCIRAPTOR_TRANSFER_EXTRA_TRUSTED_SIDS=f";{SVC};;")
        self.assertEqual(_extra_trusted_sids(), (SVC,))

    def test_too_many_fails_closed(self):
        self.env(VELOCIRAPTOR_TRANSFER_EXTRA_TRUSTED_SIDS=";".join([OTHER] * 33))
        with self.assertRaises(Error):
            _extra_trusted_sids()


class InvokeScriptTrustTests(unittest.TestCase):
    def test_without_extra_no_variable(self):
        script = wc.invoke_script(r"E:\w\requests\a.json", r"E:\py.exe", r"E:\root",
                                  r"E:\policy.json", "0" * 24)
        self.assertNotIn("EXTRA_TRUSTED_SIDS", script)
        self.assertIn("VELOCIRAPTOR_TRANSFER_POLICY", script)

    def test_with_extra_sets_variable(self):
        script = wc.invoke_script(r"E:\w\requests\a.json", r"E:\py.exe", r"E:\root",
                                  r"E:\policy.json", "0" * 24, extra_trusted_sids=SVC)
        self.assertIn("VELOCIRAPTOR_TRANSFER_EXTRA_TRUSTED_SIDS='" + SVC + "'", script)

    def test_unsafe_extra_rejected(self):
        # The script layer only guards quoting hazards; semantic validation of
        # SID shape happens on the guest side (see parsing tests above).
        for bad in (SVC + "'", SVC + "\x00"):
            with self.assertRaises(ValueError):
                wc.invoke_script(r"E:\w\requests\a.json", r"E:\py.exe", r"E:\root",
                                 r"E:\policy.json", "0" * 24, extra_trusted_sids=bad)


class ConnectionProfileTrustTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = self.root / "policy.json"
        self.policy.write_text("{}", encoding="utf-8")
        self.policy.chmod(0o600)

    def profile(self, deployment_extra):
        deployment = {"python_path": r"E:\mcp\.venv\Scripts\python.exe",
                      "project_root": r"E:\mcp", "policy_path": r"E:\secrets\transfer-policy.json",
                      "guest_work_root": r"E:\transfer"}
        if deployment_extra is not None:
            deployment["extra_trusted_sids"] = deployment_extra
        document = {"version": "velo.transfer.connection.v1",
                    "velo": {"endpoint": "http://127.0.0.1:1/mcp", "token_file": str(self.policy)},
                    "windows": None,
                    "deployment": deployment}
        path = self.root / "profile.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_default_empty_and_explicit_value(self):
        self.assertEqual(load_connection_profile(self.profile(None)).deployment.extra_trusted_sids, "")
        loaded = load_connection_profile(self.profile(SVC))
        self.assertEqual(loaded.deployment.extra_trusted_sids, SVC)

    def test_non_string_rejected(self):
        with self.assertRaises(Exception):
            load_connection_profile(self.profile(["bad"]))
        with self.assertRaises(Exception):
            load_connection_profile(self.profile("x" * 2000))


if __name__ == "__main__":
    unittest.main()


class ReplaceRetryTests(unittest.TestCase):
    """Windows-only: transient ERROR_ACCESS_DENIED on MoveFileExW is retried."""

    def test_retries_bounded_on_windows(self):
        import sys
        if sys.platform != "win32":
            self.skipTest("windows only")
        import ctypes
        import tempfile
        from velo_transfer import storage
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src.bin"
            dst = Path(tmp) / "dst.bin"
            src.write_bytes(b"payload")
            dst.write_bytes(b"old")
            real = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
            real.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
            real.restype = ctypes.c_int
            calls = {"n": 0}
            def flaky(source, destination, flags):
                calls["n"] += 1
                if calls["n"] == 1:
                    ctypes.set_last_error(5)
                    return 0
                return real(source, destination, flags)
            with mock.patch("ctypes.WinDLL", lambda *_a, **_k: type(
                    "D", (), {"MoveFileExW": flaky})):
                storage._replace(src, dst)
            self.assertGreaterEqual(calls["n"], 2)
            self.assertEqual(dst.read_bytes(), b"payload")
