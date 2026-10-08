"""Source access failures must survive the short-lived pull worker."""

import errno
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from velo_transfer import manifest
from velo_transfer.errors import TransferContentError as Error
from tests import test_transfer_guest as guest_test


class SourceDiagnosticTests(unittest.TestCase):
    def setUp(self):
        guest_test.GuestTests.setUp(self)

    def test_open_denied_records_exact_path_and_native_error(self):
        source = self.read / "管理员 output.txt"
        source.write_bytes(b"fixture")
        denied = PermissionError(errno.EACCES, "Access is denied")
        denied.winerror = 5
        real_open = os.open
        def open_file(path, *args, **kwargs):
            if os.fspath(path) == str(source):
                raise denied
            return real_open(path, *args, **kwargs)
        with mock.patch.object(manifest.os, "open", side_effect=open_file):
            with self.assertRaises(Error) as caught:
                manifest.capture_sources(self.read, [{"absolute_path": str(source),
                    "relative_path": source.name}], guest_test.GuestTests.budget(self))
        self.assertEqual(caught.exception.code, "source_unavailable")
        self.assertEqual(caught.exception.context["path"], str(source))
        self.assertEqual(caught.exception.context["operation"], "open")
        self.assertEqual(caught.exception.context["winerror"], 5)
        self.assertIn("Access is denied", caught.exception.context["os_error"])

    @unittest.skipUnless(os.name == "posix", "fork preserves injected source access failure")
    def test_pull_worker_retains_denied_file_log_after_exit(self):
        sources = []
        for index in range(8):
            source = self.read / f"output-{index}.txt"
            source.write_text(f"benign-{index}")
            sources.append({"absolute_path": str(source), "relative_path": source.name})
        denied_path = sources[3]["absolute_path"]
        real_open = os.open
        def open_file(path, *args, **kwargs):
            if os.fspath(path) == denied_path:
                denied = PermissionError(errno.EACCES, "Access is denied")
                denied.winerror = 5
                raise denied
            return real_open(path, *args, **kwargs)
        request = guest_test.GuestTests.request(self, "pull", sources, self.host / "result")
        with mock.patch.object(manifest.os, "open", side_effect=open_file):
            self.service.transfer_begin(request)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                status = self.service.transfer_status("trial", request["request_digest"])
                if status["worker"]["stopped"]:
                    break
                time.sleep(0.02)
            else:
                self.fail("worker did not exit")
        self.assertEqual(status["local_phase"], "SOURCE_PREPARING")
        self.assertEqual(status["error"], "source_unavailable")
        log = self.work / "tasks" / "trial" / ("worker-error-" + status["worker"]["nonce"] + ".json")
        self.assertTrue(log.is_file(), "worker must retain its diagnostic before exiting")
        record = json.loads(log.read_bytes())
        self.assertEqual(record["request_digest"], request["request_digest"])
        self.assertEqual(record["job"], "package")
        self.assertEqual(record["error"]["code"], "source_unavailable")
        self.assertEqual(record["error"]["context"]["path"], denied_path)
        self.assertEqual(record["error"]["context"]["winerror"], 5)
        self.assertIn("Access is denied", record["error"]["context"]["os_error"])
        self.assertEqual(log.stat().st_mode & 0o077, 0)
        # An explicit new attempt after producer handoff succeeds for all eight.
        retry = guest_test.GuestTests.request(self, "pull", sources, self.host / "result", transfer_id="repaired")
        self.service.transfer_begin(retry)
        ready = guest_test.GuestTests.wait_phase(self, retry, "SOURCE_READY")
        self.assertIsNone(ready["error"])
        import zipfile
        with zipfile.ZipFile(self.work / "tasks" / "repaired" / "bundle.zip") as bundle:
            for index in range(8):
                self.assertEqual(bundle.read(f"payload/output-{index}.txt"), f"benign-{index}".encode())
        self.assertTrue(log.exists(), "success must not erase the failed attempt")

    def test_stat_and_directory_denials_retain_operation_and_path(self):
        denied = PermissionError(errno.EACCES, "Access is denied")
        real_stat = Path.lstat
        def stat_file(path, *args, **kwargs):
            if path == self.read:
                raise denied
            return real_stat(path, *args, **kwargs)
        specs = [{"absolute_path": str(self.read), "relative_path": "outputs"}]
        for operation, patcher in (
                ("lstat", mock.patch.object(Path, "lstat", stat_file)),
                ("scandir", mock.patch.object(manifest.os, "scandir", side_effect=denied))):
            with self.subTest(operation=operation), patcher, self.assertRaises(Error) as caught:
                manifest.capture_sources(self.read, specs, guest_test.GuestTests.budget(self))
            self.assertEqual(caught.exception.code, "source_unavailable")
            self.assertEqual(caught.exception.context["path"], str(self.read))
            self.assertEqual(caught.exception.context["operation"], operation)
            self.assertEqual(caught.exception.context["errno"], errno.EACCES)

    def test_bundle_payload_open_denial_retains_source_path(self):
        from velo_transfer.bundle import create_bundle
        source = self.read / "output.txt"
        source.write_bytes(b"benign")
        specs = [{"absolute_path": str(source), "relative_path": source.name}]
        budget = guest_test.GuestTests.budget(self)
        inventory = manifest.capture_sources(self.read, specs, budget)
        real_open = os.open
        calls = 0
        def open_file(path, *args, **kwargs):
            nonlocal calls
            if os.fspath(path) == str(source):
                calls += 1
                if calls == 2:  # After preflight hash, during ZIP payload copy.
                    raise PermissionError(errno.EACCES, "Access is denied")
            return real_open(path, *args, **kwargs)
        with mock.patch.object(manifest.os, "open", side_effect=open_file):
            with self.assertRaises(Error) as caught:
                create_bundle(self.read, specs, inventory, self.work / "bundle.zip", self.work, budget)
        self.assertEqual(caught.exception.code, "source_unavailable")
        self.assertEqual(caught.exception.context["path"], str(source))
        self.assertEqual(caught.exception.context["operation"], "open")
        self.assertFalse((self.work / "bundle.zip").exists())
        self.assertEqual(source.read_bytes(), b"benign")


@unittest.skipUnless(os.name == "nt", "native Windows ACL/PowerShell acceptance")
class NativeSourceHandoffTests(unittest.TestCase):
    def test_admin_created_existing_new_and_protected_outputs(self):
        script = Path(__file__).resolve().parents[1] / "configure_transfer_source_access.ps1"
        powershell = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"
        with tempfile.TemporaryDirectory() as temp:
            # No service install, restart or real evidence mutation. Lookup of
            # the deployed virtual account is the only deployment prerequisite.
            command = r'''
$ErrorActionPreference = 'Stop'
$account = [Security.Principal.NTAccount]::new('NT SERVICE\mcp-velociraptor')
try { $sid = $account.Translate([Security.Principal.SecurityIdentifier]) } catch { exit 77 }
$root = Join-Path TASK_ROOT 'outputs'
$null = New-Item -ItemType Directory -Path $root
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = Get-Acl -LiteralPath $root
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-3-4'), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
Set-Acl -LiteralPath $root -AclObject $acl
1..8 | ForEach-Object { [IO.File]::WriteAllText((Join-Path $root "output-$_.txt"), "benign-$_") }
$policy = Join-Path TASK_ROOT 'policy.json'
@{ schema = 'velo.transfer.policy.v1'; read_roots = @($root); work_root = (Join-Path TASK_ROOT 'work') } | ConvertTo-Json | Set-Content -LiteralPath $policy -Encoding UTF8
function Run-Handoff($mode, $source = $root) {
    & TASK_SCRIPT -Mode $mode -PolicyPath $policy -SourceRoot $source | Out-Null
}
$rejected = $false
try { Run-Handoff 'verify' } catch { $rejected = $true }
if (-not $rejected) { throw 'OWNER RIGHTS incorrectly satisfied service read.' }
Run-Handoff 'configure'
Run-Handoff 'verify'
$before = (Get-Acl -LiteralPath $root).Sddl
Run-Handoff 'configure'
if ((Get-Acl -LiteralPath $root).Sddl -cne $before) { throw 'Configure is not idempotent.' }
$nested = Join-Path $root 'new-admin-dir'
$null = New-Item -ItemType Directory -Path $nested
[IO.File]::WriteAllText((Join-Path $nested 'new-admin.txt'), 'new')
Run-Handoff 'verify'
$protected = Join-Path $nested 'new-admin.txt'
$acl = Get-Acl -LiteralPath $protected
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user, 'FullControl', 'Allow'))
Set-Acl -LiteralPath $protected -AclObject $acl
$rejected = $false
try { Run-Handoff 'verify' } catch { $rejected = $true }
if (-not $rejected) { throw 'Protected producer output was accepted without service read.' }
Run-Handoff 'configure'
Run-Handoff 'verify'
$acl = Get-Acl -LiteralPath $protected
$serviceRules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference -eq $sid })
if ($serviceRules.Count -eq 0) { throw 'No service file read grant.' }
foreach ($rule in $serviceRules) {
    if (([int]$rule.FileSystemRights -band [int][Security.AccessControl.FileSystemRights]::Write) -ne 0 -or
        ([int]$rule.FileSystemRights -band [int][Security.AccessControl.FileSystemRights]::Delete) -ne 0 -or
        ([int]$rule.FileSystemRights -band [int][Security.AccessControl.FileSystemRights]::ExecuteFile) -ne 0) { throw 'File grant exceeds Read.' }
}
# A group deny must be reported and preserved, even beside the service allow.
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'), 'Read', 'Deny'))
Set-Acl -LiteralPath $protected -AclObject $acl
$before = (Get-Acl -LiteralPath $protected).Sddl
foreach ($mode in @('configure', 'verify')) {
    $rejected = $false
    try { Run-Handoff $mode } catch { $rejected = $true }
    if (-not $rejected) { throw 'Deny was silently bypassed.' }
}
if ((Get-Acl -LiteralPath $protected).Sddl -cne $before) { throw 'Deny was removed.' }
$rejected = $false
try { Run-Handoff 'configure' TASK_ROOT } catch { $rejected = $true }
if (-not $rejected) { throw 'Outside-policy root accepted.' }
'''.replace("TASK_SCRIPT", quote(script)).replace("TASK_ROOT", quote(temp))
            # A caller running PowerShell 7 can pass its incompatible modules
            # into Windows PowerShell 5.1 through Python's unchanged environment.
            child_env = os.environ.copy()
            child_env["PSModulePath"] = str(Path(os.environ["SystemRoot"]) /
                                          "System32/WindowsPowerShell/v1.0/Modules")
            result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", command],
                                    env=child_env, capture_output=True, text=True, timeout=60)
            if result.returncode == 77:
                self.skipTest("deployed service virtual account not available")
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
