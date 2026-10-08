"""Native private-config replacement/restore without real secrets or restart."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.name == 'nt', 'native Windows ReplaceFile/ACL acceptance')
class NativeServiceFileUpdateTests(unittest.TestCase):
    def test_replacement_preserves_acl_and_restore_and_rejects_public_input(self):
        script = Path(__file__).resolve().parents[1] / 'update_windows_service_file.ps1'
        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"
        with tempfile.TemporaryDirectory() as temp:
            command = r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$root=TASK_ROOT
$user=[Security.Principal.WindowsIdentity]::GetCurrent().User
$service=([Security.Principal.NTAccount]::new('NT SERVICE\mcp-velociraptor')).Translate([Security.Principal.SecurityIdentifier])
$acl=Get-Acl -LiteralPath $root
$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @($user,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
 $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
Set-Acl -LiteralPath $root -AclObject $acl
$target=Join-Path $root 'config.json'; $replacement=Join-Path $root 'replacement.json'
$backup=Join-Path $root 'original.backup'; $failed=Join-Path $root 'replaced.backup'
[IO.File]::WriteAllText($target,'benign-original')
[IO.File]::WriteAllText($replacement,'benign-replacement')
$acl=Get-Acl -LiteralPath $target
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($service,'Read','Allow'))
Set-Acl -LiteralPath $target -AclObject $acl
$before=(Get-Acl -LiteralPath $target).Sddl
& TASK_SCRIPT -TargetPath $target -AuthorizedPaths @($target) | Out-Null
& TASK_SCRIPT -Mode replace -TargetPath $target -AuthorizedPaths @($target) -ReplacementPath $replacement -BackupPath $backup | Out-Null
if ((Get-Acl -LiteralPath $target).Sddl -cne $before -or [IO.File]::ReadAllText($target) -cne 'benign-replacement' -or [IO.File]::ReadAllText($backup) -cne 'benign-original') { throw 'Replacement did not preserve ACL/content/backup.' }
& TASK_SCRIPT -Mode restore -TargetPath $target -AuthorizedPaths @($target) -ReplacementPath $backup -BackupPath $failed | Out-Null
if ((Get-Acl -LiteralPath $target).Sddl -cne $before -or [IO.File]::ReadAllText($target) -cne 'benign-original' -or [IO.File]::ReadAllText($failed) -cne 'benign-replacement') { throw 'Restore failed.' }
$failedCall=$false
try { & TASK_SCRIPT -TargetPath $replacement -AuthorizedPaths @($replacement) | Out-Null } catch {$failedCall=$true}
if (-not $failedCall) { throw 'New config without service Read was accepted.' }
$acl=Get-Acl -LiteralPath $replacement
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'Read','Allow'))
Set-Acl -LiteralPath $replacement -AclObject $acl
$failedCall=$false
try { & TASK_SCRIPT -Mode replace -TargetPath $target -AuthorizedPaths @($target) -ReplacementPath $replacement -BackupPath (Join-Path $root 'public.backup') | Out-Null } catch {$failedCall=$true}
if (-not $failedCall -or [IO.File]::ReadAllText($target) -cne 'benign-original' -or (Get-Acl -LiteralPath $target).Sddl -cne $before) { throw 'Public replacement input was accepted or target changed.' }
$failedCall=$false
try { & TASK_SCRIPT -TargetPath $target -AuthorizedPaths @($replacement) | Out-Null } catch {$failedCall=$true}
if (-not $failedCall) { throw 'Outside authorized file accepted.' }
'''.replace('TASK_ROOT', quote(temp)).replace('TASK_SCRIPT', quote(script))
            env = os.environ.copy()
            powershell = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
            env['PSModulePath'] = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/Modules')
            result = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-Command', command],
                                    env=env, capture_output=True, encoding='utf-8', errors='replace', timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
