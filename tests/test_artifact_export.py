"""Native acceptance of the producer/export seam, including real sharing errors."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.name == 'nt', 'native Windows sharing and ACL checks')
class NativeArtifactExportTests(unittest.TestCase):
    def test_verified_copy_handoff_and_guarded_failures(self):
        script = Path(__file__).resolve().parents[1] / 'export_transfer_artifacts.ps1'
        powershell = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"
        with tempfile.TemporaryDirectory() as temp:
            command = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$base = TASK_BASE
$root = Join-Path $base 'export'
$sourceRoot = Join-Path $base 'producer'
$null = New-Item -ItemType Directory -Path $root,$sourceRoot
$sid = ([Security.Principal.NTAccount]::new('NT SERVICE\mcp-velociraptor')).Translate([Security.Principal.SecurityIdentifier])
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = Get-Acl -LiteralPath $root
$acl.SetAccessRuleProtection($true,$false)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
Set-Acl -LiteralPath $root -AclObject $acl
$policyPath = Join-Path $base 'policy.json'
@{schema='velo.transfer.policy.v1'; read_roots=@($root); work_root=(Join-Path $base 'work'); limits=@{max_files=20; max_logical_bytes=1048576; max_duration_seconds=60}} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $policyPath -Encoding UTF8
$source = Join-Path $sourceRoot 'report-管理员.txt'
[IO.File]::WriteAllText($source,'benign export',[Text.UTF8Encoding]::new($false))
$ownerBefore = (Get-Acl -LiteralPath $source).Sddl
$hash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
$manifestPath = Join-Path $base 'manifest.json'
$manifest = @{schema='velo.artifact-export.v1'; producer='Windows-MCP'; batch_id='first'; source_root=$sourceRoot; producer_complete=$true; producer_quiescent=$true; references=@('native-closed-output'); files=@(@{path=$source; relative_path='nested/report.txt'; size=(Get-Item -LiteralPath $source).Length; sha256=$hash; complete=$true})}
function Save-Manifest { $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8 }
function Export { & TASK_SCRIPT -ManifestPath $manifestPath -PolicyPath $policyPath -OutputRoot $root }
Save-Manifest
$result = Export | ConvertFrom-Json
if (-not $result.export_complete -or -not $result.acl_verified) { throw 'Export did not complete.' }
$target = Join-Path $result.output_directory 'nested/report.txt'
if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash -or
    (Get-Acl -LiteralPath $source).Sddl -cne $ownerBefore) { throw 'Copy/source preservation failed.' }
$receipt = Get-Content -LiteralPath $result.receipt_path -Raw | ConvertFrom-Json
if ($receipt.files[0].sha256 -cne $hash -or $receipt.source_manifest_sha256 -cne (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()) { throw 'Receipt binding failed.' }
$rules = @((Get-Acl -LiteralPath $target).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {$_.IdentityReference -eq $sid})
if ($rules.Count -eq 0) { throw 'Service Read grant missing.' }
foreach ($rule in $rules) { if (([int]$rule.FileSystemRights -band (0x10000 -bor 0x40000 -bor 0x80000 -bor 0x116 -bor 0x20)) -ne 0) { throw 'Export grant exceeds file Read.' } }
function Reject([string]$label) {
    $before = (Get-Acl -LiteralPath $source).Sddl
    $failed = $false
    try { Export | Out-Null } catch { $failed=$true }
    if (-not $failed -or (Get-Acl -LiteralPath $source).Sddl -cne $before) { throw "Rejection/preservation failed: $label" }
    if ($manifest.batch_id -ne 'first' -and (Test-Path -LiteralPath (Join-Path $root $manifest.batch_id))) { throw "Failed export was published: $label" }
}
Reject 'existing destination'
$manifest.batch_id='incomplete'; $manifest.producer_complete=$false; Save-Manifest; Reject 'producer active'
$manifest.producer_complete=$true; $manifest.files[0].complete=$false; Save-Manifest; Reject 'unpublished artifact'
$manifest.files[0].complete=$true; $manifest.batch_id='mismatch'; $manifest.files[0].sha256=('0'*64); Save-Manifest; Reject 'wrong digest'
$manifest.files[0].sha256=$hash; $manifest.batch_id='escape'; $manifest.files[0].relative_path='../escape.txt'; Save-Manifest; Reject 'relative escape'
$manifest.files[0].relative_path='nested/report.txt'; $manifest.batch_id='sharing'; Save-Manifest
$writer = [IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
try { Reject 'active writer' } finally { $writer.Dispose() }
$native = @(Get-ChildItem -LiteralPath $root -Filter '.handoff-error-*.json' | ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 | ConvertFrom-Json} | Where-Object {$_.operation -eq 'copy' -and $_.native_error_code -eq 32})
if ($native.Count -ne 1 -or $native[0].source_path -cne $source -or [string]::IsNullOrWhiteSpace($native[0].destination_path)) { throw 'Real sharing diagnostic was lost.' }
$manifest.batch_id='second'; Save-Manifest; $null=Export
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash) { throw 'Original content changed.' }
@{case='native-export'; passed=$true; positive_batches=2; real_sharing_error=32} | ConvertTo-Json -Compress
'''.replace('TASK_SCRIPT', quote(script)).replace('TASK_BASE', quote(temp))
            env = os.environ.copy()
            env['PSModulePath'] = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/Modules')
            result = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-Command', command],
                                    capture_output=True, text=True, encoding='utf-8', errors='replace', env=env, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout.strip().splitlines()[-1])
            self.assertTrue(summary['passed'])
            self.assertEqual(summary['real_sharing_error'], 32)


if __name__ == '__main__':
    unittest.main()
