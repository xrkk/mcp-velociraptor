# Private service configuration updates


`update_windows_service_file.ps1 -Mode verify` validates an explicitly authorized
target's private ACL and service Read. `-Mode replace` requires a private
ReplacementPath and unused BackupPath in the target's protected directory.
It writes a private temporary copy, applies the original owner/DACL, checks the
original has not changed, uses Windows File.Replace, and verifies final content,
ACL and retained backup. `-Mode restore` uses that same operation with the prior
backup as ReplacementPath and a new backup name, preserving the failed version.
Output contains identifiers/hashes, never credentials or file contents.
It does not restart services. Separately verify actual service loading after a
controlled update; refuse maintenance if another transfer worker is active.
This workflow never requires a VM reboot or snapshot restore.

Use deployment-provided absolute paths; keep the authorized target list explicit
and prepare the replacement privately in the protected directory. Each backup
name must be unused. These commands verify files only, not service loading:

```powershell
$UpdateScript = Join-Path $VeloRepository 'update_windows_service_file.ps1'
& $UpdateScript -Mode verify -TargetPath $TargetPath -AuthorizedPaths @($TargetPath)
& $UpdateScript -Mode replace -TargetPath $TargetPath -AuthorizedPaths @($TargetPath) `
  -ReplacementPath $ReplacementPath -BackupPath $BackupPath
```

After authorized service maintenance, verify the running service's actual
configuration and capabilities. If loading fails, retain the failure diagnostics
and restore the prior bytes with a second, unused backup path:

```powershell
& $UpdateScript -Mode restore -TargetPath $TargetPath -AuthorizedPaths @($TargetPath) `
  -ReplacementPath $BackupPath -BackupPath $FailedVersionBackupPath
```

Recheck actual loading after restoration. Keep both backups and owned temporary
failure files until their identities and references have been reviewed. Never
copy credentials into the shared artifact output root.
