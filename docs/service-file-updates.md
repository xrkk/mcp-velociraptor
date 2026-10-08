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
