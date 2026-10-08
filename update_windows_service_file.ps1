# Preserve the protected destination ACL when replacing an authorized config.
# No service restart and no file contents in output. Backup is retained.
[CmdletBinding()]
param(
    [ValidateSet('verify','replace','restore')][string]$Mode='verify',
    [Parameter(Mandatory=$true)][string]$TargetPath,
    [Parameter(Mandatory=$true)][string[]]$AuthorizedPaths,
    [string]$ReplacementPath,
    [string]$BackupPath
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$serviceSid=([Security.Principal.NTAccount]::new('NT SERVICE\mcp-velociraptor')).Translate([Security.Principal.SecurityIdentifier])
$trusted=@('S-1-5-18','S-1-5-32-544',$serviceSid.Value,[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
$read=[int][Security.AccessControl.FileSystemRights]::Read
$privateReadMask=$read -bor 0x80000000
$writeMask=0x116 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
$temporary=$null
function OrdinaryFile([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\') -or $Path -match '(^|[\\/])\.\.?([\\/]|$)') { throw "Ordinary absolute local file required: $Path" }
    $item=Get-Item -LiteralPath $Path -Force
    if ($item -is [IO.DirectoryInfo] -or $item.Length -gt 1MB) { throw "Bounded configuration file required: $Path" }
    $current=$item
    while($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse path refused: $Path" }
        $current=if($current -is [IO.DirectoryInfo]){$current.Parent}else{$current.Directory}
    }
    return $item
}
function Verify-PrivateAcl([string]$Path,[bool]$RequireServiceRead) {
    $acl=Get-Acl -LiteralPath $Path
    $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $trusted) { throw "Untrusted config owner: $Path" }
    $granted=0
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        $sid=$rule.IdentityReference.Value
        $mask=[int]$rule.FileSystemRights
        if ($rule.AccessControlType -eq 'Deny' -and ($mask -band $read) -ne 0) { throw "Config read deny requires reconciliation: $Path" }
        if ($rule.AccessControlType -eq 'Allow') {
            if ($sid -notin $trusted -and $sid -ne 'S-1-3-4' -and ($mask -band ($privateReadMask -bor $writeMask)) -ne 0) { throw "Untrusted config access: $Path" }
            if ($sid -eq $serviceSid.Value -and $rule.PropagationFlags -ne 'InheritOnly') {
                $granted=$granted -bor $mask
                if (($mask -band $writeMask) -ne 0) { throw "Service config grant must remain read-only: $Path" }
            }
        }
    }
    if ($RequireServiceRead -and ($granted -band $read) -ne $read) { throw "Service file Read grant missing: $Path" }
    return $acl
}
try {
    $target=OrdinaryFile $TargetPath
    $allowed=@($AuthorizedPaths | ForEach-Object {[IO.Path]::GetFullPath($_)})
    if ($target.FullName -notin $allowed) { throw 'Target is not an explicitly authorized config file.' }
    $before=Verify-PrivateAcl $target.FullName $true
    $beforeHash=(Get-FileHash -LiteralPath $target.FullName -Algorithm SHA256).Hash
    if ($Mode -ne 'verify') {
        $input=OrdinaryFile $ReplacementPath
        $null=Verify-PrivateAcl $input.FullName $false
        if ($input.FullName -eq $target.FullName) { throw 'Replacement must be an independent file.' }
        if ([string]::IsNullOrEmpty($BackupPath) -or -not [IO.Path]::IsPathRooted($BackupPath) -or
            $BackupPath.StartsWith('\\') -or $BackupPath -match '(^|[\\/])\.\.?([\\/]|$)' -or
            [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($BackupPath)) -cne $target.DirectoryName -or
            (Test-Path -LiteralPath $BackupPath)) { throw 'A new backup path in the protected target directory is required.' }
        $temporary=Join-Path $target.DirectoryName ('.service-replace-'+[Guid]::NewGuid().ToString('N'))
        $sourceStream=$null; $targetStream=$null
        try {
            $sourceStream=[IO.File]::Open($input.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            $targetStream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            $sourceStream.CopyTo($targetStream,1048576)
            $targetStream.Flush($true)
        } finally {
            if($null -ne $targetStream){$targetStream.Dispose()}
            if($null -ne $sourceStream){$sourceStream.Dispose()}
        }
        # The temporary config is private from creation; install the exact
        # original owner/DACL before publishing, also covering OWNER RIGHTS.
        Set-Acl -LiteralPath $temporary -AclObject $before
        $expected=(Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash
        if ((Get-FileHash -LiteralPath $target.FullName -Algorithm SHA256).Hash -cne $beforeHash -or
            (Get-Acl -LiteralPath $target.FullName).Sddl -cne $before.Sddl) { throw 'Destination changed before replacement.' }
        [IO.File]::Replace($temporary,$target.FullName,$BackupPath,$false)
        $temporary=$null
        $after=Verify-PrivateAcl $target.FullName $true
        if ($after.Sddl -cne $before.Sddl -or
            (Get-FileHash -LiteralPath $target.FullName -Algorithm SHA256).Hash -cne $expected) {
            throw 'Published config verification failed; inspect retained backup before restore.'
        }
        $null=Verify-PrivateAcl $BackupPath $true
    }
    [ordered]@{schema='velo.service-file-update.v1'; mode=$Mode; target_path=$target.FullName
        service_read_verified=$true; acl_preserved=$true; backup_path=$BackupPath
        sha256=(Get-FileHash -LiteralPath $target.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json -Compress
} catch {
    $native=$_.Exception.GetBaseException()
    $record=[ordered]@{schema='velo.service-file-update.error.v1'; operation=$Mode; target_path=$TargetPath
        replacement_path=$ReplacementPath; backup_path=$BackupPath; temporary_path=$temporary
        exception_type=$native.GetType().FullName; hresult=$native.HResult
        native_error_code=$(if($native -is [IO.IOException] -or $native -is [UnauthorizedAccessException]){$native.HResult -band 0xffff}else{$null})
        os_error=$native.Message}
    $bytes=[Text.Encoding]::UTF8.GetBytes(($record|ConvertTo-Json -Compress)+[Environment]::NewLine)
    $stream=[Console]::OpenStandardError(); $stream.Write($bytes,0,$bytes.Length); $stream.Flush()
    throw
}
