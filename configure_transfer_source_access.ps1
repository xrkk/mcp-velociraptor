# Run elevated on a quiescent, dedicated output read root before pull BEGIN.
# Repeat configure after a producer moves files or supplies protected DACLs.
[CmdletBinding()]
param(
    [ValidateSet('configure', 'verify')]
    [string]$Mode = 'verify',
    [Parameter(Mandatory = $true)]
    [string]$PolicyPath,
    [Parameter(Mandatory = $true)]
    [string]$SourceRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Account = 'NT SERVICE\mcp-velociraptor'
$Sid = ([Security.Principal.NTAccount]::new($Account)).Translate([Security.Principal.SecurityIdentifier])
$Read = [Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Synchronize
$DirectoryRead = $Read -bor [Security.AccessControl.FileSystemRights]::Traverse
$CI = [Security.AccessControl.InheritanceFlags]::ContainerInherit
$OI = [Security.AccessControl.InheritanceFlags]::ObjectInherit
$None = [Security.AccessControl.PropagationFlags]::None
$IO = [Security.AccessControl.PropagationFlags]::InheritOnly
$Allow = [Security.AccessControl.AccessControlType]::Allow

function Get-SafeItem {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSProvider.Name -ne 'FileSystem' -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Not an ordinary filesystem object: $Path"
    }
    return $item
}

function Assert-SafeChain {
    param([string]$Path)
    $item = Get-SafeItem $Path
    while ($null -ne $item) {
        $null = Get-SafeItem $item.FullName
        # Parent returns a plain DirectoryInfo without provider-added properties.
        $item = if ($item -is [IO.DirectoryInfo]) { $item.Parent } else { $item.Directory }
    }
}

function Test-Within {
    param([string]$Path, [string]$Root)
    return $Path.Equals($Root, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Assert-NoReadDeny {
    param($Acl, [string]$Path)
    # A deny on a token group can override the service allow. Do not remove it
    # or claim effective access without the service token: reject conservatively.
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny -and
            ([int]$rule.FileSystemRights -band [int]$DirectoryRead) -ne 0) {
            throw "Read/traverse deny requires operator reconciliation: $Path ($($rule.IdentityReference))"
        }
    }
}

function Test-ServiceGrant {
    param($Acl, [int]$Rights, [int]$Inheritance, [int]$Propagation)
    $mask = 0
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference -eq $Sid -and $rule.AccessControlType -eq $Allow -and
            [int]$rule.PropagationFlags -eq $Propagation -and
            ([int]$rule.InheritanceFlags -band $Inheritance) -eq $Inheritance) {
            $mask = $mask -bor [int]$rule.FileSystemRights
        }
    }
    return ($mask -band $Rights) -eq $Rights
}

Assert-SafeChain $PolicyPath
$policyItem = Get-SafeItem $PolicyPath
if ($policyItem -is [IO.DirectoryInfo] -or $policyItem.Length -gt 1MB) { throw 'Invalid policy file.' }
$policy = Get-Content -LiteralPath $policyItem.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
if ($policy.schema -cne 'velo.transfer.policy.v1') { throw 'Invalid transfer policy schema.' }
Assert-SafeChain $SourceRoot
$root = Get-SafeItem $SourceRoot
if ($root -isnot [IO.DirectoryInfo] -or $null -eq $root.Parent) { throw 'A dedicated output directory is required.' }
$approved = @($policy.read_roots | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') })
if ($root.FullName.TrimEnd('\') -notin $approved) { throw 'SourceRoot must be an exact policy read_root.' }
$work = [IO.Path]::GetFullPath($policy.work_root).TrimEnd('\')
if ((Test-Within $work $root.FullName) -or (Test-Within $root.FullName $work) -or
    (Test-Within $policyItem.FullName $root.FullName)) {
    throw 'Output root must be separate from work_root and the policy file.'
}

# Check all existing members before changing any ACL; never recurse through a
# junction. Administrative producers must stay stopped throughout this handoff.
$items = [Collections.Generic.List[object]]::new()
$pending = [Collections.Generic.Stack[object]]::new()
$pending.Push($root)
while ($pending.Count -gt 0) {
    $item = Get-SafeItem ($pending.Pop().FullName)
    $items.Add($item)
    Assert-NoReadDeny (Get-Acl -LiteralPath $item.FullName) $item.FullName
    if ($item -is [IO.DirectoryInfo]) {
        foreach ($child in Get-ChildItem -LiteralPath $item.FullName -Force) {
            $pending.Push((Get-SafeItem $child.FullName))
        }
    }
}
foreach ($ancestor in @($root.Parent)) {
    while ($null -ne $ancestor) {
        Assert-NoReadDeny (Get-Acl -LiteralPath $ancestor.FullName) $ancestor.FullName
        $ancestor = $ancestor.Parent
    }
}

foreach ($item in $items) {
    try {
        Assert-SafeChain $item.FullName
        $acl = Get-Acl -LiteralPath $item.FullName
        Assert-NoReadDeny $acl $item.FullName
        if ($item -is [IO.DirectoryInfo]) {
            # Traverse/list on directories; Read on files, independently of owner.
            $grants = @(@($DirectoryRead, $CI, $None), @($Read, $OI, $IO))
        } else {
            $grants = ,@($Read, [Security.AccessControl.InheritanceFlags]::None, $None)
        }
        foreach ($grant in $grants) {
            if (-not (Test-ServiceGrant $acl $grant[0] $grant[1] $grant[2])) {
                if ($Mode -eq 'verify') { throw 'Service read grant is missing.' }
                $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    $Sid, $grant[0], $grant[1], $grant[2], $Allow))
            }
        }
        if ($Mode -eq 'configure') { Set-Acl -LiteralPath $item.FullName -AclObject $acl }
        $actual = Get-Acl -LiteralPath $item.FullName
        Assert-NoReadDeny $actual $item.FullName
        foreach ($grant in $grants) {
            if (-not (Test-ServiceGrant $actual $grant[0] $grant[1] $grant[2])) {
                throw 'Service read grant did not persist.'
            }
        }
    } catch {
        throw "Source permission handoff failed at '$($item.FullName)': $($_.Exception.Message)"
    }
}
[ordered]@{ account = $Account; service_sid = $Sid.Value; source_root = $root.FullName
    mode = $Mode; checked_objects = $items.Count; acl_verified = $true } | ConvertTo-Json -Compress
