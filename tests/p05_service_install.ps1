# P05 formal-entry service and firewall installation for the MCP bridge.
#
# Modes:
#   install   - create the mcp-velociraptor Windows service and the single
#               28790 firewall rule; repeated runs are no-ops.
#   verify    - read-only check of every installed fact this script owns.
#   rollback  - remove only the service and rule this script created.
#
# Security contract (P05 0.4):
#   * The service runs as the virtual account NT SERVICE\mcp-velociraptor,
#     never as LocalSystem, an admin user, or the installer account.
#   * The bearer token is never accepted as a parameter and never appears in
#     the process command line, logs, or this repository. The deployer places
#     it in a protected env file; this script only references that file.
#   * The bind address must be an existing host-only adapter address measured
#     on this machine; wildcard binds are rejected before any service exists.
#   * Rollback touches only the exact service and rule names defined here.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('install', 'verify', 'rollback')]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$RepoRoot,

    [Parameter(Mandatory = $true)]
    [string]$ProtectedEnvFile,

    [Parameter(Mandatory = $true)]
    [string]$BindAddress,

    [Parameter(Mandatory = $true)]
    [string]$HostAddress,

    [Parameter(Mandatory = $true)]
    [guid]$AttemptId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ServiceName = 'mcp-velociraptor'
$ServiceDisplayName = 'Velociraptor MCP formal entry'
$FirewallRuleName = 'mcp-velociraptor-28790'
$FirewallPort = 28790
$RunAsAccount = 'NT SERVICE\mcp-velociraptor'
$Wildcards = @('0.0.0.0', '::', '')
$Owner = 'P05:' + $AttemptId.ToString('D')
$ServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$Python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
$ServiceHost = Join-Path $RepoRoot 'tests\p05_service_host.py'
$ExpectedBinary = "`"$Python`" `"$ServiceHost`""
if ($AttemptId -eq [guid]::Empty) { throw 'AttemptId must identify a real deployment attempt.' }

function Assert-IPv4 {
    param([string]$Address)
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $parsed.ToString() -cne $Address -or $parsed.GetAddressBytes()[0] -eq 0 -or
        $parsed.GetAddressBytes()[0] -eq 127 -or $parsed.GetAddressBytes()[0] -ge 224) {
        throw 'An exact unicast IPv4 address is required.'
    }
}

function Assert-BindAddress {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address) -or $Wildcards -contains $Address) {
        throw "BindAddress must be an exact host address, not a wildcard bind."
    }
    Assert-IPv4 $Address
    Assert-IPv4 $HostAddress
    if ($Address -eq $HostAddress) { throw 'Host and guest addresses must differ.' }
    $measured = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq $Address)
    if ($measured.Count -ne 1 -or $measured[0].AddressState -ne 'Preferred' -or
        $measured[0].PrefixOrigin -ne 'Manual') { throw 'The guest bind must be a unique preferred static address.' }
}

function Assert-LocalFileSystemPath {
    param([string]$Path)
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path -match '["\r\n\x00]' -or
        [IO.Path]::GetFullPath($Path).TrimEnd('\') -cne $Path.TrimEnd('\')) {
        throw 'Deployment paths must be canonical absolute local drive paths.'
    }
    # Walk every ancestor through Get-Item: .Parent/.Directory return .NET
    # instances without the provider-added PSProvider property, which StrictMode
    # turns into a hard error from the second level upward.
    $segments = @($Path -split '\\' | Where-Object { $_ -ne '' })
    for ($index = 1; $index -lt $segments.Count; $index++) {
        $prefix = ($segments[0..$index] -join '\')
        $ancestor = Get-Item -LiteralPath $prefix -Force -ErrorAction Stop
        if ($ancestor.PSProvider.Name -ne 'FileSystem' -or
            ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Deployment paths must not traverse reparse points or other providers.'
        }
    }
}

function Assert-DeploymentPaths {
    foreach ($required in @($RepoRoot, $Python, $ServiceHost, $ProtectedEnvFile)) {
        Assert-LocalFileSystemPath $required
    }
    if (-not (Test-Path -LiteralPath $RepoRoot -PathType Container)) {
        throw 'Repository root must be a directory.'
    }
    foreach ($required in @($Python, $ServiceHost, $ProtectedEnvFile)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw 'A required deployment file is missing.'
        }
    }
}

function Get-RunAsSid {
    $output = @(sc.exe showsid $ServiceName)
    if ($LASTEXITCODE -ne 0) { throw 'The virtual service SID could not be resolved.' }
    $matches = [regex]::Matches(($output -join "`n"), 'S-1-5-80-(?:[0-9]+-){4}[0-9]+')
    if ($matches.Count -ne 1) { throw 'The virtual service SID is ambiguous.' }
    return $matches[0].Value
}

function Assert-PathAcl {
    param([string]$Path, [ValidateSet('code', 'secret', 'download')][string]$Role,
          [string]$ServiceSid)
    Assert-LocalFileSystemPath $Path
    $acl = Get-Acl -LiteralPath $Path
    $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    $administrators = @('S-1-5-18', 'S-1-5-32-544')
    $mutating = [int64]([Security.AccessControl.FileSystemRights]::Write) -bor
        [int64]([Security.AccessControl.FileSystemRights]::Delete) -bor
        [int64]([Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -bor
        [int64]([Security.AccessControl.FileSystemRights]::ChangePermissions) -bor
        [int64]([Security.AccessControl.FileSystemRights]::TakeOwnership) -bor 0x50000000
    $serviceRights = [int64]0
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        $mask = [int64]$rule.FileSystemRights
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) {
            # Do not guess effective rights through a deny/group interaction.
            throw 'Deployment ACL contains a deny entry requiring reconciliation.'
        }
        if ($Role -eq 'secret' -and $sid -notin ($administrators + @($ServiceSid))) {
            throw 'Protected configuration ACL grants another principal access.'
        }
        if (($mask -band $mutating) -ne 0 -and $sid -notin $administrators -and
            -not ($Role -eq 'download' -and $sid -eq $ServiceSid)) {
            throw 'Deployment ACL grants an unapproved principal write access.'
        }
        if ($sid -eq $ServiceSid -and $Role -eq 'download' -and
            ($mask -band 0x100C0000) -ne 0) {
            throw 'Service write access must not include permission-management rights.'
        }
        if ($sid -eq $ServiceSid -and
            -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) {
            $serviceRights = $serviceRights -bor $mask
        }
    }
    if ($Role -eq 'secret') { $required = [int64]([Security.AccessControl.FileSystemRights]::Read) }
    elseif ($Role -eq 'download') { $required = [int64]([Security.AccessControl.FileSystemRights]::Modify) }
    else { $required = [int64]([Security.AccessControl.FileSystemRights]::ReadAndExecute) }
    if (($serviceRights -band $required) -ne $required) {
        throw 'Deployment ACL lacks the explicit service access required for this role.'
    }
}

function Assert-CodeTreeAcl {
    param([string]$ServiceSid)
    $pending = [Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($RepoRoot)
    $logs = Join-Path $RepoRoot 'Logs'
    Assert-PathAcl -Path $logs -Role download -ServiceSid $ServiceSid
    while ($pending.Count -gt 0) {
        $path = $pending.Dequeue()
        if ($path -ieq $logs) { continue } # Runtime logs are not executable source.
        Assert-PathAcl -Path $path -Role code -ServiceSid $ServiceSid
        if (Test-Path -LiteralPath $path -PathType Container) {
            foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($path)) {
                $pending.Enqueue($entry)
            }
        }
    }
}

function Assert-ProtectedEnv {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "Protected env file is missing: deployer must place it before install."
    }
    $serviceSid = Get-RunAsSid
    Assert-PathAcl -Path $Path -Role secret -ServiceSid $serviceSid
    $content = Get-Content -LiteralPath $Path -ErrorAction Stop
    $required = @(
        'VELOCIRAPTOR_MCP_TRANSPORT=http',
        'VELOCIRAPTOR_MCP_HOST=',
        'VELOCIRAPTOR_MCP_BEARER_TOKEN=',
        'VELOCIRAPTOR_API_CONFIG=',
        'VELOCIRAPTOR_DOWNLOAD_ROOT='
    )
    foreach ($prefix in $required) {
        if (-not ($content | Where-Object { $_ -like "$prefix*" })) {
            throw "Protected env file lacks required setting prefix '$prefix'."
        }
    }
    $settings = @{}
    foreach ($line in $content) {
        $entry = $line.Trim()
        if (-not $entry -or $entry.StartsWith('#')) { continue }
        $pair = $entry -split '=', 2
        if ($pair.Count -ne 2) { throw 'Invalid protected configuration format.' }
        $name = $pair[0].Trim()
        if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$' -or $name -ceq 'VELOCIRAPTOR_ENV_FILE') {
            throw 'Invalid protected configuration key.'
        }
        if ($settings.ContainsKey($name)) { throw 'Duplicate protected configuration key.' }
        $settings[$name] = $pair[1].Trim()
    }
    if ($settings['VELOCIRAPTOR_MCP_TRANSPORT'] -cne 'http' -or
        $settings['VELOCIRAPTOR_MCP_HOST'] -cne $BindAddress -or
        [string]::IsNullOrWhiteSpace($settings['VELOCIRAPTOR_API_CONFIG']) -or
        [string]::IsNullOrWhiteSpace($settings['VELOCIRAPTOR_DOWNLOAD_ROOT']) -or
        [string]::IsNullOrWhiteSpace($settings['VELOCIRAPTOR_MCP_BEARER_TOKEN']) -or
        $settings['VELOCIRAPTOR_MCP_BEARER_TOKEN'].Length -lt 32) {
        throw 'Protected configuration does not satisfy the formal endpoint contract.'
    }
    Assert-LocalFileSystemPath $settings['VELOCIRAPTOR_API_CONFIG']
    Assert-LocalFileSystemPath $settings['VELOCIRAPTOR_DOWNLOAD_ROOT']
    if (-not (Test-Path -LiteralPath $settings['VELOCIRAPTOR_API_CONFIG'] -PathType Leaf) -or
        -not (Test-Path -LiteralPath $settings['VELOCIRAPTOR_DOWNLOAD_ROOT'] -PathType Container)) {
        throw 'The service API configuration and download directory must exist.'
    }
    Assert-PathAcl -Path $settings['VELOCIRAPTOR_API_CONFIG'] -Role secret -ServiceSid $serviceSid
    Assert-PathAcl -Path $settings['VELOCIRAPTOR_DOWNLOAD_ROOT'] -Role download -ServiceSid $serviceSid
    Assert-CodeTreeAcl -ServiceSid $serviceSid
    # Values are read only inside this process; never print content or exceptions
    # containing individual configuration lines.
}

function Get-ServiceOrNull {
    Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
}

function Get-RuleOrNull {
    Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {
        $_.Name -eq $FirewallRuleName -or $_.DisplayName -eq $FirewallRuleName
    }
}

function Assert-ServiceIdentity {
    param($Service)
    if ($Service.StartName -ne $RunAsAccount -or $Service.PathName -cne $ExpectedBinary -or
        $Service.StartMode -notin @('Manual', 'Auto')) { throw 'Existing service identity differs; refusing to touch it.' }
    $environment = Get-ItemProperty -LiteralPath ($ServiceKey + '\Environment')
    if ($environment.VELOCIRAPTOR_ENV_FILE -isnot [string] -or
        $environment.VELOCIRAPTOR_ENV_FILE -cne $ProtectedEnvFile) {
        throw 'Service protected environment reference differs.'
    }
}

function Assert-RuleIdentity {
    param($Rule)
    $ports = @($Rule | Get-NetFirewallPortFilter)
    $addresses = @($Rule | Get-NetFirewallAddressFilter)
    if ($Rule.Name -ne $FirewallRuleName -or $Rule.DisplayName -ne $FirewallRuleName -or
        $Rule.Direction -ne 'Inbound' -or $Rule.Action -ne 'Allow' -or $Rule.Enabled -ne 'True' -or
        $ports.Count -ne 1 -or $addresses.Count -ne 1 -or
        [string]$ports[0].Protocol -notin @('TCP','6') -or
        @($ports[0].LocalPort).Count -ne 1 -or [string]$ports[0].LocalPort -ne '28790' -or
        @($addresses[0].LocalAddress).Count -ne 1 -or [string]$addresses[0].LocalAddress -ne $BindAddress -or
        @($addresses[0].RemoteAddress).Count -ne 1 -or [string]$addresses[0].RemoteAddress -ne $HostAddress) {
        throw 'Existing firewall rule differs from the exact guest/host boundary.'
    }
}

function Invoke-Install {
    Assert-BindAddress -Address $BindAddress
    Assert-DeploymentPaths
    Assert-ProtectedEnv -Path $ProtectedEnvFile

    foreach ($required in @($Python, $ServiceHost, $ProtectedEnvFile)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Required file missing: $required"
        }
    }

    $existing = Get-ServiceOrNull
    $rules = @(Get-RuleOrNull)
    if ($rules.Count -gt 1) { throw 'Ambiguous firewall rule identity.' }
    if ($rules.Count -eq 1) { Assert-RuleIdentity $rules[0] }
    if ($null -ne $existing) { Assert-ServiceIdentity $existing }
    if ($null -ne $existing) {
        Write-Output "service: already installed; install is a no-op"
    } else {
        # The command line carries only paths; the token stays in the protected env
        # referenced through the service-scoped VELOCIRAPTOR_ENV_FILE variable.
        $binPath = $ExpectedBinary
        sc.exe create $ServiceName binPath= $binPath obj= $RunAsAccount start= demand DisplayName= $ServiceDisplayName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe create failed with exit code $LASTEXITCODE"
        }
        $envRegistryKey = $ServiceKey + '\Environment'
        New-Item -Path $envRegistryKey -Force | Out-Null
        New-ItemProperty -LiteralPath $envRegistryKey -Name VELOCIRAPTOR_ENV_FILE -PropertyType String -Value $ProtectedEnvFile | Out-Null
        New-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name P05CreatedBy -PropertyType String -Value $Owner | Out-Null
        Write-Output "service: created as $RunAsAccount with protected env reference"
    }

    if ($rules.Count -eq 1) {
        Write-Output "firewall: rule already present; install is a no-op"
    } else {
        New-NetFirewallRule -Name $FirewallRuleName -DisplayName $FirewallRuleName -Description $Owner `
            -Direction Inbound -Action Allow -Protocol TCP `
            -LocalPort $FirewallPort -LocalAddress $BindAddress -RemoteAddress $HostAddress | Out-Null
        Write-Output "firewall: created exact guest/host TCP boundary"
    }
    Invoke-Verify
}

function Invoke-Verify {
    Assert-BindAddress $BindAddress
    Assert-DeploymentPaths
    Assert-ProtectedEnv -Path $ProtectedEnvFile
    $result = [ordered]@{
        service_exists        = $false
        service_account       = $null
        service_start_mode    = $null
        service_binary_python = $false
        firewall_rule_unique  = $false
        firewall_port         = $null
    }
    $service = Get-ServiceOrNull
    if ($null -ne $service) {
        $result.service_exists = $true
        Assert-ServiceIdentity $service
        $result.service_account = $service.StartName
        $result.service_start_mode = $service.StartMode
        $result.service_binary_python = $true
    }
    $rules = @(Get-RuleOrNull)
    if ($rules.Count -eq 1) {
        Assert-RuleIdentity $rules[0]
        $result.firewall_rule_unique = $true
        $portFilter = $rules[0] | Get-NetFirewallPortFilter
        $result.firewall_port = $portFilter.LocalPort
    }
    if ($null -eq $service -or $rules.Count -ne 1) { throw 'Deployment is incomplete.' }
    Write-Output ($result | ConvertTo-Json -Compress)
}

function Invoke-Rollback {
    $service = Get-ServiceOrNull
    $rules = @(Get-RuleOrNull)
    # Validate the entire removal set before the first destructive operation.
    if ($rules.Count -gt 1) { throw 'Ambiguous firewall rule identity.' }
    if ($null -ne $service) {
        Assert-ServiceIdentity $service
        $tag = Get-ItemProperty -LiteralPath $ServiceKey -Name P05CreatedBy
        if ($tag.P05CreatedBy -cne $Owner -or $service.State -ne 'Stopped') {
            throw 'Rollback requires this attempt ownership and an already stopped service.'
        }
    }
    if ($rules.Count -eq 1) {
        Assert-RuleIdentity $rules[0]
        if ($rules[0].Description -cne $Owner) { throw 'Firewall rule was not created by this attempt.' }
    }
    if ($null -ne $service) {
        sc.exe delete $ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Service deletion failed; preserve partial rollback evidence.' }
        Write-Output "service: deleted"
    } else {
        Write-Output "service: absent; nothing to roll back"
    }
    if ($rules.Count -gt 0) {
        $rules | Remove-NetFirewallRule
        Write-Output "firewall: removed $($rules.Count) owned rule(s)"
    } else {
        Write-Output "firewall: absent; nothing to roll back"
    }
}

$mutex = [Threading.Mutex]::new($false, 'Global\VelociraptorMCP-P05-Deployment')
$acquired = $false
try {
    try { $acquired = $mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] {
        # Ownership is acquired by WaitOne, but a partial installation needs
        # manual evidence reconciliation; do not silently continue.
        $acquired = $true
        throw 'Previous deployment was interrupted; reconcile its original evidence first.'
    }
    if (-not $acquired) { throw 'Another deployment operation is active.' }
    switch ($Mode) {
        'install' { Invoke-Install }
        'verify' { Invoke-Verify }
        'rollback' { Invoke-Rollback }
    }
} finally {
    if ($acquired) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
