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
    [string]$BindAddress
)

$ErrorActionPreference = 'Stop'

$ServiceName = 'mcp-velociraptor'
$ServiceDisplayName = 'Velociraptor MCP formal entry'
$FirewallRuleName = 'mcp-velociraptor-28790'
$FirewallPort = 28790
$RunAsAccount = 'NT SERVICE\mcp-velociraptor'
$Wildcards = @('0.0.0.0', '::', '')

function Assert-BindAddress {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address) -or $Wildcards -contains $Address) {
        throw "BindAddress must be an exact host address, not a wildcard bind."
    }
    $measured = Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -like '192.168.204.*' } |
        Select-Object -ExpandProperty IPAddress
    if ($measured -notcontains $Address) {
        throw "BindAddress '$Address' is not a measured host-only adapter address on this machine: $($measured -join ', ')"
    }
}

function Assert-ProtectedEnv {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "Protected env file is missing: deployer must place it before install."
    }
    $content = Get-Content $Path -ErrorAction Stop
    $required = @(
        'VELOCIRAPTOR_MCP_TRANSPORT=http',
        'VELOCIRAPTOR_MCP_HOST=',
        'VELOCIRAPTOR_MCP_BEARER_TOKEN='
    )
    foreach ($prefix in $required) {
        if (-not ($content | Where-Object { $_ -like "$prefix*" })) {
            throw "Protected env file lacks required setting prefix '$prefix'."
        }
    }
    # The token value itself is never read, echoed, or logged here.
}

function Get-ServiceOrNull {
    Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
}

function Get-RuleOrNull {
    Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction SilentlyContinue
}

function Invoke-Install {
    Assert-BindAddress -Address $BindAddress
    Assert-ProtectedEnv -Path $ProtectedEnvFile

    $python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
    $bridge = Join-Path $RepoRoot 'mcp_velociraptor_bridge.py'
    foreach ($required in @($python, $bridge, $ProtectedEnvFile)) {
        if (-not (Test-Path $required)) {
            throw "Required file missing: $required"
        }
    }

    $existing = Get-ServiceOrNull
    if ($null -ne $existing) {
        if ($existing.UserName -ne $RunAsAccount) {
            throw "Existing service '$ServiceName' does not run as $RunAsAccount; refusing to touch it."
        }
        Write-Output "service: already installed; install is a no-op"
    } else {
        # The command line carries only paths; the token stays in the protected env
        # referenced through the service-scoped VELOCIRAPTOR_ENV_FILE variable.
        $binPath = "`"$python`" `"$bridge`""
        sc.exe create $ServiceName binPath= $binPath obj= $RunAsAccount start= demand DisplayName= $ServiceDisplayName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe create failed with exit code $LASTEXITCODE"
        }
        $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Environment"
        New-Item -Path $serviceKey -Force | Out-Null
        Set-ItemProperty -Path $serviceKey -Name VELOCIRAPTOR_ENV_FILE -Value ([string[]]@($ProtectedEnvFile))
        Write-Output "service: created as $RunAsAccount with protected env reference"
    }

    $rule = Get-RuleOrNull
    if ($null -ne $rule) {
        Write-Output "firewall: rule already present; install is a no-op"
    } else {
        New-NetFirewallRule -DisplayName $FirewallRuleName `
            -Direction Inbound -Action Allow -Protocol TCP `
            -LocalPort $FirewallPort -RemoteAddress '192.168.204.0/24' | Out-Null
        Write-Output "firewall: created inbound TCP $FirewallPort for the host-only subnet"
    }
}

function Invoke-Verify {
    $result = [ordered]@{
        service_exists        = $false
        service_account       = $null
        service_binary_python = $false
        firewall_rule_unique  = $false
        firewall_port         = $null
    }
    $service = Get-ServiceOrNull
    if ($null -ne $service) {
        $result.service_exists = $true
        $result.service_account = $service.UserName
        $wmi = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
        $result.service_binary_python = ($wmi.PathName -like '*python.exe*') -and ($wmi.PathName -like '*mcp_velociraptor_bridge.py*')
    }
    $rules = @(Get-RuleOrNull)
    if ($rules.Count -eq 1) {
        $result.firewall_rule_unique = $true
        $portFilter = $rules[0] | Get-NetFirewallPortFilter
        $result.firewall_port = $portFilter.LocalPort
    }
    Write-Output ($result | ConvertTo-Json -Compress)
}

function Invoke-Rollback {
    $service = Get-ServiceOrNull
    if ($null -ne $service) {
        if ($service.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force
        }
        sc.exe delete $ServiceName | Out-Null
        Write-Output "service: deleted"
    } else {
        Write-Output "service: absent; nothing to roll back"
    }
    $rules = @(Get-RuleOrNull)
    if ($rules.Count -gt 0) {
        $rules | Remove-NetFirewallRule
        Write-Output "firewall: removed $($rules.Count) owned rule(s)"
    } else {
        Write-Output "firewall: absent; nothing to roll back"
    }
}

switch ($Mode) {
    'install' { Invoke-Install }
    'verify' { Invoke-Verify }
    'rollback' { Invoke-Rollback }
}
