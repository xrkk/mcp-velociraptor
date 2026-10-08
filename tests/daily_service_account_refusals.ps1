# Native PowerShell regression for account migration refusal boundaries.
# SCM/task/config calls are intercepted; this test never changes a deployment.
[CmdletBinding()]
param([string]$RepoRoot = (Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$RepoRoot = (Get-Item -LiteralPath $RepoRoot).FullName
$scriptPath = Join-Path $RepoRoot 'configure_windows_service.ps1'
$python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
$entry = Join-Path $RepoRoot 'velociraptor_windows_service.py'
$fixture = [pscustomobject]@{
    Name = 'mcp-velociraptor'; StartName = 'LocalSystem'; State = 'Running'
    PathName = "`"$python`" `"$entry`""
}
function Get-CimInstance {
    [CmdletBinding()] param([string]$ClassName, [string]$Filter)
    return $fixture
}
function Get-ScheduledTask {
    [CmdletBinding()] param([string]$TaskName, [string]$TaskPath)
    return [pscustomobject]@{ Settings = [pscustomobject]@{ Enabled = $true } }
}
function Get-ItemProperty { throw 'Unexpected protected configuration read in refusal test.' }
function sc.exe { throw 'Unexpected SCM mutation in refusal test.' }
function Register-ScheduledTask { throw 'Unexpected task mutation in refusal test.' }
function Start-Service { throw 'Unexpected service start in refusal test.' }

function Assert-Refusal([string]$Mode, [string]$Account, [string]$Expected) {
    try {
        & $scriptPath -Mode $Mode -RepoRoot $RepoRoot -ServiceAccount $Account
    } catch {
        if ($_.Exception.Message -ceq $Expected) { return }
        throw
    }
    throw 'Unsafe account transition was accepted.'
}

Assert-Refusal verify VirtualAccount 'Service account differs from the selected account.'
Assert-Refusal configure VirtualAccount 'Disable keepalive and stop the service before changing its account.'
$fixture.StartName = 'NT SERVICE\mcp-velociraptor'
Assert-Refusal configure LocalSystem 'Disable keepalive and stop the service before changing its account.'
$fixture.State = 'Stopped'
Assert-Refusal configure LocalSystem 'Disable keepalive before changing the service account.'
$fixture.StartName = 'unrelated-account'
Assert-Refusal configure LocalSystem 'Existing service identity differs; refusing to touch it.'
Assert-Refusal verify LocalSystem 'Existing service identity differs; refusing to touch it.'
[ordered]@{ schema = 'velo.daily-account.refusals.v1'; passed = 6; native_mutations = 0 } | ConvertTo-Json -Compress
