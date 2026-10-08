# Configure an existing MCP service for daily operation.
# Run elevated after deploying this script and velociraptor_windows_service.py.
# Does not install a service, read secrets, or restart a running bridge.
[CmdletBinding()]
param(
    [ValidateSet('configure', 'verify')]
    [string]$Mode = 'verify',
    [string]$RepoRoot = $PSScriptRoot,
    [ValidateSet('LocalSystem', 'VirtualAccount')]
    [string]$ServiceAccount = 'LocalSystem'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ServiceName = 'mcp-velociraptor'
$VirtualAccount = 'NT SERVICE\mcp-velociraptor'
$Account = if ($ServiceAccount -eq 'LocalSystem') { 'LocalSystem' } else { $VirtualAccount }
$TaskName = 'mcp-velociraptor-keepalive'
$TaskDescription = 'Velociraptor MCP daily service keepalive v1'
$ServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$RepoRoot = (Get-Item -LiteralPath $RepoRoot).FullName
$Python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
$Entry = Join-Path $RepoRoot 'velociraptor_windows_service.py'
$LegacyEntry = Join-Path $RepoRoot 'tests\p05_service_host.py'
$ExpectedBinary = "`"$Python`" `"$Entry`""
$LegacyBinary = "`"$Python`" `"$LegacyEntry`""
$PowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

# The task only starts this exact service, under the selected account.
# Disabled/manual mode provides an additional explicit maintenance opt-out.
$KeepAliveCommand = @'
$ErrorActionPreference = 'Stop'
$service = Get-CimInstance Win32_Service -Filter "Name='mcp-velociraptor'"
if ($null -ne $service -and $service.StartName -eq '__SERVICE_ACCOUNT__' -and $service.StartMode -eq 'Auto' -and $service.State -eq 'Stopped') {
    Start-Service -Name 'mcp-velociraptor'
}
'@
$KeepAliveCommand = $KeepAliveCommand.Replace('__SERVICE_ACCOUNT__', $Account)
$EncodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($KeepAliveCommand))
$TaskArguments = '-NoProfile -NonInteractive -EncodedCommand ' + $EncodedCommand

function Invoke-SC {
    param([string[]]$Arguments)
    & sc.exe @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Service configuration failed with exit code $LASTEXITCODE." }
}

function Assert-ExistingDeployment {
    foreach ($path in @($Python, $Entry, $LegacyEntry)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Required deployment file is missing.' }
    }
    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($null -eq $service -or $service.StartName -notin @($VirtualAccount, 'LocalSystem') -or
        $service.PathName -cnotin @($ExpectedBinary, $LegacyBinary)) {
        throw 'Existing service identity differs; refusing to touch it.'
    }
    if ($service.StartName -ne $Account) {
        if ($Mode -eq 'verify') { throw 'Service account differs from the selected account.' }
        if ($service.State -ne 'Stopped') {
            throw 'Disable keepalive and stop the service before changing its account.'
        }
        $task = Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue
        if ($null -ne $task -and $task.Settings.Enabled) {
            throw 'Disable keepalive before changing the service account.'
        }
    }
    $reference = Get-ItemProperty -LiteralPath ($ServiceKey + '\Environment') -Name VELOCIRAPTOR_ENV_FILE
    if ($reference.VELOCIRAPTOR_ENV_FILE -isnot [string] -or
        -not (Test-Path -LiteralPath $reference.VELOCIRAPTOR_ENV_FILE -PathType Leaf)) {
        throw 'Existing protected environment reference is unavailable.'
    }
    $existingTask = Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue
    if ($null -ne $existingTask -and $existingTask.Description -cne $TaskDescription) {
        throw 'Keepalive task name is already owned by another deployment.'
    }
}

function Assert-Recovery {
    $settings = Get-ItemProperty -LiteralPath $ServiceKey
    # SC stores reset/header DWORDs followed by SC_ACTION type/delay pairs.
    $bytes = $settings.FailureActions
    if ($settings.FailureActionsOnNonCrashFailures -ne 1 -or $bytes.Length -ne 44 -or
        [BitConverter]::ToUInt32($bytes, 0) -ne 86400 -or
        [BitConverter]::ToUInt32($bytes, 12) -ne 3 -or
        [BitConverter]::ToUInt32($bytes, 16) -ne 20) {
        throw 'Service recovery policy differs.'
    }
    foreach ($offset in @(20, 28, 36)) {
        if ([BitConverter]::ToUInt32($bytes, $offset) -ne 1 -or
            [BitConverter]::ToUInt32($bytes, $offset + 4) -ne 10000) {
            throw 'Service recovery must restart after ten seconds on every failure.'
        }
    }
}

Assert-ExistingDeployment
if ($Mode -eq 'configure') {
    Invoke-SC -Arguments @('config', $ServiceName, 'binPath=', $ExpectedBinary, 'start=', 'auto', 'obj=', $Account)
    Invoke-SC -Arguments @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/10000/restart/10000/restart/10000')
    Invoke-SC -Arguments @('failureflag', $ServiceName, '1')
    $action = New-ScheduledTaskAction -Execute $PowerShell -Argument $TaskArguments
    $repeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
    $startup = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $TaskName -TaskPath '\' -Description $TaskDescription `
        -Action $action -Trigger @($repeat, $startup) -Principal $principal -Settings $settings -Force | Out-Null
}

$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if ($service.StartName -ne $Account -or $service.StartMode -ne 'Auto' -or $service.PathName -cne $ExpectedBinary) {
    throw 'Service must use the selected account, automatic startup and the formal Windows entry.'
}
Assert-Recovery
$task = Get-ScheduledTask -TaskName $TaskName -TaskPath '\'
$actions = @($task.Actions)
$triggers = @($task.Triggers)
if (-not $task.Settings.Enabled -or $actions.Count -ne 1 -or
    $actions[0].Execute -cne $PowerShell -or $actions[0].Arguments -cne $TaskArguments -or
    $task.Principal.UserId -notin @('SYSTEM', 'S-1-5-18') -or
    $task.Principal.LogonType -ne 'ServiceAccount' -or $task.Principal.RunLevel -ne 'Highest' -or
    $triggers.Count -ne 2 -or @($triggers | Where-Object {
        $_.CimClass.CimClassName -eq 'MSFT_TaskTimeTrigger' -and $_.Enabled -and
        $_.Repetition.Interval -eq 'PT1M' -and [string]::IsNullOrEmpty($_.Repetition.Duration)
    }).Count -ne 1 -or @($triggers | Where-Object {
        $_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' -and $_.Enabled
    }).Count -ne 1) {
    throw 'Keepalive task differs from the one-minute/startup policy.'
}
[ordered]@{
    service = $service.Name
    state = $service.State
    account = $service.StartName
    entry = $Entry
    start_mode = $service.StartMode
    recovery_delay_seconds = 10
    recovery_reset_seconds = 86400
    noncrash_recovery = $true
    keepalive_task = $TaskName
    keepalive_interval_seconds = 60
} | ConvertTo-Json -Compress
