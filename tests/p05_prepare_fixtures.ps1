[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^wf-[a-z0-9-]{8,80}$')]
    [string]$WorkflowId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^p05-[a-z0-9-]{4,80}$')]
    [string]$AttemptId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ExpectedWorkflow = 'wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2'
$FixtureRoot = 'C:\VelociraptorMCP\fixtures-p05'
$OwnerPath = Join-Path $FixtureRoot '.p05-owner.json'
$InstancePath = Join-Path $FixtureRoot 'fixture-instance-v1.json'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$SpecPath = Join-Path $RepoRoot 'tests\data\p05_fixture_spec.json'

if ($WorkflowId -ne $ExpectedWorkflow) {
    throw 'workflow_id is not approved for this fixture root'
}
if (-not [IO.Path]::IsPathRooted($FixtureRoot) -or $FixtureRoot.StartsWith('\\')) {
    throw 'fixture root must be one fixed local absolute path'
}
if ([IO.Path]::GetPathRoot($FixtureRoot).TrimEnd('\') -eq $FixtureRoot.TrimEnd('\')) {
    throw 'fixture root must not be a drive root'
}

function Assert-NoReparse([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "reparse point is not allowed: $Path"
        }
    }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Convert-CreationTime($Value) {
    if ($Value -is [DateTime]) {
        return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    }
    return [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
}

function Convert-RecordedTime($Value) {
    if ($Value -is [DateTime]) {
        return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    }
    $parsed = [DateTime]::Parse(
        [string]$Value,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    )
    return $parsed.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
}

Assert-NoReparse ([IO.Path]::GetPathRoot($FixtureRoot))
Assert-NoReparse (Split-Path -Parent $FixtureRoot)
Assert-NoReparse $FixtureRoot

$createdRoot = $false
if (-not (Test-Path -LiteralPath $FixtureRoot)) {
    New-Item -ItemType Directory -Path $FixtureRoot | Out-Null
    $createdRoot = $true
}
Assert-NoReparse $FixtureRoot

if ($createdRoot) {
    $owner = [ordered]@{ schema_version = 1; workflow_id = $WorkflowId }
    $ownerJson = $owner | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($OwnerPath, $ownerJson + "`n", (New-Object Text.UTF8Encoding($false)))
}
if (-not (Test-Path -LiteralPath $OwnerPath -PathType Leaf)) {
    throw 'existing fixture root has no ownership marker'
}
$ownerValue = Get-Content -LiteralPath $OwnerPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($ownerValue.schema_version -ne 1 -or $ownerValue.workflow_id -ne $WorkflowId) {
    throw 'existing fixture root has a conflicting ownership marker'
}

$spec = Get-Content -LiteralPath $SpecPath -Raw -Encoding UTF8 | ConvertFrom-Json
$specHash = Get-Sha256 $SpecPath
$fileRows = @()
foreach ($entry in $spec.files) {
    $relative = [string]$entry.path
    if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains('..')) {
        throw "invalid fixture relative path: $relative"
    }
    $target = Join-Path $FixtureRoot ($relative.Replace('/', '\'))
    $parent = Split-Path -Parent $target
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Assert-NoReparse $parent
    if ($entry.encoding -eq 'ascii') {
        $bytes = [Text.Encoding]::ASCII.GetBytes([string]$entry.payload)
    } elseif ($entry.encoding -eq 'utf-8') {
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes([string]$entry.payload)
    } elseif ($entry.encoding -eq 'byte-sequence-0-255-repeat-4') {
        $bytes = New-Object byte[] 1024
        for ($index = 0; $index -lt 1024; $index++) { $bytes[$index] = $index % 256 }
    } else {
        throw "unsupported fixture encoding: $($entry.encoding)"
    }
    if (-not (Test-Path -LiteralPath $target)) {
        [IO.File]::WriteAllBytes($target, $bytes)
    }
    Assert-NoReparse $target
    $actualSize = (Get-Item -LiteralPath $target).Length
    $actualHash = Get-Sha256 $target
    if ($actualSize -ne [int64]$entry.size -or $actualHash -ne [string]$entry.sha256) {
        throw "fixture file conflicts with spec: $relative"
    }
    $fileRows += [ordered]@{
        path = [IO.Path]::GetFullPath($target)
        relative_path = $relative
        sha256 = $actualHash
        size = $actualSize
    }
}

$registryPath = "HKLM:\SOFTWARE\VelociraptorMCP\P05\$WorkflowId"
if (-not (Test-Path -LiteralPath $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
$expectedRegistry = [ordered]@{ Owner = $WorkflowId; Attempt = $AttemptId; FixtureVersion = 1 }
foreach ($name in $expectedRegistry.Keys) {
    $existing = Get-ItemProperty -LiteralPath $registryPath -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        New-ItemProperty -LiteralPath $registryPath -Name $name -Value $expectedRegistry[$name] -PropertyType $(if ($name -eq 'FixtureVersion') { 'DWord' } else { 'String' }) | Out-Null
    } elseif ($existing.$name -ne $expectedRegistry[$name]) {
        throw "registry fixture conflict: $name"
    }
}

$eventSource = 'VelociraptorMCP-P05'
$eventId = 42005
$eventMessage = "$WorkflowId|$AttemptId|fixture-v1"
if (-not [Diagnostics.EventLog]::SourceExists($eventSource)) {
    $sourceData = New-Object Diagnostics.EventSourceCreationData($eventSource, 'Application')
    [Diagnostics.EventLog]::CreateEventSource($sourceData)
}
$eventLog = New-Object Diagnostics.EventLog('Application')
$matchingEvents = @($eventLog.Entries | Where-Object { $_.Source -eq $eventSource -and $_.EventID -eq $eventId -and $_.Message -eq $eventMessage })
if ($matchingEvents.Count -eq 0) {
    [Diagnostics.EventLog]::WriteEntry($eventSource, $eventMessage, [Diagnostics.EventLogEntryType]::Information, $eventId)
    $eventLog.Close()
    $eventLog = New-Object Diagnostics.EventLog('Application')
    $matchingEvents = @($eventLog.Entries | Where-Object { $_.Source -eq $eventSource -and $_.EventID -eq $eventId -and $_.Message -eq $eventMessage })
}
if ($matchingEvents.Count -ne 1) {
    throw 'event fixture must have exactly one matching event'
}
$eventLog.Close()

$taskPath = '\VelociraptorMCP\'
$taskName = 'P05-Fixture'
$task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
if ($null -eq $task) {
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument '/d /c exit 0'
    $settings = New-ScheduledTaskSettingsSet
    Register-ScheduledTask -TaskPath $taskPath -TaskName $taskName -Action $action -Settings $settings -User 'SYSTEM' -RunLevel Highest | Out-Null
    Disable-ScheduledTask -TaskPath $taskPath -TaskName $taskName | Out-Null
    $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName
}
if ($task.State -ne 'Disabled' -or @($task.Triggers | Where-Object { $null -ne $_ }).Count -ne 0 -or @($task.Actions | Where-Object { $null -ne $_ }).Count -ne 1) {
    throw 'scheduled task fixture conflicts with inert spec'
}
$taskAction = @($task.Actions)[0]
if ($taskAction.Execute -ne "$env:SystemRoot\System32\cmd.exe" -or $taskAction.Arguments -ne '/d /c exit 0') {
    throw 'scheduled task action conflicts with inert spec'
}

$pythonPath = [IO.Path]::GetFullPath((Join-Path $RepoRoot '.venv\Scripts\python.exe'))
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
    throw 'locked guest Python interpreter is missing'
}
$existingInstance = $null
if (Test-Path -LiteralPath $InstancePath -PathType Leaf) {
    $existingInstance = Get-Content -LiteralPath $InstancePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($existingInstance.workflow_id -ne $WorkflowId -or $existingInstance.attempt_id -ne $AttemptId -or $existingInstance.fixture_spec_sha256 -ne $specHash) {
        throw 'fixture instance conflicts with this workflow, attempt, or spec'
    }
}
$process = $null
if ($null -ne $existingInstance) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($existingInstance.process.pid)" -ErrorAction SilentlyContinue
    if ($null -ne $process) {
        $creation = Convert-CreationTime $process.CreationDate
        $recordedCreation = Convert-RecordedTime $existingInstance.process.creation_time_utc
        if ($creation -ne $recordedCreation -or -not $process.CommandLine.Contains($WorkflowId) -or -not $process.CommandLine.Contains($AttemptId)) {
            throw 'fixture process PID was reused or its identity changed'
        }
    }
}
if ($null -eq $process) {
    $argumentLine = "-c `"import time; time.sleep(86400)`" `"$WorkflowId`" `"$AttemptId`""
    $started = Start-Process -FilePath $pythonPath -ArgumentList $argumentLine -WindowStyle Hidden -PassThru
    Start-Sleep -Milliseconds 500
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($started.Id)" -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        throw 'fixture process exited before its identity could be recorded'
    }
}
$processCreation = Convert-CreationTime $process.CreationDate
if (-not $process.CommandLine.Contains($WorkflowId) -or -not $process.CommandLine.Contains($AttemptId)) {
    throw 'fixture process command line is missing ownership tokens'
}

# The frozen spec records the canonical unexpanded %SystemRoot% form; the
# ScheduledTasks API always returns the expanded interpreter path.
$canonicalExecute = $taskAction.Execute -replace [regex]::Escape("$env:SystemRoot\System32\cmd.exe"), '%SystemRoot%\System32\cmd.exe'
$instance = [ordered]@{
    schema_version = 1
    fixture_spec_sha256 = $specHash
    workflow_id = $WorkflowId
    attempt_id = $AttemptId
    ownership_marker = [ordered]@{ path = $OwnerPath; workflow_id = $WorkflowId }
    hostname = $env:COMPUTERNAME
    fixture_root = $FixtureRoot
    files = $fileRows
    registry = [ordered]@{ path = $registryPath; values = $expectedRegistry }
    event = [ordered]@{ log = 'Application'; source = $eventSource; event_id = $eventId; message = $eventMessage; record_id = [int64]$matchingEvents[0].Index }
    task = [ordered]@{ path = $taskPath; name = $taskName; enabled = $false; triggers = @(); execute = $canonicalExecute; arguments = $taskAction.Arguments }
    process = [ordered]@{ pid = [int]$process.ProcessId; creation_time_utc = $processCreation; token = "$WorkflowId|$AttemptId"; interpreter = $pythonPath; command_line = $process.CommandLine; sleep_seconds = 86400 }
}
$json = $instance | ConvertTo-Json -Depth 12
$tempPath = "$InstancePath.$([Guid]::NewGuid().ToString('N')).tmp"
$utf8 = New-Object Text.UTF8Encoding($false)
$stream = New-Object IO.FileStream($tempPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $data = $utf8.GetBytes($json + "`n")
    $stream.Write($data, 0, $data.Length)
    $stream.Flush($true)
} finally {
    $stream.Dispose()
}
if (Test-Path -LiteralPath $InstancePath) {
    $backup = "$InstancePath.$([Guid]::NewGuid().ToString('N')).bak"
    [IO.File]::Replace($tempPath, $InstancePath, $backup, $true)
    Remove-Item -LiteralPath $backup -Force
} else {
    [IO.File]::Move($tempPath, $InstancePath)
}

$result = [ordered]@{
    ok = $true
    workflow_id = $WorkflowId
    attempt_id = $AttemptId
    fixture_spec_sha256 = $specHash
    fixture_instance = $InstancePath
    fixture_instance_sha256 = Get-Sha256 $InstancePath
    process_pid = [int]$process.ProcessId
}
$result | ConvertTo-Json -Compress
