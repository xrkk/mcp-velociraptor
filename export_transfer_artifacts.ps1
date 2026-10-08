# Explicit producer-close -> verified independent copy -> source ACL handoff.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ManifestPath,
    [Parameter(Mandatory = $true)][string]$PolicyPath,
    [Parameter(Mandatory = $true)][string]$OutputRoot
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$operation = 'preflight'
$sourcePath = $ManifestPath
$targetPath = $OutputRoot
$logRoot = $null
$stage = $null
$watch = [Diagnostics.Stopwatch]::StartNew()

function Get-OrdinaryItem([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\') -or $Path -match '(^|[\\/])\.\.?([\\/]|$)') {
        throw "An ordinary absolute local path is required: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    $current = $item
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse path refused: $Path" }
        $current = if ($current -is [IO.DirectoryInfo]) { $current.Parent } else { $current.Directory }
    }
    return $item
}
function Within([string]$Path, [string]$Root) {
    return $Path.Equals($Root, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
}
function Read-Json([string]$Path) {
    $item = Get-OrdinaryItem $Path
    if ($item -is [IO.DirectoryInfo] -or $item.Length -gt 1MB) { throw "Invalid metadata file: $Path" }
    return Get-Content -LiteralPath $item.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
}
function Assert-Relative([string]$Path) {
    if ([string]::IsNullOrEmpty($Path) -or $Path.Contains('\')) { throw "Invalid artifact relative path: $Path" }
    foreach ($part in $Path.Split('/')) {
        if ([string]::IsNullOrEmpty($part) -or $part -in @('.', '..') -or
            $part -match '[<>:"|?*\x00-\x1f]' -or $part.EndsWith('.') -or $part.EndsWith(' ') -or
            $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)' -or
            $part -eq 'handoff-receipt.json') { throw "Invalid artifact relative path: $Path" }
    }
}

try {
    $policy = Read-Json $PolicyPath
    $manifest = Read-Json $ManifestPath
    $manifestDigest = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $policyDigest = (Get-FileHash -LiteralPath $PolicyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($policy.schema -cne 'velo.transfer.policy.v1' -or $manifest.schema -cne 'velo.artifact-export.v1') {
        throw 'Invalid policy or export schema.'
    }
    $root = Get-OrdinaryItem $OutputRoot
    if ($root -isnot [IO.DirectoryInfo] -or $null -eq $root.Parent) { throw 'Dedicated output directory required.' }
    $approved = @($policy.read_roots | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') })
    if ($root.FullName.TrimEnd('\') -notin $approved) { throw 'OutputRoot must be an exact policy read_root.' }
    $work = [IO.Path]::GetFullPath($policy.work_root)
    if ((Within $root.FullName $work) -or (Within $work $root.FullName) -or
        (Within ([IO.Path]::GetFullPath($PolicyPath)) $root.FullName)) { throw 'Output root overlaps private state or policy.' }
    $logRoot = $root.FullName
    if ($manifest.producer -cnotin @('Windows-MCP', 'FakeNet-NG') -or
        $manifest.batch_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$' -or
        $manifest.producer_complete -isnot [bool] -or -not $manifest.producer_complete -or
        $manifest.producer_quiescent -isnot [bool] -or -not $manifest.producer_quiescent -or
        @($manifest.references).Count -eq 0) { throw 'Completed, quiescent producer evidence required.' }
    foreach ($reference in @($manifest.references)) {
        if ($reference -isnot [string] -or [string]::IsNullOrWhiteSpace($reference)) { throw 'Invalid producer reference.' }
    }
    $sourceRoot = Get-OrdinaryItem $manifest.source_root
    if ($sourceRoot -isnot [IO.DirectoryInfo] -or (Within $root.FullName $sourceRoot.FullName) -or
        (Within $sourceRoot.FullName $root.FullName)) { throw 'Independent producer source root required.' }
    if ($manifest.producer -ceq 'FakeNet-NG' -and
        ($sourceRoot.Name -cne 'artifacts' -or $manifest.producer_state -cne 'stopped' -or
         [string]::IsNullOrWhiteSpace($manifest.run_id))) { throw 'Stopped FakeNet registered-artifacts evidence required.' }
    $files = @($manifest.files)
    if ($files.Count -eq 0 -or $files.Count + 1 -gt $policy.limits.max_files) { throw 'Artifact file budget exceeded.' }
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $total = [long]0
    foreach ($file in $files) {
        $sourcePath = $file.path
        Assert-Relative $file.relative_path
        if (-not $names.Add($file.relative_path) -or $file.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $file.complete -isnot [bool] -or -not $file.complete -or
            ($file.size -isnot [int] -and $file.size -isnot [long]) -or
            $file.size -lt 0) { throw 'Invalid or incomplete artifact metadata.' }
        $source = Get-OrdinaryItem $file.path
        if ($source -is [IO.DirectoryInfo] -or -not (Within $source.FullName $sourceRoot.FullName) -or
            $source.Length -ne $file.size) { throw "Source identity/size invalid: $($file.path)" }
        $total += [long]$file.size
        if ($total -gt $policy.limits.max_logical_bytes) { throw 'Artifact byte budget exceeded.' }
    }
    foreach ($name in $names) {
        foreach ($other in $names) {
            if ($name.StartsWith($other + '/', [StringComparison]::OrdinalIgnoreCase)) { throw 'Artifact path collision.' }
        }
    }
    $final = Join-Path $root.FullName $manifest.batch_id
    if (Test-Path -LiteralPath $final) { throw "Destination exists; inspect retained receipt before retry: $final" }
    $stage = Join-Path $root.FullName ('.handoff-' + [Guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $stage
    $records = [Collections.Generic.List[object]]::new()
    $deadline = [Math]::Min(600, $policy.limits.max_duration_seconds)
    foreach ($file in $files) {
        $operation = 'copy'
        $sourcePath = $file.path
        $targetPath = Join-Path $stage ($file.relative_path.Replace('/', '\'))
        $null = New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($targetPath)) -Force
        $inputStream = $null
        $outputStream = $null
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            # No writer or rename sharing: an active producer causes a native
            # sharing error rather than a misleading completed copy.
            $inputStream = [IO.File]::Open($sourcePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            $outputStream = [IO.File]::Open($targetPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $buffer = New-Object byte[] 1048576
            $copied = [long]0
            while (($count = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                if ($watch.Elapsed.TotalSeconds -ge $deadline) { throw 'Artifact copy deadline exceeded.' }
                $copied += $count
                if ($copied -gt $file.size) { throw 'Artifact size changed.' }
                $outputStream.Write($buffer, 0, $count)
                $null = $hasher.TransformBlock($buffer, 0, $count, $null, 0)
            }
            $null = $hasher.TransformFinalBlock([byte[]]@(), 0, 0)
            $digest = ([BitConverter]::ToString($hasher.Hash)).Replace('-', '').ToLowerInvariant()
            $outputStream.Flush($true)
            if ($copied -ne $file.size -or $digest -cne $file.sha256) { throw 'Artifact content changed or declaration mismatched.' }
        } finally {
            if ($null -ne $outputStream) { $outputStream.Dispose() }
            if ($null -ne $inputStream) { $inputStream.Dispose() }
            $hasher.Dispose()
        }
        if ((Get-FileHash -LiteralPath $targetPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.sha256) {
            throw 'Export copy verification failed.'
        }
        $records.Add([ordered]@{ source_path = $file.path; relative_path = $file.relative_path; size = $file.size; sha256 = $digest })
    }
    $operation = 'receipt'
    if ((Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifestDigest -or
        (Get-FileHash -LiteralPath $PolicyPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $policyDigest) {
        throw 'Export metadata or policy changed.'
    }
    $targetPath = Join-Path $stage 'handoff-receipt.json'
    $receipt = [ordered]@{ schema = 'velo.artifact-export.receipt.v1'; producer = $manifest.producer
        batch_id = $manifest.batch_id; producer_complete = $true; producer_quiescent = $true
        references = @($manifest.references); source_manifest_sha256 = $manifestDigest
        output_directory = $final; files = @($records.ToArray()) }
    [IO.File]::WriteAllText($targetPath, ($receipt | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    $operation = 'acl_handoff'
    $aclScript = Join-Path $PSScriptRoot 'configure_transfer_source_access.ps1'
    & $aclScript -Mode configure -PolicyPath $PolicyPath -SourceRoot $root.FullName -ArtifactPath $stage | Out-Null
    & $aclScript -Mode verify -PolicyPath $PolicyPath -SourceRoot $root.FullName -ArtifactPath $stage | Out-Null
    $operation = 'publish'
    [IO.Directory]::Move($stage, $final)
    $targetPath = $final
    & $aclScript -Mode verify -PolicyPath $PolicyPath -SourceRoot $root.FullName -ArtifactPath $final | Out-Null
    [ordered]@{ schema = 'velo.artifact-export.result.v1'; export_complete = $true; acl_verified = $true
        output_directory = $final; receipt_path = (Join-Path $final 'handoff-receipt.json')
        file_count = $files.Count; logical_bytes = $total } | ConvertTo-Json -Compress
} catch {
    $native = $_.Exception.GetBaseException()
    $record = [ordered]@{ schema = 'velo.artifact-export.error.v1'; operation = $operation
        source_path = $sourcePath; destination_path = $targetPath; stage_path = $stage
        exception_type = $native.GetType().FullName; hresult = $native.HResult
        native_error_code = $(if ($native -is [IO.IOException] -or $native -is [UnauthorizedAccessException]) { $native.HResult -band 0xffff } else { $null })
        os_error = $native.Message }
    if ($null -ne $logRoot) {
        try { [IO.File]::WriteAllText((Join-Path $logRoot ('.handoff-error-' + [Guid]::NewGuid().ToString('N') + '.json')),
            ($record | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false)) } catch { }
    }
    $errorBytes = [Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json -Depth 5 -Compress) + [Environment]::NewLine)
    $errorStream = [Console]::OpenStandardError()
    $errorStream.Write($errorBytes, 0, $errorBytes.Length)
    $errorStream.Flush()
    throw
}
