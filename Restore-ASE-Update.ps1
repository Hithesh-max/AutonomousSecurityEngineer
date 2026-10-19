param([Parameter(Mandatory=$true)][string]$BackupPath)
$ErrorActionPreference = 'Stop'
$backup = [IO.Path]::GetFullPath($BackupPath).TrimEnd([char[]]"\/")
$record = Get-Content -LiteralPath (Join-Path $backup 'applied.json') -Raw | ConvertFrom-Json
$root = [IO.Path]::GetFullPath($record.project_path).TrimEnd([char[]]"\/")
foreach ($entry in $record.files) {
    if ([IO.Path]::IsPathRooted($entry.path) -or $entry.path -match '(^|[\\/])\.\.([\\/]|$)' -or $entry.path -match ':') { throw 'Invalid rollback path.' }
    $path = [IO.Path]::GetFullPath((Join-Path $root $entry.path))
    if (!$path.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Rollback path escapes project.' }
    $current = $path
    while ($current.Length -ge $root.Length) {
        if ((Test-Path -LiteralPath $current) -and ((Get-Item -LiteralPath $current).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Rollback refuses symlinks and junctions.' }
        $parent = Split-Path -Parent $current
        if (!$parent -or $parent -eq $current) { break }
        $current = $parent
    }
    if (!(Test-Path -LiteralPath $path) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) { throw "File changed after installation: $($entry.path). No rollback performed; preserve your newer work." }
    if ($entry.original_sha256 -and (Get-FileHash -LiteralPath (Join-Path $backup $entry.path) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.original_sha256) { throw 'Backup checksum failed.' }
}
foreach ($entry in $record.files) {
    $path = Join-Path $root $entry.path
    if ($entry.original_sha256) { Copy-Item -LiteralPath (Join-Path $backup $entry.path) -Destination $path -Force }
    else { Remove-Item -LiteralPath $path }
}
Write-Host 'Original files restored. Rebuild/restart services using your original Compose settings. Keep the additive database migration; do not drop tables or volumes.'
