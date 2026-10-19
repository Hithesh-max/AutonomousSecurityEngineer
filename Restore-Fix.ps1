param([Parameter(Mandatory=$true)][string]$BackupDirectory)
$ErrorActionPreference = 'Stop'
$BackupDirectory = (Resolve-Path -LiteralPath $BackupDirectory).Path
$manifest = Get-Content -LiteralPath (Join-Path $BackupDirectory 'RESTORE_MANIFEST.json') -Raw | ConvertFrom-Json
foreach ($entry in $manifest.files) {
    $relative = $entry.path.Replace('/', [IO.Path]::DirectorySeparatorChar)
    $current = Join-Path $manifest.project_root $relative
    if (-not (Test-Path -LiteralPath $current)) { throw "Expected updated file missing: $relative" }
    if ((Get-FileHash -LiteralPath $current -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) { throw "File changed after update: $relative. Rollback stopped before restoring anything." }
    if ($entry.original_sha256) {
        $saved = Join-Path $BackupDirectory $relative
        if ((Get-FileHash -LiteralPath $saved -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.original_sha256) { throw "Backup checksum mismatch: $relative" }
    }
}
foreach ($entry in $manifest.files) {
    $relative = $entry.path.Replace('/', [IO.Path]::DirectorySeparatorChar)
    $current = Join-Path $manifest.project_root $relative
    if ($entry.original_sha256) { Copy-Item -LiteralPath (Join-Path $BackupDirectory $relative) -Destination $current -Force }
    else { Remove-Item -LiteralPath $current }
}
Write-Host 'Restored code files. Database and uploaded projects were not changed. Rebuild services using START_HERE.md.'
