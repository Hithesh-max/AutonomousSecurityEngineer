param([Parameter(Mandatory=$true)][string]$ProjectRoot)
$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path
if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot 'backend\app\main.py'))) { throw 'Choose the ASE project root containing backend and frontend.' }
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'ASE_FIX_MANIFEST.json') -Raw | ConvertFrom-Json
$pending = @()
foreach ($entry in $manifest.files) {
    $relative = $entry.path.Replace('/', [IO.Path]::DirectorySeparatorChar)
    $source = Join-Path $PSScriptRoot $relative
    $destination = Join-Path $ProjectRoot $relative
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) { throw "Update checksum mismatch: $relative" }
    $actual = if (Test-Path -LiteralPath $destination) { (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
    if ($actual -eq $entry.sha256) { continue }
    if ($actual -ne $entry.original_sha256) { throw "Local file differs from the supplied ZIP: $relative. Nothing copied. Send this message with your current file." }
    $pending += $entry
}
if ($pending.Count -eq 0) { Write-Host 'All update files already match. No files changed.'; exit 0 }
$backup = Join-Path (Split-Path -Parent $ProjectRoot) ('ASE-Fix-Backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $backup | Out-Null
# Finish all backups before overwriting any project file.
foreach ($entry in $pending) {
    $relative = $entry.path.Replace('/', [IO.Path]::DirectorySeparatorChar)
    if ($entry.original_sha256) {
        $saved = Join-Path $backup $relative
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $saved) | Out-Null
        Copy-Item -LiteralPath (Join-Path $ProjectRoot $relative) -Destination $saved
    }
}
@{ project_root=$ProjectRoot; files=@($pending) } | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $backup 'RESTORE_MANIFEST.json')
foreach ($entry in $pending) {
    $relative = $entry.path.Replace('/', [IO.Path]::DirectorySeparatorChar)
    $destination = Join-Path $ProjectRoot $relative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $relative) -Destination $destination -Force
}
Write-Host "Applied $($pending.Count) files. Backup: $backup"
Write-Host 'Database, uploaded projects, Docker volumes and .env were not changed. Follow START_HERE.md to rebuild services.'
