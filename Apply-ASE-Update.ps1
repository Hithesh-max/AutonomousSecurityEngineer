param(
    [string]$ProjectPath = 'D:\antigrav\AutonomousSecurityEngineer',
    [switch]$CheckOnly
)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($ProjectPath).TrimEnd([char[]]"\/")
$packageRoot = $PSScriptRoot
$manifestPath = Join-Path $packageRoot 'ASE_UPDATE_MANIFEST.json'
if (!(Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Keep the installer beside ASE_UPDATE_MANIFEST.json in the extracted update.' }
if (!(Test-Path -LiteralPath (Join-Path $root 'backend\app\main.py'))) { throw 'ProjectPath must point to your existing ASE project.' }
if (!(Test-Path -LiteralPath (Join-Path $root '.env'))) { throw 'Existing .env is missing. This installer never creates or overwrites it.' }
if ($root -eq [IO.Path]::GetFullPath($packageRoot).TrimEnd([char[]]"\/")) { throw 'Extract the update into a separate folder, then supply the existing project path.' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
function Safe-Path([string]$base, [string]$relative) {
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)' -or $relative -match ':') { throw 'Invalid update path.' }
    $full = [IO.Path]::GetFullPath((Join-Path $base $relative))
    if (!$full.StartsWith($base + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Update path escapes its root.' }
    $current = $full
    while ($current.Length -ge $base.Length) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Symlink/junction not allowed: $relative" }
        }
        $parent = Split-Path -Parent $current
        if ($parent -eq $current -or !$parent) { break }
        $current = $parent
    }
    return $full
}
$pending = @()
foreach ($entry in $manifest.files) {
    if ($entry.path -eq '.env' -or $entry.path -match '\.(dump|zip)$') { throw 'Protected file in update manifest.' }
    $source = Safe-Path $packageRoot $entry.path
    $destination = Safe-Path $root $entry.path
    if (!(Test-Path -LiteralPath $source -PathType Leaf) -or (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) { throw "Update file failed checksum: $($entry.path)" }
    if (Test-Path -LiteralPath $destination) {
        $actual = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -eq $entry.sha256) { continue }
        if (!$entry.original_sha256 -or $actual -ne $entry.original_sha256) { throw "Local changes detected in $($entry.path). Nothing copied. Compare with your current file before installing." }
    } elseif ($entry.original_sha256) { throw "Expected original file is missing: $($entry.path)" }
    $pending += $entry
}
Write-Host "Preflight passed. $($pending.Count) files need updating; existing .env and database are untouched."
if ($CheckOnly -or !$pending.Count) { return }
$backup = Join-Path $root ('ase-update-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $backup | Out-Null
foreach ($entry in $pending) {
    if ($entry.original_sha256) {
        $destination = Join-Path $backup $entry.path
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
        Copy-Item -LiteralPath (Join-Path $root $entry.path) -Destination $destination
    }
}
@{project_path=$root; files=@($pending)} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $backup 'applied.json') -Encoding UTF8
foreach ($entry in $pending) {
    $destination = Join-Path $root $entry.path
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    Copy-Item -LiteralPath (Join-Path $packageRoot $entry.path) -Destination $destination -Force
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) { throw "Copy verification failed. Original files are backed up at $backup" }
}
Write-Host "Files installed. Backup: $backup"
Write-Host 'Follow START_HERE_ASE_UPDATE.md to build, apply the additive migration, and restart services. No services or database were changed by this script.'
