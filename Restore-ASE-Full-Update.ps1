<#
.SYNOPSIS
    Restores an ASE installation from a backup created by Apply-ASE-Full-Update.ps1.

.DESCRIPTION
    Rolls back modified files to their previous states and removes newly added files.

.PARAMETER BackupDir
    The backup directory to restore from (e.g. '_backup_before_update_20261013_130000').

.PARAMETER TargetDir
    The root directory of the ASE installation. Defaults to the current directory.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$BackupDir,

    [Parameter(Mandatory = $false)]
    [string]$TargetDir = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($TargetDir)) {
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $TargetDir = $PSScriptRoot
    } else {
        $TargetDir = (Get-Location).Path
    }
}

$TargetDir = (Resolve-Path $TargetDir).Path
$BackupDir = (Resolve-Path $BackupDir).Path

Write-Host "======================================================================" -ForegroundColor Yellow
Write-Host "  AUTONOMOUS SECURITY ENGINEER (ASE) - RESTORE / ROLLBACK" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Yellow
Write-Host "Restoring from: $BackupDir" -ForegroundColor Magenta
Write-Host "Target Root:    $TargetDir" -ForegroundColor Gray

if (-not (Test-Path $BackupDir)) {
    Write-Error "Backup directory does not exist: $BackupDir"
    exit 1
}

$BackupFiles = Get-ChildItem -Path $BackupDir -Recurse -File
$RestoredCount = 0

foreach ($File in $BackupFiles) {
    $RelPath = $File.FullName.Substring($BackupDir.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar)
    $DestFile = Join-Path $TargetDir $RelPath
    $DestParent = Split-Path -Parent $DestFile

    if (-not (Test-Path $DestParent)) {
        New-Item -ItemType Directory -Path $DestParent -Force | Out-Null
    }

    Copy-Item -Path $File.FullName -Destination $DestFile -Force
    Write-Host "  [RESTORED] $RelPath" -ForegroundColor Green
    $RestoredCount++
}

Write-Host "`n----------------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "Rollback complete: $RestoredCount files restored to previous state." -ForegroundColor White
Write-Host "----------------------------------------------------------------------" -ForegroundColor Yellow
