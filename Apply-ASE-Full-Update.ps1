<#
.SYNOPSIS
    Applies the Autonomous Security Engineer (ASE) Completion Update with pre-flight checks,
    automatic backups, and cryptographic SHA-256 integrity verification.

.DESCRIPTION
    Safely applies the update package into the project root directory.
    Supports -CheckOnly mode to preview changes and verify checksums without modifying files.

.PARAMETER TargetDir
    The root directory of the ASE installation. Defaults to the current directory.

.PARAMETER CheckOnly
    If set, only performs pre-flight integrity verification and lists changes without modifying files.

.PARAMETER BackupDir
    Custom path for the backup directory. Defaults to '_backup_before_update_<timestamp>'.

.EXAMPLE
    .\Apply-ASE-Full-Update.ps1 -CheckOnly
    .\Apply-ASE-Full-Update.ps1
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$TargetDir = "",

    [Parameter(Mandatory = $false)]
    [switch]$CheckOnly,

    [Parameter(Mandatory = $false)]
    [string]$BackupDir = ""
)

$ErrorActionPreference = "Stop"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  AUTONOMOUS SECURITY ENGINEER (ASE) - UPDATE INSTALLER" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

if ([string]::IsNullOrWhiteSpace($TargetDir)) {
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $TargetDir = $PSScriptRoot
    } else {
        $TargetDir = (Get-Location).Path
    }
}

$TargetDir = (Resolve-Path $TargetDir).Path
Write-Host "Target Root: $TargetDir" -ForegroundColor Gray

$ManifestFile = Join-Path $TargetDir "UPDATE_MANIFEST_SHA256.json"
$ZipFile = Join-Path $TargetDir "ASE_FINAL_COMPLETION_UPDATE.zip"

if (-not (Test-Path $ManifestFile)) {
    Write-Error "Missing manifest file: $ManifestFile"
    exit 1
}

$Manifest = Get-Content $ManifestFile -Raw | ConvertFrom-Json
$FileCount = ($Manifest | Get-Member -MemberType NoteProperty).Count
Write-Host "Loaded update manifest with $FileCount tracked files.`n" -ForegroundColor Green

if ($CheckOnly) {
    Write-Host "[CHECK-ONLY MODE] Verifying package contents without writing changes..." -ForegroundColor Yellow
} else {
    if ([string]::IsNullOrWhiteSpace($BackupDir)) {
        $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $BackupDir = Join-Path $TargetDir "_backup_before_update_$Timestamp"
    }
    Write-Host "Backup Directory: $BackupDir" -ForegroundColor Magenta
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

$TempExtractDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ase_update_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TempExtractDir -Force | Out-Null

try {
    Write-Host "Extracting update package archive..." -ForegroundColor Gray
    Expand-Archive -Path $ZipFile -DestinationPath $TempExtractDir -Force

    $VerifiedCount = 0
    $ChangedCount = 0
    $NewCount = 0

    foreach ($Prop in ($Manifest | Get-Member -MemberType NoteProperty)) {
        $RelPath = $Prop.Name
        $ExpectedHash = $Manifest.$RelPath.sha256
        $ExtractedFile = Join-Path $TempExtractDir ($RelPath -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        $DestinationFile = Join-Path $TargetDir ($RelPath -replace '/', [System.IO.Path]::DirectorySeparatorChar)

        if (-not (Test-Path $ExtractedFile)) {
            Write-Error "Package inconsistency: $RelPath missing from ZIP!"
            exit 1
        }

        # Verify extracted file checksum
        $ActualHash = (Get-FileHash -Path $ExtractedFile -Algorithm SHA256).Hash.ToLower()
        if ($ActualHash -ne $ExpectedHash.ToLower()) {
            Write-Error "Checksum mismatch in package for $RelPath! Expected $ExpectedHash, got $ActualHash"
            exit 1
        }

        $ExistsInDest = Test-Path $DestinationFile
        if ($ExistsInDest) {
            $CurrentHash = (Get-FileHash -Path $DestinationFile -Algorithm SHA256).Hash.ToLower()
            if ($CurrentHash -eq $ExpectedHash.ToLower()) {
                Write-Host "  [IDENTICAL] $RelPath" -ForegroundColor DarkGray
                $VerifiedCount++
                continue
            } else {
                Write-Host "  [UPDATE]    $RelPath" -ForegroundColor Yellow
                $ChangedCount++
            }
        } else {
            Write-Host "  [NEW FILE]  $RelPath" -ForegroundColor Green
            $NewCount++
        }

        if (-not $CheckOnly) {
            # Backup existing
            if ($ExistsInDest) {
                $BackupFileDest = Join-Path $BackupDir ($RelPath -replace '/', [System.IO.Path]::DirectorySeparatorChar)
                $BackupParent = Split-Path -Parent $BackupFileDest
                if (-not (Test-Path $BackupParent)) {
                    New-Item -ItemType Directory -Path $BackupParent -Force | Out-Null
                }
                Copy-Item -Path $DestinationFile -Destination $BackupFileDest -Force
            }

            # Install updated file
            $DestParent = Split-Path -Parent $DestinationFile
            if (-not (Test-Path $DestParent)) {
                New-Item -ItemType Directory -Path $DestParent -Force | Out-Null
            }
            Copy-Item -Path $ExtractedFile -Destination $DestinationFile -Force

            # Post-copy integrity verification
            $CopiedHash = (Get-FileHash -Path $DestinationFile -Algorithm SHA256).Hash.ToLower()
            if ($CopiedHash -ne $ExpectedHash.ToLower()) {
                Write-Error "Installation verification failed for $RelPath after copy!"
                exit 1
            }
        }
    }

    Write-Host "`n----------------------------------------------------------------------" -ForegroundColor Cyan
    if ($CheckOnly) {
        Write-Host "PRE-FLIGHT CHECK COMPLETED SUCCESSFULLY!" -ForegroundColor Green
        Write-Host "  Unchanged: $VerifiedCount | To Update: $ChangedCount | New: $NewCount" -ForegroundColor White
        Write-Host "Run without -CheckOnly to apply updates with automatic backup." -ForegroundColor Gray
    } else {
        Write-Host "UPDATE INSTALLED AND CRYPTOGRAPHICALLY VERIFIED!" -ForegroundColor Green
        Write-Host "  Identical: $VerifiedCount | Updated: $ChangedCount | Newly Added: $NewCount" -ForegroundColor White
        Write-Host "  Backup preserved at: $BackupDir" -ForegroundColor Magenta
        Write-Host "`nTo test the installed update:" -ForegroundColor Cyan
        Write-Host "  Backend:  pytest backend/tests/test_ssrf_scope.py backend/tests/test_conflicts.py ..." -ForegroundColor White
        Write-Host "  Frontend: cd frontend; npm run build" -ForegroundColor White
    }
    Write-Host "----------------------------------------------------------------------" -ForegroundColor Cyan
}
finally {
    if (Test-Path $TempExtractDir) {
        Remove-Item -Path $TempExtractDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
