param([string]$Project = 'D:\antigrav\AutonomousSecurityEngineer')
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (!(Test-Path (Join-Path $Project 'backend\app\api\remediation.py')) -or !(Test-Path (Join-Path $Project 'frontend\src\pages\Findings.tsx'))) {
    throw 'The target is not the existing ASE project. Nothing was changed.'
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = Join-Path $Project ("ase-batch-backup-" + $stamp)
New-Item -ItemType Directory -Force -Path $backup | Out-Null
$files = @('backend\app\api\remediation.py','frontend\src\api.ts','frontend\src\components\BulkRemediation.tsx','frontend\src\pages\Findings.tsx')
foreach ($relative in $files) {
    $original = Join-Path $Project $relative
    if (Test-Path $original) {
        $destination = Join-Path $backup $relative
        New-Item -ItemType Directory -Force -Path (Split-Path $destination -Parent) | Out-Null
        Copy-Item -LiteralPath $original -Destination $destination
    }
}
# Inspect current Findings.tsx before any source replacement.
$page = Join-Path $Project 'frontend\src\pages\Findings.tsx'
$content = Get-Content -LiteralPath $page -Raw
if ($content -notmatch 'BulkRemediation') {
    if (!$content.Contains("import RemediationPanel from '../components/RemediationPanel';")) { throw 'Findings import layout differs; original files backed up. No files installed.' }
    if (!$content.Contains('<div className="bg-[#0F1523]')) { throw 'Findings layout differs; original files backed up. No files installed.' }
}
foreach ($relative in @('backend\app\api\remediation.py','frontend\src\api.ts','frontend\src\components\BulkRemediation.tsx')) {
    $src = Join-Path $here $relative
    $dst = Join-Path $Project $relative
    New-Item -ItemType Directory -Force -Path (Split-Path $dst -Parent) | Out-Null
    Copy-Item -LiteralPath $src -Destination $dst -Force
}
if ($content -notmatch 'BulkRemediation') {
    $content = $content.Replace("import RemediationPanel from '../components/RemediationPanel';", "import RemediationPanel from '../components/RemediationPanel';`r`nimport BulkRemediation from '../components/BulkRemediation';")
    $content = $content.Replace('      <div className="bg-[#0F1523]', '      <BulkRemediation findings={findings} onReview={id => setExpandedId(id)} />' + "`r`n" + '      <div className="bg-[#0F1523]')
    Set-Content -LiteralPath $page -Value $content -Encoding utf8
}
Write-Host 'ASE batch update installed. Existing .env, database, lab and ZAP Compose files untouched.'
Write-Host "Backup folder: $backup"
Write-Host 'Next: docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d --build --no-deps backend frontend'
