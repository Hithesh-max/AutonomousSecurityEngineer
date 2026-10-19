$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    if (!(Test-Path 'docker-compose.yml') -or !(Test-Path '.env')) {
        throw 'Run this update in the existing ASE project with its existing .env.'
    }
    $existing = @(Get-Content -LiteralPath '.env' | Where-Object { $_ -match '^\s*ZAP_API_KEY\s*=' })
    if ($existing.Count -gt 1) { throw 'Duplicate ZAP_API_KEY entries in .env; keep exactly one.' }
    if ($existing.Count -eq 0) {
        $bytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        $key = [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
        Add-Content -LiteralPath '.env' -Value ("`nZAP_API_KEY=" + $key) -Encoding ASCII
        Write-Host 'Added a separate random ZAP key. Existing settings were preserved.'
    } elseif (($existing[0] -replace '^\s*ZAP_API_KEY\s*=\s*', '').Trim().Length -lt 32) {
        throw 'Existing ZAP_API_KEY is too short. Replace it with a random value of at least 32 characters.'
    }
    docker compose -f docker-compose.yml -f docker-compose.lab.yml config --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Compose configuration validation failed.' }
    Write-Host 'Configuration ready. Follow WEB_LAB_UPDATE.md to build and start the lab.'
} finally { Pop-Location }
