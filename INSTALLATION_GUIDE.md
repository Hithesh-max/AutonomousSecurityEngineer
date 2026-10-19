# Autonomous Security Engineer (ASE) - Final Update Installation Guide

This guide describes how to apply, verify, and test the final ASE completion update.

---

## 1. Quick Verification & Installation

### Option A: Automatic PowerShell Installer (Recommended)

1. Open PowerShell in the project root directory (`D:\antigrav\AutonomousSecurityEngineer`).
2. Run pre-flight verification without making any changes:
   ```powershell
   .\Apply-ASE-Full-Update.ps1 -CheckOnly
   ```
3. Apply the update with automatic pre-update backup and post-install SHA-256 integrity verification:
   ```powershell
   .\Apply-ASE-Full-Update.ps1
   ```
   *Note: This automatically creates a timestamped backup directory (e.g. `_backup_before_update_YYYYMMDD_HHMMSS`) before modifying any files.*

4. To rollback at any time:
   ```powershell
   .\Restore-ASE-Full-Update.ps1 -BackupDir "_backup_before_update_YYYYMMDD_HHMMSS"
   ```

### Option B: Manual Application
If installing manually or in Linux/Docker environments:
1. Extract `ASE_FINAL_COMPLETION_UPDATE.zip` over the project root directory.
2. Verify all extracted files against `UPDATE_MANIFEST_SHA256.json`.

---

## 2. Running Verification & Test Suites

### Backend Unit & Integration Tests
Execute the comprehensive test suites on the host Python:
```powershell
$env:PYTHONPATH="backend"
pytest backend/tests/test_ssrf_scope.py `
       backend/tests/test_conflicts.py `
       backend/tests/test_verification_runner.py `
       backend/tests/test_supply_chain.py `
       backend/tests/test_api_security.py `
       backend/tests/test_evaluation.py `
       backend/tests/test_collaboration.py `
       backend/tests/unit/ `
       backend/tests/test_corrections.py
```
**Expected Outcome:** 78 passed, 0 failed.

### Frontend Production Build Verification
Ensure the TypeScript client compiles cleanly:
```powershell
cd frontend
npm run build
```
**Expected Outcome:** `tsc -b && vite build` succeeds with `0 errors`.

---

## 3. Starting the Services

### Docker Deployment
```powershell
docker compose up -d --build
```

### Standalone Local Development
**Terminal 1 (Backend API):**
```powershell
cd backend
$env:PYTHONPATH="."
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 (Celery Worker):**
```powershell
cd backend
$env:PYTHONPATH="."
celery -A app.workers.celery_app worker --loglevel=info -Q default,web_scans,analysis
```

**Terminal 3 (Frontend UI):**
```powershell
cd frontend
npm run dev
```
Access the application at `http://localhost:5173`.

---

## 4. Key Functional Areas

1. **Authorized Deployed Web Scanning (`/web-lab`):**
   - Register deployed web targets with pre-flight SSRF resolution checks.
   - Restrict scans to approved explicit scopes (private IP ranges, loopbacks, and cloud metadata 169.254.169.254 are strictly blocked).
   - Preserves `ase-lab` container network scanning.

2. **Supply Chain & SBOM (`/repositories` -> Repository Analysis):**
   - One-click export of CycloneDX v1.5 JSON and SPDX 2.3 JSON SBOMs.
   - Inspect dependencies with curated CVE advisories (`ONLINE`, `OFFLINE_CACHE_ONLY`, `METADATA_UNAVAILABLE`).
   - One-click proposal of dependency version upgrades with generated unified diffs.

3. **Multi-File Remediation & Verification Runner (`/repositories` -> Repository Analysis):**
   - Check line overlaps, function collisions, and dependency conflicts between patch proposals.
   - Run isolated sandbox builds and syntax tests, classifying fixes into 6 strict states (`VERIFIED_FIXED`, `STILL_VULNERABLE`, `REGRESSION`, `FAILED`, `UNSUPPORTED`, `INCONCLUSIVE`).
   - Export printable HTML/PDF remediation reports.

4. **Security Suite (`/security-suite`):**
   - **API Security:** OpenAPI 3.0 / Swagger ingestion and automated synthetic persona tests (`USER_A`, `USER_B`, `ADMIN`, `UNAUTHENTICATED`) for BOLA and BFLA with credential redaction.
   - **Benchmark Evaluation:** 10 ground truth cases across SQLi, Command Injection, Code Eval, Secrets, and Crypto with Confusion Matrix, Precision, Recall, and F1 calculations. Cross-tool correlation without hiding divergence.
   - **Two-Node Transfer & CIA+AA:** Authenticated AES-256-GCM transfer of text, image, audio, and video; SHA-256 integrity verification, tampered payload rejection, and live CIA+AA goals and performance profiling.
