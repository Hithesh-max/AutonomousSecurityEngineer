import os
import sys
import json
import zipfile
import hashlib
from pathlib import Path

ROOT_DIR = Path(r"D:\antigrav\AutonomousSecurityEngineer")
ZIP_NAME = "ASE_FINAL_COMPLETION_UPDATE.zip"
MANIFEST_NAME = "UPDATE_MANIFEST_SHA256.json"

FILES_TO_PACKAGE = [
    # Backend Core & Network
    "backend/app/network/scope.py",
    "backend/app/scanners/nmap.py",
    "backend/app/scanners/zap.py",
    "backend/app/scanners/controlled.py",
    
    # Backend Remediation & Verification
    "backend/app/remediation/conflicts.py",
    "backend/app/verification/runner.py",
    "backend/app/api/remediation.py",
    
    # Backend Supply Chain
    "backend/app/supply_chain/sbom.py",
    "backend/app/supply_chain/advisories.py",
    "backend/app/supply_chain/upgrades.py",
    "backend/app/api/supply_chain.py",
    
    # Backend API Security
    "backend/app/api_testing/openapi_parser.py",
    "backend/app/api_testing/authorization_checker.py",
    "backend/app/api/api_security.py",
    
    # Backend Evaluation & Benchmark
    "backend/app/evaluation/benchmark.py",
    "backend/app/evaluation/metrics.py",
    "backend/app/api/evaluation.py",
    
    # Backend Collaboration & Security Goals (4-Member Requirement)
    "backend/app/collaboration/node_transfer.py",
    "backend/app/collaboration/security_evaluation.py",
    "backend/app/api/collaboration.py",
    
    # Backend App & Config Updates
    "backend/app/main.py",
    "backend/app/config/settings.py",
    "backend/app/api/web_scans.py",
    "backend/app/workers/web_jobs.py",
    
    # Backend Tests
    "backend/tests/conftest.py",
    "backend/tests/test_ssrf_scope.py",
    "backend/tests/test_conflicts.py",
    "backend/tests/test_verification_runner.py",
    "backend/tests/test_supply_chain.py",
    "backend/tests/test_api_security.py",
    "backend/tests/test_evaluation.py",
    "backend/tests/test_collaboration.py",
    "backend/tests/unit/test_archive.py",
    "backend/tests/unit/test_controlled_tools.py",
    "backend/tests/unit/test_intelligence.py",
    "backend/tests/unit/test_web_tools.py",
    
    # Frontend Source Updates
    "frontend/src/api.ts",
    "frontend/src/App.tsx",
    "frontend/src/pages/WebLab.tsx",
    "frontend/src/pages/RepositoryAnalysis.tsx",
    "frontend/src/pages/SecuritySuite.tsx",

    # Installation Scripts and Final Reports
    "Apply-ASE-Full-Update.ps1",
    "Restore-ASE-Full-Update.ps1",
    "INSTALLATION_GUIDE.md",
    "ASE_FINAL_COMPLETION_REPORT.md",
]

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def main():
    print(f"Creating release package from {ROOT_DIR}...")
    manifest = {}
    missing = []
    
    zip_path = ROOT_DIR / ZIP_NAME
    manifest_path = ROOT_DIR / MANIFEST_NAME
    
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel_path in FILES_TO_PACKAGE:
            full_path = ROOT_DIR / rel_path.replace("/", os.sep)
            if not full_path.exists():
                print(f"ERROR: Missing file {full_path}")
                missing.append(rel_path)
                continue
            
            file_hash = sha256_file(full_path)
            file_size = full_path.stat().st_size
            manifest[rel_path] = {
                "sha256": file_hash,
                "bytes": file_size
            }
            
            # Write to ZIP using forward-slash normalized relative path
            zf.write(full_path, arcname=rel_path)
            print(f"  + Added {rel_path} ({file_size} bytes, sha256: {file_hash[:12]}...)")
            
    if missing:
        print(f"Packaging failed due to {len(missing)} missing files.")
        sys.exit(1)
        
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        
    print(f"\nManifest written to {manifest_path} ({len(manifest)} files tracked).")
    print(f"Final Package created at {zip_path} ({zip_path.stat().st_size} bytes).")

if __name__ == "__main__":
    main()
