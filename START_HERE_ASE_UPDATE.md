# ASE update — uploaded-source remediation and corrected-project export

This is an **update-only package based on AutonomousSecurityEngineer (3)(1).zip**. It contains changed files, new modules, tests, and installation documentation. It is not a replacement project, and it contains no `.env`, credentials, database dump, uploaded repositories, dependencies, or unchanged project files.

## What this release implements

- Uploaded SAST findings resolve against the owning scan, archive identity, source manifest, scanner evidence, and exact file hash. The bundled-lab restriction remains only for DAST.
- SQL injection, dynamic evaluation and shell-execution findings can reach source review when their real source is verified. Eligibility does not promise that a behavior-preserving automatic fix exists. Arbitrary command-running endpoints need an explicit application-specific security design.
- Credential findings remain visible with rotation/revocation guidance. Files with detected credentials are withheld from AI. Missing secret-scan coverage fails closed.
- Durable Celery remediation batches process one finding per task, retain proposals and checkpoints, support analysis-only or proposal mode, pause/resume, and stop on quota/authentication failures. Refreshing the browser does not lose work.
- Full original/corrected file previews, exact-hash approvals, selected/all approval, overlapping-edit rejection, revocation, combined approved diff and audit events.
- Server-side corrected ZIP export reconstructs the original complete upload, applies compatible approved changes, retains ordinary unchanged files, excludes credential/private artifacts, runs syntax checks and attempts trusted Semgrep reanalysis. It checks archive CRCs and includes a remediation manifest.
- Python/JSON and Tree-sitter syntax adapters for JavaScript/JSX, TypeScript/TSX, Java, C/C++, HTML and CSS. SQL and unsupported formats require manual review. Parsing is not type checking, building or testing.
- Gemini/OpenAI settings reach both backend and background worker. The missing timezone import in approval is repaired.

**This does not complete every research/enterprise feature in the supplied directive.** See `docs/ASE_UPDATE_VALIDATION.md` for executed tests, limitations and remaining modules. No real provider, Docker lab or PostgreSQL runtime success is claimed from this environment.

## Install on your existing Windows project

1. Extract this update ZIP to a separate folder, for example `D:\ase-update`. Do not replace your original project directory with this folder.
2. In PowerShell, stop only the application services while installing (keep the database, Redis, ZAP and lab running):

```powershell
Set-Location 'D:\antigrav\AutonomousSecurityEngineer'
docker compose -f docker-compose.yml -f docker-compose.lab.yml stop backend worker frontend
```

3. Run the installer from the extracted update folder:

```powershell
Set-Location 'D:\ase-update'
powershell -ExecutionPolicy Bypass -File .\Apply-ASE-Update.ps1 -ProjectPath 'D:\antigrav\AutonomousSecurityEngineer' -CheckOnly
powershell -ExecutionPolicy Bypass -File .\Apply-ASE-Update.ps1 -ProjectPath 'D:\antigrav\AutonomousSecurityEngineer'
```

The installer validates every supplied SHA-256, checks changed originals against your uploaded snapshot, and backs up files before replacing them. It stops rather than overwriting newer local edits. It never writes `.env`, resets PostgreSQL, or removes volumes. If a checksum conflict appears, preserve that local file and merge its changes; do not bypass the check blindly.

4. Rebuild all three application services. The worker needs the new parser packages and task registration too:

```powershell
Set-Location 'D:\antigrav\AutonomousSecurityEngineer'
docker compose -f docker-compose.yml -f docker-compose.lab.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.lab.yml build backend worker frontend
```

Stop if either command fails. Avoid `docker compose config` without `--quiet`, which can print expanded secrets.

5. Back up PostgreSQL using your normal backup process. Apply the additive migration with a one-off backend container, then restart application services:

```powershell
docker compose -f docker-compose.yml -f docker-compose.lab.yml run --rm --no-deps backend alembic upgrade head
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d --no-deps backend worker frontend
docker compose -f docker-compose.yml -f docker-compose.lab.yml exec backend alembic current
```

Expected new head: **f19b6c20aa01**. It adds only `remediation_batches` and indexes. It does not modify existing users/findings/scans or drop tables. Never run `down -v`, delete database volumes or stamp migration history to get around an error.

If you do not use the web lab, omit `-f docker-compose.lab.yml` consistently. The base Compose defaults to OpenAI; set `AI_PROVIDER`, `AI_MODEL` and the corresponding key in your existing configuration if you use Gemini without the lab overlay. The lab overlay retains Gemini defaults. Existing `ZAP_API_KEY` requirements and lab isolation remain intact.

6. Hard-refresh the browser (`Ctrl+Shift+R`). On Findings, select your uploaded repository in Whole-project remediation.

## Use the workflow

1. Ensure the repository scan finished and Gitleaks completed successfully. Existing source/index hashes can be reused; re-upload is not automatically required.
2. Inspect source eligibility. Source-changed/missing/credential/unsupported results explain the reason; they are not silently omitted.
3. Authorize the external provider only if you agree, then select **Analyze all findings** or **Generate all eligible fixes**.
4. Review saved progress. A provider quota pause does not advance past the pending finding. Resume after correcting the quota/credentials. A crashed worker can be resumed after 15 minutes without a checkpoint. A fresh batch retries failed findings and preserves existing valid proposals.
5. Open each proposal and inspect the diff, full original/corrected file, assumptions and limitations. Approve selected proposals or reviewed validated proposals. Approval is tied to exact patch/source hashes; overlapping approved edits are rejected.
6. Review the combined approved diff. Optionally run the isolated syntax check. Its status is intentionally **INCONCLUSIVE**, not “fixed”.
7. Download the corrected project ZIP. Credential files are omitted and listed in its manifest; restore required secrets securely in the target deployment. Removing a secret does not revoke it. The project ZIP includes ordinary unchanged assets/configuration and all approved compatible edits.
8. Download the audit report. The ZIP's `ASE_REMEDIATION_MANIFEST.json` contains export-specific syntax/rescan evidence, changed hashes, excluded files and unresolved findings. Revocation affects future exports, not copies already downloaded.

Default AI budget is 20 requests/hour/user. A new analysis plus proposal generally uses two requests. Batches stop at the configured budget and resume later; there is no eight-finding batch truncation. `AI_MAX_REQUESTS_PER_HOUR` can be configured within the existing validated bounds when your provider budget permits.

## Validate on your machine

```powershell
docker compose -f docker-compose.yml -f docker-compose.lab.yml exec backend python -m pytest checks -q
docker compose -f docker-compose.yml -f docker-compose.lab.yml exec backend python -m pytest tests -q
```

The existing full test suite creates its own `ase_test_*` PostgreSQL database and requires database-creation privileges; it refuses to select the application database. Run it against a disposable test deployment if your operator policy requires that. Docker lab and real external-provider acceptance still need your configured environment.

## Rollback

Stop backend/worker/frontend. From the extracted update folder run:

```powershell
powershell -ExecutionPolicy Bypass -File .\Restore-ASE-Update.ps1 -BackupPath 'D:\antigrav\AutonomousSecurityEngineer\ase-update-backup-<actual-name>'
```

Use the actual backup directory printed by the installer. Rollback checks that installed files have not changed since installation before restoring originals/removing newly added files. Rebuild and restart using the restored Compose files. **Keep the additive migration/table** to preserve batch history; old code can ignore it. Do not downgrade or delete volumes just to roll back source files.
