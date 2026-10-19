# ASE repository intelligence + real static analysis update

This ZIP contains changed/new files only. Apply it to the SAME original project:
`D:\antigrav\AutonomousSecurityEngineer`.
Do not run Docker Compose from the extracted update directory. Do not replace your `.env`, reset data, or delete Docker volumes.

## Apply the update

1. Open PowerShell in the original project folder and stop application containers:

```powershell
cd D:\antigrav\AutonomousSecurityEngineer
docker compose stop backend worker frontend
```

2. Extract the update ZIP elsewhere. Copy all its contents into the original project folder, merging folders and replacing every matching file. In particular replace `backend/app/workers/recovery_jobs.py`, `celery_app.py`, and BOTH modified model files `project.py` and `repository.py`. These must stay together to avoid mapper initialization errors. Keep your original `.env`.

3. Apply the forward migration and start the same services:

```powershell
docker compose run --rm backend alembic upgrade head
docker compose up -d
docker compose ps
```

Expected migration: `d7a104c892ab -> e821ac6093fb`. Existing repositories/users/findings are preserved. Code is bind-mounted by the existing Compose setup, so rebuilding images is not required for this update. Existing Docker images should already contain Semgrep and Gitleaks; the next command verifies that instead of assuming it.

4. Run a mandatory real scanner check in the worker:

```powershell
docker compose exec worker python scripts/check_static_tools.py
```

It must print PASS for BOTH Semgrep and Gitleaks and detect the seeded cases. A missing executable, unsupported flag, invalid rule or missing expected finding is a failure. Do not treat missing tools as a successful scan. If it fails, share that output before continuing.

5. Run database/API/worker regression tests and the complete frontend build:

```powershell
docker compose exec backend sh -c "PYTHONPATH=/app pytest -ra"
docker compose exec frontend npm run build
```

The suite includes a real scanner/database acceptance test. Any skip due to unavailable scanners is an acceptance gap. Tests use disposable UUID PostgreSQL databases; they do not reset the application database.

## Use the new feature

1. Open `http://localhost:5173`, sign in and go to Repositories.
2. Select your existing project and approved target.
3. Upload the included `samples/ase-static-analysis-lab.zip`; wait for ingestion READY.
4. Click **Analyze repository** on that repository card.
5. Watch actual backend stages and both tool results. Review languages, frameworks, manifests, extracted dependencies and findings.
6. Open the SAST finding's source context. Secret-bearing files are deliberately withheld; their findings retain redacted evidence and location.
7. Refresh: analysis history, tool results and findings must remain.

The previous tiny ingestion sample may legitimately produce no findings. The new sample is deliberately vulnerable static input and contains only a synthetic, nonfunctional credential. Do not execute or deploy its code.

Use **Analyze repository** in Repositories for this milestone. Scan Center's older SCAN action still has its previous restrictions; this update does not implement network scanning or change that action.

## Delivery verification and limits

Verified locally: 33 standard-library tests, Python compilation, focused strict TypeScript checks for the API client and repository pages. Real scanner smoke check failed honestly with `Semgrep executable not found` in this delivery environment. Docker is unavailable here, so migrations, PostgreSQL integration, full frontend build and real scans remain locally unverified until you run the commands above.

New functionality: repository inspection, bounded scanner adapters, versioned local rules, persistent per-tool progress, partial failure handling, normalized findings with provenance, searchable source metadata and a redacted source viewer. No fabricated security findings are generated.

Not implemented: public Git ingestion, complete semantic indexing, Nmap/ZAP/Trivy orchestration, AI patch generation, correlation/risk, independent verification/regression or final reports. Dedicated scanner OS sandboxing, orphan workspace cleanup and stronger tool supply-chain controls remain hardening work. See `docs/repository-analysis.md` for exact coverage and constraints.

Full frontend build was also attempted in the delivery environment: `npm run build` was blocked by permissions on the extracted TypeScript launcher. Running the launcher directly (`node node_modules/typescript/bin/tsc -b`) confirmed missing local packages (`lucide-react`, `framer-motion`, `@tailwindcss/vite`). This incomplete extracted dependency tree is not evidence of a successful full build; use the Docker build command above for verification. The new repository pages and API client passed their separate strict TypeScript check.
