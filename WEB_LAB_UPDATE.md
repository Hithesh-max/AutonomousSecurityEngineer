# ASE: isolated web-lab assessment update

This is an incremental update to the existing project. It adds real Nmap and OWASP ZAP adapters, an isolated vulnerable lab, authenticated scan submission, persistent results, and a Web Lab page. It does not complete all of Part 3.

## Install in your ORIGINAL folder

1. In PowerShell at `D:\antigrav\AutonomousSecurityEngineer`, stop application processes while copying:

   ```powershell
   docker compose stop backend worker frontend
   ```

2. Extract this ZIP elsewhere, then copy its **contents** into `D:\antigrav\AutonomousSecurityEngineer`, replacing matching files. Keep your existing `.env`. This ZIP contains changed files only, not a standalone replacement project. Do not delete volumes or run `down -v`.

3. Generate a separate ZAP API key without replacing your existing configuration:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\Enable-WebLab.ps1
   ```

4. Build the small lab image and start the combined configuration:

   ```powershell
   docker compose -f docker-compose.yml -f docker-compose.lab.yml build ase-lab
   docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d
   docker compose -f docker-compose.yml -f docker-compose.lab.yml ps
   ```

   The first start downloads the ZAP image and may take several minutes. Existing backend/worker images already contain Nmap; application source is mounted from your folder. No new migration is required. Use BOTH Compose files for subsequent `up` commands while using the lab. The fixed subnet is `172.30.250.0/28`; a Docker subnet collision must be resolved before starting, not bypassed by changing target validation.

5. Test real scanners from the worker (after ZAP has started):

   ```powershell
   docker compose exec worker python scripts/check_web_lab.py --authorized-lab
   ```

   Expect real Nmap port discovery and ZAP crawl/passive findings. If ZAP is still starting, inspect `docker compose -f docker-compose.yml -f docker-compose.lab.yml logs --tail=60 zap`, wait for startup, and retry. A failure is not a successful assessment. The smoke test does not store findings in PostgreSQL.

## Verify through ASE

1. Open `http://localhost:5173`, log in, select **Web Lab** in the navigation.
2. Select your existing project and click **Register bundled lab target**.
3. Check the authorization box and click **Confirm lab authorization**. The URL is fixed to `http://ase-lab:8080`; scope is `ase-lab`. This is a new target; do not repurpose your repository target.
4. Leave the profile at **SAFE** and active testing unchecked. Click **Start crawl and passive lab scan**.
5. Watch real job stages. Inspect Nmap port 8080, ZAP endpoints, tool versions, and stored findings. Refresh: history and findings must remain visible.
6. For the second assessment, check the explicit active-testing consent and start again. Only the XSS and SQL injection active rules are enabled. Inspect actual results; do not assume every seeded vulnerability will be detected by every tool version.
7. Revoke authorization and verify another scan cannot be submitted. Revocation during execution is checked repeatedly; network requests already in flight may finish before stopping.

An optional independent active smoke test is:

```powershell
docker compose exec worker python scripts/check_web_lab.py --authorized-lab --active
```

It fails if neither seeded active rule is detected. It also does not write database findings.

## Regression checks on your machine

```powershell
docker compose exec backend sh -c "PYTHONPATH=/app pytest -ra --tb=short"
docker compose exec frontend npm run build
```

These commands remain necessary. The six new database/API tests require PostgreSQL. Unit parser fixtures exercise error handling and control flow; they are not evidence that a real scanner ran.

## What was verified while preparing this update

- `python -m unittest discover -s tests/unit -q` in backend: **43 passed**.
- `python -m unittest discover -s lab -p 'test_*.py' -v`: **3 passed**, using a real temporary loopback HTTP server.
- Python compilation of backend modules, tests, scripts, and migrations: passed.
- Focused strict TypeScript checks for the API client, Web Lab page, and modified Repositories page: passed.
- Docker Compose execution, PowerShell execution, PostgreSQL integration tests, real Nmap/ZAP execution, and full frontend build: **not executable in the preparation environment**. They must be verified locally. This is not a claim of end-to-end completion.

## Boundaries and limitations

- Only the bundled lab origin and fixed Docker IP are accepted. No arbitrary Internet scanning or public lab ports.
- SAFE means conservative Nmap TCP reconnaissance; ZAP crawling still sends HTTP requests. Active testing is separately opt-in.
- Lab and ZAP run on an internal Docker network without published ports. The lab uses synthetic, per-request SQLite data. Neither receives repository or database mounts.
- ZAP uses an API key and permits only the worker IP. A Redis lease serializes access to its session across users/jobs; this shared lab is for the local classroom demonstration, not a multi-tenant hosted service.
- A tool failure produces FAILED or PARTIALLY_COMPLETED, with per-tool diagnostics. No fallback findings. An open port is reconnaissance, not automatically a vulnerability.
- ZAP stop failure retains the lease until its 15-minute expiry. Restart ZAP and allow expiry before retrying; do not delete locks while jobs may still be running.
- Duration caps can make coverage inconclusive. A completed scan means the configured bounded workflow finished, not that the application is secure.
- Evidence stores rule, endpoint without query values, parameter, bounded redacted evidence, versions, and job provenance. It does not store full HTTP bodies or credentials.
- ZAP uses its `stable` image tag; the actual scanner version is recorded. A validated image digest should be pinned after the first successful local acceptance run.
- Git ingestion, Trivy orchestration, OpenAPI ingestion, cross-tool correlation, AI patch generation, verified remediation, and final reporting remain separate work.
- Repository source withholding for suspected secrets remains enabled. The stale repository message claiming analysis has not started is corrected.

## Changed files

See `CHANGED_FILES_SHA256.txt` for the exact inventory. No `.env`, credentials, dependencies, database dumps, or volume contents are included.
