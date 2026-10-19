# ASE project filtering and Security Suite repair

Apply this update to the current project supplied as `AutonomousSecurityEngineer (4).zip`.
It contains only changed/new files. It does not clear the database, uploads, targets,
accounts, lab, Docker volumes or `.env`. No migration is required.

## Install on Windows

1. Extract this ZIP into a separate directory, such as `D:\antigrav\ASE_Project_Scope_Suite_Fix`.
2. From PowerShell run:

```powershell
powershell -ExecutionPolicy Bypass -File "D:\antigrav\ASE_Project_Scope_Suite_Fix\Apply-Fix.ps1" -ProjectRoot "D:\antigrav\AutonomousSecurityEngineer"
```

The installer checks the files against the supplied baseline and backs up every
file it changes. If a file has changed locally since that ZIP, it stops before copying;
provide the mismatch output rather than deleting local files.

3. Rebuild to install the missing YAML/performance dependencies and start the updated services:

```powershell
cd D:\antigrav\AutonomousSecurityEngineer
docker compose -f docker-compose.yml -f docker-compose.lab.yml -f docker-compose.lab-browser.yml up -d --build backend worker frontend
```

If you do not have the optional browser override, omit its `-f` argument.
Do not run `down -v`, database truncation, Redis flush or database reset.
Refresh the browser with Ctrl+F5 after the rebuild.

## Acceptance checks

- Findings: select AllInOneAi. ASE Lab findings must disappear. Selecting an uploaded
  repository further restricts the table and repository actions. The table includes
  source/tool/location/scan provenance. Run Analyze repository after ZIP ingestion;
  no stored findings alone does not establish security.
- API suite: import an actual JSON/YAML OpenAPI specification for the selected target.
  Configure distinct synthetic User A, User B and administrator tokens and an existing
  User A resource ID. Only GET/HEAD are probed. Failed owner/admin control requests are
  inconclusive. The simple ASE Lab does not provide the required authenticated API fixtures.
- Finding comparison: handles absent locations/tool lists and namespaces locations by
  repository/scan. This is location grouping, not measured cross-tool accuracy.
- Benchmark: displays native backend results and explicitly states that string heuristics,
  not real scanners, are evaluated. Results are not evidence of Semgrep/ZAP accuracy.
- Encryption demo: text and real image/audio/video file round trips now use the backend's
  actual packet contract. Keys are scoped to the signed-in user and metadata is authenticated.
  This is one-process encryption, not inter-device delivery. Event logs are bounded,
  per-user and in memory, not immutable or persistent.
- Approved changes: generate/review/approve patches first, then use Validate Approved
  Changes (Static). Empty approvals return a clear prerequisite message. Reviewed hashes
  are checked; compatible edits to one file are combined. Syntax checks and trusted
  Semgrep reanalysis may run. Nothing executes uploaded build/test scripts in the backend.
- Dependency previews: send manifest/package/version fields correctly and reject unsafe
  paths/versions. These previews are not approved patches; lockfiles and compatibility
  tests are not updated. Advisory examples are explicitly offline, and no match is not
  described as proof that a dependency is safe.

## Validation and boundaries

Executed: 66 offline workflow/API/security regressions and 28 selected pure unit tests
passed in separate runs; TypeScript and Vite production build passed; Python compilation
and ZIP integrity checks passed. Workflow tests use SQLite and explicit mock AI/probes.
The unit tests are run without the existing PostgreSQL autouse test-database fixture.
A larger than 500 KB frontend bundle warning remains.

Not executed here: PowerShell installer/rollback execution, live Docker rebuild, PostgreSQL migration/locking, browser automation,
real Gemini requests, live target authorization probes or live ZAP scans.

A true isolated application build/test/dynamic verification runner is still absent.
The previous runner used a temporary directory and executed project scripts inside the
API container; it could also label ordinary test success VERIFIED_FIXED. This update
removes that execution path and reports static checks as INCONCLUSIVE or an evidenced
failure/still-reported alert. It does not claim to implement the missing execution runner.

This repair is not completion of the entire enterprise specification. The full labeled
real-scanner benchmark, actual two-node media delivery, durable transfer audit, complete
supply-chain upgrades and universal multi-file remediation remain separate work.

## Roll back

Use the backup directory printed by the installer:

```powershell
powershell -ExecutionPolicy Bypass -File "D:\antigrav\ASE_Project_Scope_Suite_Fix\Restore-Fix.ps1" -BackupDirectory "D:\antigrav\ASE-Fix-Backup-YYYYMMDD-HHMMSS"
```

Then run the same service rebuild command. Rollback also preserves database and uploads.
