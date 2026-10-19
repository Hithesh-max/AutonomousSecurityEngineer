# Secure ZIP ingestion milestone

This extends the supplied ASE codebase. It does not complete Part 2 or enable scanners.

## Architecture

An authenticated project owner selects an approved, active, in-scope target and confirms permission to upload its source. The React Repositories page sends a raw ZIP body to `POST /api/targets/{target_id}/repositories/upload?name=...&source_authorized=true`. The API streams the upload into a private server-issued UUID directory, records a SHA-256 checksum, and commits a Repository and REPOSITORY_INGESTION ScanJob before publishing to Celery. No request field can select a local path.

The Celery worker atomically claims the queued job, rechecks project ownership, active user, target approval, and scope, validates ZIP records, and extracts without executing code. It rechecks authorization before committing COMPLETED and READY together. Failed validation, revoked access, queue failure, and timeouts are recorded with static failure codes/messages. The UI polls PostgreSQL-backed API state every two seconds while jobs/repositories are active.

The API and worker share a named Docker volume `repository_data`, mounted at `/workspaces`. Each repository lives under `/workspaces/repositories/<server UUID>/`, with `upload.zip` and (only after successful extraction) `source/`. Absolute paths and source contents are not returned by the repository API. No files are mounted into the frontend. The previous host `./workspaces` directory is not deleted or reused.

`GET /api/repositories?project_id=...` and `GET /api/repositories/{id}` enforce project ownership. Existing `/api/jobs` endpoints expose repository_id and current ingestion stage. Cross-user access is masked as 404.

## Provenance and states

Repository metadata includes project/target IDs, uploader, permission-confirmation timestamp, source type ZIP, upload bytes, SHA-256 checksum, extraction file count/bytes, ingestion timestamp, failure code/message, and analysis status. The original archive is retained. It is a checksum-based provenance record, not a Git commit; Git/branch/commit tracking belongs to the next ingestion method.

Job: QUEUED → RUNNING (VALIDATING / EXTRACTING) → COMPLETED or FAILED.
Repository: QUEUED → RUNNING → READY or FAILED.
Analysis: NOT_STARTED throughout this milestone. READY means extracted, not analyzed or secure.

## Bounds and extraction policy

Defaults are 20 MiB upload, 100 MiB expanded total, 5 MiB per file, 3,000 entries, and 100:1 maximum per-file compression ratio. Streaming upload has a 60-second deadline. Extraction has a 90-second deadline, and the ingestion task has 110-second soft and 120-second hard Celery time limits. The worker is limited to two task processes, 1 GiB memory, and 128 processes in Compose. Repository admission is bounded to 50 stored records per user, including failed records; it is serialized at final admission per owner.

The central directory is counted before Python allocates ZipInfo objects. Metadata is limited to 2,048 bytes per configured entry in aggregate. Actual expanded bytes are checked while streaming every file; files must pass ZIP CRC checks before publishing. Absolute, parent, ambiguous, control-character, backslash, drive/ADS, Windows reserved, duplicate (including case/Unicode collisions), and file/directory-conflicting paths are rejected. Symlinks, special files, encryption, ZIP64/multi-volume archives, and compression methods other than stored/Deflate are rejected. File modes are rewritten to non-executable 0600. Extraction uses an exclusive private staging directory; rejected archives never publish a source directory.

Initial ingestion never invokes subprocesses, repository scripts, package installers, hooks, imports, binaries, or builds. Workspace separation is for non-executing ingestion; it is not a sandbox for running untrusted application code. Build/test execution must later use a separate sandbox.

Settings use ZIP_MAX_UPLOAD_BYTES, ZIP_MAX_EXPANDED_BYTES, ZIP_MAX_FILE_BYTES, ZIP_MAX_ENTRIES, ZIP_MAX_COMPRESSION_RATIO, ZIP_UPLOAD_SECONDS, and REPOSITORY_LIMIT_PER_USER. Compose forwards them from the operator's existing environment. The UI remains capped at 20 MiB even if an operator increases the backend cap. Existing JWT configuration is preserved; the supplied .env.example is a template only.

## Related repairs included

All ORM models are registered through app.models before a fresh Celery process starts, including User and Repository. This incorporates the import fix proven by the user's diagnostic job.

Stale recovery uses an atomic conditional UPDATE with RETURNING instead of overwriting objects read earlier. Repository failure metadata is committed in that same transaction. Diagnostic/security worker failure writes and API dispatch-failure writes also use conditional UPDATEs. Each task type claims only its matching job type. Recovery failures now fail the Celery task instead of reporting success.

The existing approval popup now suggests a hostname, and the timestamp helper accepts absent timestamps. The login page no longer displays the disabled legacy account's obsolete password hint and labels its submit button Sign in. Registration still uses the existing backend endpoint; a registration UI is not added in this milestone.

## Validation performed here

- `PYTHONPATH=. python -m unittest discover -s tests/unit -v`: 22 tests passed, covering genuine ZIP bytes and malicious archive cases, non-execution, byte limits, CRC corruption, pre-allocation entry limits, deadlines, and workspace safety.
- `python -m compileall -q backend`: passed (run from the extracted source root).
- Strict TypeScript check of src/api.ts and src/pages/Repositories.tsx using the bundled TypeScript/React declarations: passed.
- Static migration-chain validation: one connected head, d7a104c892ab.

Docker is not available in the editing environment. FastAPI/SQLAlchemy/Celery/PostgreSQL dependencies were also unavailable, and installing them was blocked. Therefore the full pytest suite, live migrations, Redis/Celery execution, browser upload integration, and a complete Vite build have NOT been verified here. The archived node_modules is incomplete; a whole-project type check hit missing existing dependencies. An existing ScanCenter timestamp type error found by that check was corrected. No fake scanner or provider results were introduced.

Additional PostgreSQL integration tests are supplied in backend/tests/test_repositories.py. They cover authenticated uploads, ownership, approval/scope, permission confirmation, malformed/oversized/chunked uploads, ingestion provenance, duplicates, malicious ZIP failures, revocation, disabled users, broker failures including ambiguous publication after successful execution, stale recovery, repository quotas, and fresh-process model registration. Those tests stub queue publication for deterministic execution, and call the real extraction worker. They do not mock security scanners. Run them locally with the full suite before accepting the milestone.

## Limitations and exact next step

No Git/local-path ingestion, technology/dependency detection, source indexing/viewer, scanning, findings, AI analysis, patches, or verification was implemented in this update. The SCAN button continues to fail honestly; READY repositories are not wired to scanners yet.

Archives/workspaces are retained for provenance and have no user-facing deletion/retention operation yet. A killed worker can leave private staging files, or a source directory without a READY record; such files are not exposed or considered successful. Recovery marks jobs failed after 15 minutes but does not itself stop processes. The ingestion task has its own hard execution limit. Beat runs in the single worker container; if the whole container stops, recovery waits until it starts again. Production multi-worker scheduling and stronger filesystem/runtime isolation remain later work.

Next: verify a real browser upload reaches READY/COMPLETED and survives refresh, run the local tests/build, then add language/framework/dependency indexing and connect real Semgrep/Gitleaks analysis to repository IDs (not client-provided paths).
