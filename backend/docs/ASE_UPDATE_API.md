# Remediation API and state contract

All routes have the existing `/api` prefix and require the normal authenticated bearer session. Repository and finding ownership is checked; foreign identifiers return 404. External AI requests additionally require `acknowledge_external_transmission: true` when the configured provider is external.

| Method and path | Behavior |
| --- | --- |
| GET `/repositories/{id}/remediation-inventory` | Complete latest-scan finding inventory, source-resolution/eligibility, latest analysis/proposal/verification state. No provider call. |
| POST `/repositories/{id}/remediation-batches` | Body: `{"mode":"ANALYZE" or "PROPOSE","acknowledge_external_transmission":true}`. Returns 202 with persisted job/checkpoint. |
| GET `/repositories/{id}/remediation-batches` | Latest 30 job summaries and per-finding results; historical jobs remain in the database. |
| POST `/remediation-batches/{id}/pause` | Pauses queued work or requests pause after the in-flight provider request. |
| POST `/remediation-batches/{id}/resume` | Resumes paused/failed work; an active job must be stale for at least 15 minutes. A new scan requires a new job. |
| GET `/findings/{id}/remediation` | Existing analysis, proposal, verified source window and audit history. |
| POST `/findings/{id}/analysis` | Existing single-finding structured analysis with consent. |
| POST `/findings/{id}/patches` | Existing proposal generation with optional `analysis_id` and consent. No source mutation. |
| GET `/patches/{id}/corrected-source` | Complete original and proposed file after stored patch/source integrity checks. |
| POST `/patches/{id}/approve` | Body `{"patch_sha256":"<reviewed hash>"}`; checks exact source/proposal hashes and approved overlap. |
| POST `/patches/{id}/reject` | Same body; rejects the pending proposal even if source is no longer available. |
| POST `/patches/{id}/revoke` | Same body; removes approval for subsequent exports. Records an audit event. |
| POST `/patches/{id}/verify` | Reconstructs a private temporary file and applies its language parser. Returns INCONCLUSIVE; no uploaded code execution. |
| GET `/repositories/{id}/remediation-diff` | Consolidated compatible approved changes for review. |
| GET `/repositories/{id}/corrected-zip?all_approved=true` | Authenticated complete reconstructed ZIP for latest-scan approvals. Explicit comma-separated `patch_ids` also supported. Integrity/conflict failures return 409. |
| GET `/repositories/{id}/remediation-report?format=json` | Inventory, job history and audit records. `format=html` returns escaped HTML with restrictive CSP. |

## Durable batch behavior

States: QUEUED → RUNNING → QUEUED (next finding), COMPLETED, or PAUSED. Pause during a request uses PAUSING → PAUSED. A database partial unique index permits at most one active batch per repository. A PostgreSQL session advisory lock prevents simultaneous execution of the same batch across service commits. The task processes one finding, commits the outcome, releases the lock and dispatches the next task. Duplicate delivery does not advance a non-queued batch. Dispatch failures become PAUSED rather than false success.

Provider quota/authentication failures leave the cursor at the pending finding. Other per-finding failures are recorded and processing continues. Starting a new job retries failed findings while preserving valid existing proposals. No background task automatically approves any patch.

## Source and export boundaries

Repository source resolution requires matching project owner, repository, repository-analysis scan, archive identity, indexed relative path, scanner/file hashes and source coordinates. Source is withheld when Gitleaks coverage is missing, the file has a secret finding, a credential filename/content is recognized, the file is too large, or the source has changed. DAST continues using only the existing verified bundled-lab mapping.

Export reconstructs from the hash-checked original ZIP through the existing bounded safe archive extractor. It checks every proposal again, applies bottom-up nonoverlapping edits, syntax-parses the combined result and attempts Semgrep with trusted local rules in a separate copy. It never runs project builds, package installation hooks or uploaded application code. Original archive/source and running lab files are unchanged.

API credential values, `.env`, private-key files, known credential files, detected-secret paths, database dumps/databases, logs, caches and dependency folders are excluded from exports. Exclusions are explicit in the manifest. Secret detection/redaction is defense in depth, not proof that an arbitrary repository has no unknown secret format. Review deployment configuration before using any export.
