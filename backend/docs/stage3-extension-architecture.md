# ASE Stage 3 extension: architecture and status

Source of truth for what is built. Updated per phase; "Not built" means exactly that.

## Phase 1 audit findings (from the repository, not assumptions)
- Backend: FastAPI + SQLAlchemy + Alembic (head was `e821ac6093fb`), Celery/Redis, PostgreSQL. Tests need a real
  PostgreSQL and Redis (conftest creates a throwaway `ase_test_*` database; it never touches the app database).
- Baseline before changes: 94 passed, 1 skipped (real Semgrep+Gitleaks absent), 25 subtests. Not the 79 of earlier notes.
- Reusable: `app/utils/redaction.py`, `app/repositories/intelligence.py` (manifest parsing, for SCA phase),
  `app/scanners/trivy.py` (exists; no timeout / exit-code handling yet), `app/network/scope.py` (lab-only egress),
  verified bundled-lab mapping table `_LAB_MAPPINGS` in `app/api/web_scans.py` (reused read-only, never edited).
- Pre-existing AI code: `services/llm.py` + `workers/remediation_jobs.py` + `POST /findings/{id}/remediate` store raw
  free text in `findings.remediation_plan`. Left untouched; the new pipeline is separate and validated.
- The lab source is mounted read-only only in the `backend` container (docker-compose.lab.yml), not `worker`.
  Phase 2 therefore runs AI calls in the API process (bounded by AI_TIMEOUT_SECONDS), not in Celery.

## Phase 2 (AI remediation foundation) - built
Flow: finding -> Analyze (validated JSON, stored) -> Generate patch (edits validated, diff rendered by ASE, stored).
Nothing is applied, approved, executed or verified in this phase.

| Concern | Where |
|---|---|
| Provider abstraction (OpenAI adapter, test-only mock) | `app/ai/providers.py`, `app/ai/factory.py` |
| Untrusted-data prompts with per-request nonce | `app/ai/prompts.py` |
| Output schemas (extra fields forbidden) | `app/ai/schemas.py` |
| Source locator interface + bundled-lab adapter | `app/remediation/source.py` |
| Patch validation + diff + measured checks | `app/remediation/patching.py` |
| Lifecycle state machine (approval states defined, unused yet) | `app/remediation/states.py` |
| Orchestration, consent, rate limit, advisory lock, audit | `app/remediation/service.py` |
| API | `app/api/remediation.py` |
| Tables | `ai_analyses`, `patch_proposals`, `remediation_events` (migration `a3f1c0de5b21`) |
| UI | `frontend/src/components/RemediationPanel.tsx`, `DiffViewer.tsx`, mounted in Web Lab finding details |

Endpoints: `GET /api/ai/status`, `GET /api/findings/{id}/remediation`, `POST /api/findings/{id}/analysis`,
`POST /api/findings/{id}/patches`, `GET /api/patches/{id}`.

Configuration (all optional except a key): `AI_PROVIDER` (OpenAIProvider), `AI_MODEL`, `AI_API_KEY` or `OPENAI_API_KEY`,
`AI_TIMEOUT_SECONDS`, `AI_MAX_RETRIES`, `AI_MAX_OUTPUT_TOKENS`, `AI_MAX_CONTEXT_CHARS`, `AI_MAX_REQUESTS_PER_HOUR`.

Safety properties enforced and tested: ownership (404 for foreign ids); explicit per-request consent before any
external transmission; redaction of evidence before prompts; model may not supply locations, paths or diffs; edits
must quote exact current source, stay inside the verified mapping window, parse as Python, add no non-allow-listed
imports or dangerous calls; stale analysis/source blocks patching; one in-flight AI request per finding; hourly
limit; no fallback to fabricated AI output; append-only audit events.

## Not built yet (do not treat as available)
Approval/rejection, isolated patch application, regression tests, patched-lab rescanning, verification reports,
remediation quality score (Phase 6); SCA/SBOM (Phase 3); API authorization testing (Phase 4); false-positive
reduction (Phase 5); remediation of non-bundled-lab findings (needs a managed-repository locator adapter).
