# Repository analysis milestone

ZIP ingestion remains a separate prerequisite. An approved, active, in-scope target and a READY server-managed repository are required for analysis. Public Git ingestion, Nmap/ZAP/Trivy orchestration, correlation, AI patching and verification are not part of this update.

## Data flow

The API locks the repository, admits at most one active analysis, commits a UUID job and latest-analysis pointer, then publishes its preassigned Celery task ID. Broker failure updates only an unclaimed job. The worker atomically claims a QUEUED repository-analysis job and rechecks authorization before indexing, each tool, and publication.

Indexing uses Python AST, JavaScript/TypeScript heuristics, shebang/content signals and manifest parsing. Extension-only classifications carry LOW confidence. Route candidates retain an unresolved-prefix flag; they are not verified endpoint-to-service mappings. No imported repository modules or scripts are executed. Ignored dependency/build/Git directories are excluded. Python text beyond 512 KiB and text beyond 1 MiB have limited indexing. Files remain bounded by ingestion's 5 MiB/file and 100 MiB total limits. Metadata is capped at 4 MiB; exceeding resource limits fails honestly. Requirements environment markers and lockfile-v1 recursive resolution are not fully modeled. Docker/Compose manifests are detected only. There is no dependency vulnerability lookup in this milestone.

A fresh private, checksum-validated copy of eligible source becomes scanner input. Uploaded ignore/config files are excluded. Semgrep uses only the versioned local ASE rules, disables inline suppression, metrics, version checks and Git ignore behavior. Gitleaks uses a trusted config extending its installed defaults, ignores uploaded suppressions, and scans current files without Git history. Raw reports and snippets are transient and are not stored in the database. Gitleaks's finding exit code is 7, separate from ordinary tool failures.

The controlled adapter exposes environment validation, health/version checks, execute, parse, normalize and scan. It uses absolute executables, argv arrays, no shell, private HOME/TMPDIR, and a child environment containing no application API/JWT/database secrets. It kills the process group on timeout or interruption and bounds reports/stdout/stderr to 8 MiB and each tool to 2,000 findings. Semgrep runs one scanner job with a 256 MiB scanner memory setting; the existing worker container supplies additional memory/PID bounds. The job has a soft 550-second and hard 600-second limit; stale recovery remains 15 minutes. A hard worker kill cannot reliably execute Python cleanup; orphan workspace cleanup and stronger scanner sandboxing remain later hardening work.

## Provenance and state

Every analysis retains its own code index and per-tool summaries in ScanJob.result_summary. Repository.intelligence is a convenience view of the latest index. Findings link to the repository and analysis job, and retain the archive hash, source hash, scanner/rule-pack version and rule-pack hash. ZIP provenance is a content hash, not a Git commit. Exact duplicate tool/rule/path/line/column findings are collapsed within a run only. Historical runs remain independent; cross-tool correlation is future work.

States are QUEUED -> RUNNING -> COMPLETED / PARTIALLY_COMPLETED / FAILED. Per-tool states are RUNNING -> COMPLETED / PARTIAL / FAILED. Semgrep errors or zero scanned files cannot produce full success. One failing scanner allows the other's genuine findings to be published with partial status. Both failing scanners fail the job while retaining successful source inspection. Authorization/provenance failure prevents publication. Findings and terminal job state commit together. Stale analysis recovery changes analysis status only; it preserves READY ingestion and source data.

## Source viewer and privacy

Source is fetched only for an indexed path in an owned analysis, with matching source checksum, after successful Gitleaks completion. Credential-like filenames and files containing Gitleaks findings are withheld entirely. Other source is a bounded, redacted window around a requested line. React escapes the code; no repository HTML is rendered. Regex redaction is best effort, and a successful secret scan does not guarantee every possible secret format is recognized. Do not upload production credentials.

This milestone supplies controlled subprocess execution and separate workspaces, not a hardened OS sandbox. Scanner binaries share the worker container's account and mounts. Parser exploits, filesystem access and egress containment require an unprivileged dedicated scanner sandbox before accepting hostile public repositories. No build/test scripts are executed here.

## Rule coverage

ASE's local Semgrep pack has four review/detection rules: Python shell execution, request-to-SQL taint, input-to-eval/exec taint, and JavaScript/TypeScript eval review. Shell/eval review patterns alone do not prove exploitability. There are no claims of universal SAST coverage or automatic IDOR detection. Gitleaks uses real installed default secret rules. Absence of findings is not proof of security.

## Validation

The local delivery environment ran 33 standard-library unit tests, Python compilation and focused strict TypeScript checks. It lacks Docker, PostgreSQL, Semgrep and Gitleaks, so full migrations, database integration, complete frontend build and real tool execution must be verified in the user's Docker environment. Parser fixtures test normalization only; they are never exposed as executed scan results.

Run the mandatory smoke command in UPDATE_INSTRUCTIONS.md. It fails when either real binary is missing or fails to detect seeded issues. The PostgreSQL acceptance test also invokes both real scanners and verifies stored findings, source paths, secret withholding and provenance; it skips if a binary is missing, which is not successful scanner acceptance.

Full frontend build was also attempted in the delivery environment: `npm run build` was blocked by permissions on the extracted TypeScript launcher. Running the launcher directly (`node node_modules/typescript/bin/tsc -b`) confirmed missing local packages (`lucide-react`, `framer-motion`, `@tailwindcss/vite`). This incomplete extracted dependency tree is not evidence of a successful full build; use the Docker build command above for verification. The new repository pages and API client passed their separate strict TypeScript check.
