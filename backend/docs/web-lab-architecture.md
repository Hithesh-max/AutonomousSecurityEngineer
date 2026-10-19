# Controlled web assessment

The authenticated API creates a WEB_SCAN row before Celery dispatch. The worker atomically claims it, verifies project ownership, target approval and scope, and restricts execution to the bundled lab origin and pinned IP. Authorization is rechecked during subprocess execution and before ZAP API operations. Findings and terminal job status commit together; late workers cannot publish results for an already terminal job.

Nmap uses a fixed argv with TCP connect scanning, no DNS, a single port, bounded retries and timeout. STANDARD adds light version detection. Execution uses the shared controlled process runner, no shell, bounded output and a minimal environment. XML is validated before port metadata is stored.

The ZAP adapter uses authenticated API requests to a fixed internal address, with proxy inheritance and redirects disabled. An exclusive Redis lease protects session creation, context setup, protected mode, crawling, passive processing and optional active testing. The context permits only the lab origin. Active testing enables only rules 40012 and 40018 with LOW attack strength. Timeouts, malformed responses, missing rules, lease loss and unconfirmed stopping are explicit failures.

The internal Docker network contains the worker, ZAP and the vulnerable lab. Only the worker additionally joins the existing application network to communicate with Redis and PostgreSQL. The lab and ZAP have no host port mappings, Docker socket or source mounts. The lab runs without root, with a read-only filesystem and resource limits. This network boundary is part of the design and must not be removed to support an arbitrary target.

ScanJob.result_summary records requested configuration, authorization identity/scope/time, stage events, tool versions, coverage, duration, discovered endpoints and ports. ZAP findings use the existing Finding model, with per-scan deterministic fingerprints and bounded redacted evidence. Deduplication is limited to identical ZAP observations; it does not infer cross-tool root causes. This update uses existing database columns and adds no migration.

The UI reads persisted state and polls active jobs. It presents tool failure separately from findings and exposes explicit consent for active testing. The command-line smoke test runs real adapters under the same global ZAP lease, but deliberately does not pretend to be a user-owned database assessment.

## References

- ZAP API: https://www.zaproxy.org/docs/api/
- ZAP Docker daemon setup: https://www.zaproxy.org/docs/docker/about/
- ZAP alert catalog: https://www.zaproxy.org/docs/alerts/
- Nmap TCP connect scanning: https://nmap.org/book/scan-methods-connect-scan.html

## Acceptance evidence still required

Capture a successful local Docker start, full backend tests/frontend build, real scanner smoke output, a persisted passive assessment, an explicitly authorized active assessment, and an authorization-denial example. Record tool versions and whether seeded issues were actually found. Two isolated container roles provide a simulation for the classroom demonstration; security-goal and efficiency evaluation still need a separate measured report.
