# ASE bundled Web Lab source snippets

Copy the four files from this patch into the **existing** `D:\antigrav\AutonomousSecurityEngineer` directory, preserving their paths. Do not copy the `ase_review` directory itself. Keep your existing `.env`.

Changed files:
- `backend/app/api/web_scans.py` — authenticated, read-only lab source endpoint, checks ownership, ZAP rule, route and parameter.
- `frontend/src/pages/WebLab.tsx` — highlighted snippet inside expanded XSS/SQLi finding.
- `frontend/src/api.ts` — typed API call.
- `docker-compose.lab.yml` — mounts **only** `lab/app.py` read-only into the backend.

IMPORTANT: The bundled Compose file in this patch comes from your uploaded ZIP. If your local `docker-compose.lab.yml` has newer working ZAP allowlist settings, **do not overwrite it**. Instead add just these lines under `services.backend`, at the same indentation as `environment`:

```yaml
    volumes:
      - ./lab/app.py:/opt/ase-lab-source/app.py:ro
```

Then run from project root:

```powershell
docker compose -f docker-compose.yml -f docker-compose.lab.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d --no-deps --force-recreate backend
```

Refresh Web Lab and expand a HIGH XSS or SQL Injection finding. Snippet appears below evidence. No new scan or database migration is needed.

Scope: only two ZAP rules (40012 and 40018) and the corresponding bundled lab endpoints. Other findings correctly have no code mapping. Existing finding records are unchanged. If the lab source changes, the backend rejects stale mappings.
