# ASE Vulnerability Training Target (local only)

This is a deliberately vulnerable, disposable Flask target for practicing ASE scans. It contains intentionally unsafe SQL construction, reflected HTML, `eval`, shell command execution, a fake nonfunctional API-key string, and a cookie with weak flags. Data is synthetic and stored inside the container's temporary filesystem.

**Do not deploy this publicly, connect it to real data, or enter real secrets.** The app binds to `127.0.0.1:8082` on your Windows host. Its container is non-root, read-only except for temporary `/tmp`, drops Linux capabilities, and has memory/process limits. Those controls reduce lab impact; they do not make the vulnerable app safe for public exposure.

## Start it beside ASE on Windows PowerShell

1. Extract this ZIP into your ASE project folder, so the folder is `D:\antigrav\AutonomousSecurityEngineer\ase-vuln-demo`.
2. Confirm Docker has ASE's lab network:

   ```powershell
   docker network ls
   ```

   The default configured name is `autonomoussecurityengineer_ase_lab_network`. If your network has a different name, set it for this PowerShell window before starting:

   ```powershell
   $env:ASE_DOCKER_NETWORK = "YOUR_ACTUAL_NETWORK_NAME"
   ```

3. From the ASE project root, start only this target:

   ```powershell
   docker compose -f docker-compose.yml -f docker-compose.lab.yml -f .\ase-vuln-demo\docker-compose.target.yml up -d --build ase-vuln-lab
   ```

4. Check the browser URL: `http://127.0.0.1:8082/health`. In ASE's web scan target, use **`http://ase-vuln-lab:8080`** so the scanner container reaches it over the shared Docker network. Do not use `localhost` as the scanner URL; inside a container, localhost points back to that scanner container.

5. For source-code scanning, upload/import `ase-vuln-demo\app.py` and `requirements.txt` as a separate repository. For DAST, register/approve the target URL above, then run the scan. These are separate scan types.

## Harmless check URLs

- `/search?q=Welcome`
- `/echo?text=training`
- `/calculate?expression=1%2B1`
- `/command?cmd=echo%20hello`
- `/login`

Do not test destructive shell commands. Do not expose port 8082 on a public interface.

## Stop only this lab target

Run from the ASE project root:

```powershell
docker compose -f docker-compose.yml -f docker-compose.lab.yml -f .\ase-vuln-demo\docker-compose.target.yml stop ase-vuln-lab
docker compose -f docker-compose.yml -f docker-compose.lab.yml -f .\ase-vuln-demo\docker-compose.target.yml rm -f ase-vuln-lab
```

## What ASE may and may not fix

ASE should produce findings based on the scanners actually enabled and their rules. ZAP may report reflected XSS and response-header/cookie issues; Semgrep may report unsafe `eval`, shell execution, and SQL construction; Gitleaks may or may not classify the clearly fake key. Scanner coverage depends on your ASE configuration.

This target lets you test the end-to-end remediation workflow. It does **not** guarantee every finding will be eligible for automatic remediation or that an exported ZIP is safe. Secret rotation cannot be performed by a code patch. Review each diff, run a fresh scan against the corrected export, and treat any `INCONCLUSIVE`, `UNVERIFIED`, or `UNRESOLVED` status as not fixed. Never deploy this training target.
