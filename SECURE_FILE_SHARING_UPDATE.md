# ASE encrypted corrected-project sharing

This update adds an end-to-end encrypted share link beside **Download corrected project ZIP**. It shares the corrected ZIP produced by ASE's existing approved-patch export; it does not share unapproved proposals.

## What happens

1. The signed-in sender asks ASE for the corrected ZIP.
2. The sender's browser packages the ZIP name and bytes and encrypts them with AES-256-GCM using the browser Web Crypto API.
3. Only ciphertext is uploaded. ASE stores it in a private persistent volume and records an opaque share ID, owner, expiry, download count, and a hash of a reader token derived in the browser. The decryption key stays in the URL fragment after `#`; it is never sent to ASE.
4. A recipient opens the link without needing an ASE account, selects **Decrypt and download file**, and the browser downloads and decrypts the ZIP locally.
5. Links stop working after 24 hours or five downloads by default. Celery Beat removes expired ciphertext hourly; expired links are rejected immediately even before cleanup. The owner can revoke a link with the authenticated API.

Anyone who gets the complete link can download and decrypt the file. Send it only to the intended recipient. The backend caps encrypted uploads at 50 MiB by default. Do not use an insecure HTTP deployment for remote recipients; Web Crypto requires a secure browser context (HTTPS, or localhost during development).

## Apply the update

1. Extract this update ZIP into the ASE project folder, preserving its folder structure and allowing the listed files to merge/overwrite. Do not replace `.env` or database files.
2. Back up the ASE database. From the project folder, run the migration command matching how you start ASE:
   - If you start with the isolated lab overlay: `docker compose -f docker-compose.yml -f docker-compose.lab.yml exec backend alembic upgrade head`
   - If you start only the base stack: `docker compose exec backend alembic upgrade head`
   This additive migration creates the `secure_shares` table.
3. Restart the same stack, adding `--build` and the services `backend worker frontend` to its usual `up -d` command. For the lab-overlay stack: `docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d --build backend worker frontend`.
4. In **Vulnerability Findings → Whole-project remediation**, approve the proposals you intend to export. Click **Create encrypted share link** next to the corrected ZIP download. The link is copied automatically and also appears in the page for manual copying.

The Docker Compose update mounts one named volume into both backend and worker so uploaded ciphertext and scheduled expiry cleanup use the same storage. For a hosted deployment, configure equivalent persistent storage shared by the API and worker. The implementation is a small ASE feature modeled on the behavior described in Wormhole's security design; it is not Wormhole's code and has not had an independent cryptographic audit.
