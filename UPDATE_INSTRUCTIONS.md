# ASE ZIP-ingestion update — apply to your existing project

This is a PATCH: copy its backend/, frontend/, docker-compose.yml, docs/, and other included files into your current project. Do not replace the whole project folder. Existing files that are not in this update must remain, including your .env and database volume. The original uploaded ZIP remains unchanged.

## 1. Stop application processes before copying

In PowerShell, inside D:\antigrav\AutonomousSecurityEngineer:

```powershell
docker compose stop backend worker frontend
```

Keep a backup of your source folder. This update does not delete/reset your database, users, projects, findings, or targets. It contains no .env file or real credentials. Keep your current .env; do not overwrite it with .env.example.

## 2. Copy the update

Extract ASE_ZIP_INGESTION_UPDATE.zip into a temporary folder. Copy its contents into D:\antigrav\AutonomousSecurityEngineer, choosing Replace for matching files. Merge the backend/frontend folders; do not delete their existing contents. After copying, the new file must be at backend\app\repositories\archive.py, not inside an extra nested update folder.

No package dependencies or Dockerfiles changed, so an image rebuild is unnecessary for this patch. Existing containers use source bind mounts. If your local Dockerfiles differ from those supplied, rebuild as your local setup requires.

## 3. Migrate, start, test

Run these commands in your existing project folder, one at a time:

```powershell
docker compose up -d db redis
docker compose run --rm backend alembic upgrade head
docker compose up -d
docker compose exec backend sh -c "PYTHONPATH=/app pytest"
docker compose exec frontend npm run build
```

The migration should reach d7a104c892ab. Do not use `docker compose down -v`; it deletes volumes. If any command fails, stop and send its error with secrets removed. Do not manually stamp or reset the database for this update.

Optional extraction-only test command (no test DB required):

```powershell
docker compose exec backend sh -c "PYTHONPATH=/app python -m unittest discover -s tests/unit -v"
```

## 4. Try the real upload

1. Open http://localhost:5173 and sign in with your current working account.
2. Click the new Repositories sidebar item.
3. Choose ASE Lab and its APPROVED ASE Lab Target.
4. Enter a repository name, such as Ingestion Test.
5. Select samples\ase-ingestion-sample.zip from this update. It is a small, harmless source archive for testing extraction only.
6. Tick the source-authorization confirmation and click Upload and ingest ZIP.
7. Expect Repository ingestion READY, Analysis NOT_STARTED, and the job COMPLETED. The sample contains three files.
8. Refresh; the repository and job should remain visible. You can also view the REPOSITORY_INGESTION job in Scan Center.

No security scan has run. Do not expect vulnerability findings from this sample or use the SCAN button yet.

If the upload fails or stays queued:

```powershell
docker compose logs --tail=80 worker
docker compose logs --tail=80 backend
```

## What's included / what's verified

See docs\zip_ingestion.md for architecture, changed behavior, security limits, tests, and remaining work. The package contains changed/new files only, a per-file SHA-256 manifest, and a sample archive. Twenty-two extraction tests and strict TypeScript checks of the new page/API passed here. Docker/database/Celery integration and the complete frontend build still require the local commands above; they have not been claimed as passing.
