import logging
import shutil
from datetime import datetime, timezone
from uuid import UUID
from celery.exceptions import SoftTimeLimitExceeded
from app.workers.celery_app import celery
from app.config.database import SessionLocal
from app.config.settings import settings
from app.models.project import ScanJob
from app.models.repository import Repository
from app.repositories.access import require_authorized_target
from app.repositories.archive import ArchiveLimits, ArchiveRejected, extract_zip
from app.repositories.storage import repository_directory

logger = logging.getLogger(__name__)


@celery.task(bind=True, name='ingest_zip_repository', soft_time_limit=110, time_limit=120)
def ingest_zip_repository(self, job_id: str):
    job_id = UUID(job_id)
    db = SessionLocal()
    directory = None
    published = False
    try:
        claimed = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.job_type == 'REPOSITORY_INGESTION',
                                         ScanJob.status == 'QUEUED').update({
            'status': 'RUNNING', 'current_stage': 'VALIDATING',
            'message': 'Validating ZIP entries and resource limits.', 'started_at': datetime.now(timezone.utc),
        }, synchronize_session=False)
        db.commit()
        if not claimed:
            return 'Aborted: Job already claimed, terminal, or missing.'
        job = db.query(ScanJob).filter(ScanJob.id == job_id).one()
        repository = db.query(Repository).filter(Repository.id == job.repository_id).one()
        target = require_authorized_target(db, job.target_id, job.requesting_user_id)
        if repository.target_id != target.id or repository.project_id != target.project_id or repository.uploaded_by != job.requesting_user_id:
            raise PermissionError('Repository provenance does not match the job.')
        repository.ingestion_status = 'RUNNING'
        db.commit()
        directory = repository_directory(settings.SCAN_WORKSPACE_ROOT, repository.id)
        archive = directory / 'upload.zip'
        moved = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.status == 'RUNNING').update({
            'current_stage': 'EXTRACTING', 'message': 'Safely extracting ZIP into a private workspace.',
        }, synchronize_session=False)
        db.commit()
        if not moved:
            return 'Aborted: Job was marked terminal.'
        result = extract_zip(archive, directory, ArchiveLimits(
            upload_bytes=settings.ZIP_MAX_UPLOAD_BYTES, expanded_bytes=settings.ZIP_MAX_EXPANDED_BYTES,
            file_bytes=settings.ZIP_MAX_FILE_BYTES, entries=settings.ZIP_MAX_ENTRIES,
            compression_ratio=settings.ZIP_MAX_COMPRESSION_RATIO,
        ))
        published = True
        if result.archive_sha256 != repository.archive_sha256:
            raise ArchiveRejected('PROVENANCE_ERROR', 'Managed archive checksum changed during ingestion.')
        require_authorized_target(db, job.target_id, job.requesting_user_id)
        # Completion and READY metadata are one transaction; recovery cannot overwrite it.
        changed = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.status == 'RUNNING').update({
            'status': 'COMPLETED', 'current_stage': 'COMPLETED',
            'message': 'ZIP ingestion completed. Security analysis has not started.',
            'result_summary': {'repository_id': str(repository.id), 'file_count': result.file_count,
                               'expanded_bytes': result.expanded_bytes, 'archive_sha256': result.archive_sha256},
            'finished_at': datetime.now(timezone.utc),
        }, synchronize_session=False)
        if not changed:
            db.rollback()
            shutil.rmtree(directory / 'source')
            published = False
            return 'Aborted: Late worker completion ignored.'
        db.query(Repository).filter(Repository.id == repository.id).update({
            'ingestion_status': 'READY', 'file_count': result.file_count,
            'extracted_bytes': result.expanded_bytes, 'ingested_at': datetime.now(timezone.utc),
        }, synchronize_session=False)
        db.commit()
        logger.info('repository_ingestion_completed', extra={'job_id': str(job_id), 'repository_id': str(repository.id)})
        return 'Success: ZIP ingested; security analysis not started.'
    except Exception as error:
        db.rollback()
        if isinstance(error, ArchiveRejected):
            code, message = error.code, error.message
        elif isinstance(error, PermissionError):
            code, message = 'AUTHORIZATION_ERROR', 'Repository access or target authorization was revoked.'
        elif isinstance(error, SoftTimeLimitExceeded):
            code, message = 'INGESTION_TIMEOUT', 'ZIP ingestion exceeded its time limit.'
        else:
            code, message = 'INGESTION_ERROR', 'Repository ingestion failed. Check storage and worker availability.'
        logger.error('repository_ingestion_failed', extra={'job_id': str(job_id), 'failure_code': code})
        try:
            job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
            changed = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.status == 'RUNNING').update({
                'status': 'FAILED', 'current_stage': 'ERROR', 'message': message,
                'failure_code': code, 'failure_message': message, 'finished_at': datetime.now(timezone.utc),
            }, synchronize_session=False)
            if changed and job and job.repository_id:
                db.query(Repository).filter(Repository.id == job.repository_id).update({
                    'ingestion_status': 'FAILED', 'failure_code': code, 'failure_message': message,
                }, synchronize_session=False)
            db.commit()
            if changed and published and directory is not None:
                shutil.rmtree(directory / 'source')
        except Exception:
            db.rollback()
            logger.critical('repository_failure_persistence_failed', extra={'job_id': str(job_id)})
        # Celery receives sanitized failure, not filenames or repository contents.
        raise RuntimeError(message) from None
    finally:
        db.close()
