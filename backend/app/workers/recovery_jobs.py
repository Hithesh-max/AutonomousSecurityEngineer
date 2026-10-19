import logging
from datetime import datetime, timedelta, timezone
from sqlalchemy import and_, or_, update
from app.workers.celery_app import celery
from app.config.database import SessionLocal
from app.models.project import ScanJob
from app.models.repository import Repository

logger = logging.getLogger(__name__)
TIMEOUT_MINUTES = 15


@celery.task(name='recover_stale_jobs')
def recover_stale_jobs():
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=TIMEOUT_MINUTES)
        # created_at is legacy naive UTC; started_at is timestamp with timezone.
        stale = or_(
            and_(ScanJob.status.in_(['QUEUED', 'INITIALIZING']), ScanJob.created_at < cutoff.replace(tzinfo=None)),
            and_(ScanJob.status == 'RUNNING', or_(
                ScanJob.started_at < cutoff,
                and_(ScanJob.started_at.is_(None), ScanJob.created_at < cutoff.replace(tzinfo=None)),
            )),
        )
        # One conditional UPDATE. PostgreSQL rechecks the predicate after lock waits.
        rows = db.execute(update(ScanJob).where(stale).values(
            status='FAILED', current_stage='ABORTED',
            message='Job timed out or its worker became unavailable.',
            failure_code='TIMEOUT_OR_WORKER_CRASH',
            failure_message='Completion could not be confirmed within the job timeout.',
            finished_at=now,
        ).returning(ScanJob.id, ScanJob.repository_id, ScanJob.job_type, ScanJob.result_summary)).all()
        repository_ids = [row.repository_id for row in rows if row.repository_id and row.job_type == 'REPOSITORY_INGESTION']
        if repository_ids:
            db.query(Repository).filter(Repository.id.in_(repository_ids), Repository.ingestion_status.in_(['QUEUED', 'RUNNING'])).update({
                'ingestion_status': 'FAILED', 'failure_code': 'TIMEOUT_OR_WORKER_CRASH',
                'failure_message': 'Ingestion timed out or its worker became unavailable.',
            }, synchronize_session=False)
        for row in rows:
            if row.job_type in {'REPOSITORY_ANALYSIS', 'WEB_SCAN'}:
                summary = row.result_summary or {}
                for tool in summary.get('tools', []):
                    if tool['status'] == 'RUNNING':
                        tool.update(status='FAILED', failure_code='TIMEOUT_OR_WORKER_CRASH', failure_message='Scanner completion could not be confirmed.')
                db.query(ScanJob).filter(ScanJob.id == row.id, ScanJob.status == 'FAILED').update({'result_summary': summary}, synchronize_session=False)
                if row.repository_id and row.job_type == 'REPOSITORY_ANALYSIS':
                    db.query(Repository).filter(Repository.id == row.repository_id, Repository.latest_analysis_job_id == row.id).update({'analysis_status': 'FAILED'}, synchronize_session=False)
        db.commit()
        logger.info('stale_job_recovery_completed', extra={'recovered_count': len(rows)})
        return len(rows)
    except Exception:
        db.rollback()
        logger.error('stale_job_recovery_failed')
        raise RuntimeError('Stale job recovery failed. Check database availability.') from None
    finally:
        db.close()
