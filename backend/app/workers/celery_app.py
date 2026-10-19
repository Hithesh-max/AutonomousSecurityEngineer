from celery import Celery
from celery.schedules import crontab
from app.config.settings import settings
from app.models import User, Project, Target, ScanJob, Finding, Repository

celery = Celery(
    "ase_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.workers.scan_jobs", 
        "app.workers.remediation_jobs",
        "app.workers.diagnostic_jobs",
        "app.workers.recovery_jobs",
        "app.workers.ingestion_jobs",
        "app.workers.analysis_jobs",
        "app.workers.web_jobs",
        "app.workers.remediation_batch",
        "app.workers.secure_share_cleanup",
    ]
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    beat_schedule={
        "recover-stale-jobs": {
            "task": "recover_stale_jobs",
            "schedule": 60.0, # Run every minute
        },
        "expire-secure-shares": {
            "task": "expire_secure_shares",
            "schedule": 3600.0,
        },
    }
)
