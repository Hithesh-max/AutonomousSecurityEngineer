import logging
from datetime import datetime
from app.workers.celery_app import celery
from app.config.database import SessionLocal
from app.models.project import ScanJob, Target
from sqlalchemy import text

logger = logging.getLogger(__name__)

@celery.task(bind=True, name="run_diagnostic_job")
def run_diagnostic_job(self, job_id: str):
    logger.info(f"Starting diagnostic job: {job_id}")
    db = SessionLocal()
    try:
        # Atomic claim to prevent concurrent duplicate delivery execution
        updated_count = db.query(ScanJob).filter(
            ScanJob.id == job_id,
            ScanJob.job_type == "DIAGNOSTIC",
            ScanJob.status.in_(["QUEUED", "INITIALIZING"])
        ).update({
            "status": "RUNNING",
            "current_stage": "DIAGNOSTIC_CHECK",
            "message": "Running diagnostic database connectivity check.",
            "started_at": datetime.utcnow()
        }, synchronize_session=False)
        db.commit()
        
        if updated_count == 0:
            logger.warning(f"Job {job_id} could not be claimed. Already running/completed or missing.")
            return "Aborted: Job already claimed or missing."
            
        # Fetch Job
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not job:
            raise ValueError("Job not found after claim.")
            
        # Double-check Authorization boundary
        if job.target_id:
            target = db.query(Target).filter(Target.id == job.target_id).first()
            if not target:
                raise PermissionError("Target not found. Aborting job.")
            if target.authorization_status != "APPROVED" or not target.is_active:
                raise PermissionError("Authorization revoked or target inactive. Aborting job.")
            
            # Check scope
            from app.utils.validators import is_url_in_scope
            if not target.explicit_scope or not is_url_in_scope(target.url, target.explicit_scope):
                raise PermissionError("Target URL is outside of the approved explicit scope. Aborting job.")
                
            # Verify requesting user is the project owner (or has access)
            project = target.project
            if not project or project.owner_id != job.requesting_user_id:
                raise PermissionError("Project ownership mismatch. Aborting job.")
                
        # Real diagnostic task: check DB connectivity
        try:
            res = db.execute(text("SELECT 1")).scalar()
            if res != 1:
                raise RuntimeError("Database connectivity check returned unexpected result.")
        except Exception as e:
            raise RuntimeError(f"Database connectivity check failed.") # Do not expose raw str(e) containing credentials
            
        # Mark as COMPLETED atomically to prevent late workers from overwriting recovered states
        updated = db.query(ScanJob).filter(
            ScanJob.id == job_id, 
            ScanJob.status == "RUNNING"
        ).update({
            "status": "COMPLETED",
            "current_stage": "COMPLETED",
            "message": "The diagnostic succeeded.",
            "result_summary": {"diagnostic": "Success", "database_connectivity": "OK"},
            "finished_at": datetime.utcnow()
        }, synchronize_session=False)
        db.commit()
        
        if updated == 0:
            logger.warning(f"Job {job_id} finished diagnostic but was already marked terminal (e.g. by recovery).")
            return "Aborted: Late worker success ignored."
            
        logger.info(f"Diagnostic job {job_id} completed successfully.")
        return "Success: Diagnostic completed."
        
    except Exception as e:
        logger.error(f"Job {job_id} failed: {type(e).__name__}")
        db.rollback()
        # Attempt to persist sanitized failure state
        try:
            if isinstance(e, PermissionError):
                code = "AUTHORIZATION_ERROR"
                message = "Target authorization failed or was revoked."
            else:
                code = "WORKER_INTERNAL_ERROR"
                message = "An unexpected error occurred. Raw details are hidden for security."
            db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.status == "RUNNING").update({
                "status": "FAILED", "current_stage": "ERROR",
                "message": "Job encountered a fatal error during execution.",
                "failure_code": code, "failure_message": message,
                "finished_at": datetime.utcnow(),
            }, synchronize_session=False)
            db.commit()
        except Exception as fallback_e:
            logger.critical(f"Failed to persist job failure state. Error omitted.")
            
        raise  # Explicitly fail the Celery task
    finally:
        db.close()
