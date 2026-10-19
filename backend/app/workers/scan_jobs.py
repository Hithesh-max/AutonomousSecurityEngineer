import json
import subprocess
import uuid
import os
from typing import Dict, List, Any
import logging

from app.workers.celery_app import celery
from app.config.database import SessionLocal
from app.models.project import Target
from app.models.finding import Finding
from app.scanners.semgrep import SemgrepScanner
from app.scanners.trivy import TrivyScanner
from app.scanners.gitleaks import GitleaksScanner

from datetime import datetime
from app.models.project import ScanJob

logger = logging.getLogger(__name__)

@celery.task(bind=True, name="run_security_scan")
def run_security_scan(self, job_id: str):
    logger.info(f"Starting security scan job: {job_id}")
    db = SessionLocal()
    try:
        # Atomic claim
        updated_count = db.query(ScanJob).filter(
            ScanJob.id == job_id,
            ScanJob.job_type == "SECURITY_SCAN",
            ScanJob.status.in_(["QUEUED", "INITIALIZING"])
        ).update({
            "status": "RUNNING",
            "current_stage": "AUTHORIZATION_CHECK",
            "message": "Verifying target authorization.",
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
            
        # 1. Fetch Target
        target = db.query(Target).filter(Target.id == job.target_id).first()
        if not target:
            raise PermissionError("Target not found. Aborting scan.")
            
        # 1.a. Double-check Authorization boundary inside worker
        if target.authorization_status != "APPROVED" or not target.is_active:
            raise PermissionError("Authorization revoked or target inactive. Aborting scan.")
            
        from app.utils.validators import is_url_in_scope
        if not target.explicit_scope or not is_url_in_scope(target.url, target.explicit_scope):
            raise PermissionError("Target URL is outside of the approved explicit scope. Aborting scan.")
        
        # Verify requesting user is the project owner (or has access)
        project = target.project
        if not project or project.owner_id != job.requesting_user_id:
            raise PermissionError("Project ownership mismatch. Aborting job.")
            
        project_id = target.project_id
        repo_url = target.repo_url
        
        job.current_stage = "SCANNING"
        job.message = "Initializing security scanners."
        db.commit()
        
        # 2. Initialize Scanners
        findings_to_save = []
        
        # 2.a. File System Scanners (Semgrep, Trivy, Gitleaks)
        has_local_workspace = repo_url and os.path.isdir(repo_url)
        
        if not has_local_workspace:
            raise ValueError("Repository scanning skipped: Missing repository workspace for target.")
            
        if repo_url:
            raise PermissionError("Repository scanning is currently blocked pending a server-managed workspace registry.")
            
        # 3. Save Findings to Database (skipped since scanners blocked)
        
        job.status = "COMPLETED"
        job.current_stage = "COMPLETED"
        job.message = "Security scan completed successfully."
        job.finished_at = datetime.utcnow()
        db.commit()
        
        return f"Success: Found {len(findings_to_save)} vulnerabilities."
        
    except Exception as e:
        logger.error(f"Job failed: {type(e).__name__}")
        db.rollback()
        try:
            if isinstance(e, PermissionError):
                code = "AUTHORIZATION_ERROR"
                message = "Target authorization failed or was revoked."
            elif isinstance(e, ValueError) and "Repository scanning skipped" in str(e):
                code = "WORKSPACE_ERROR"
                message = "Repository scanning skipped: Missing repository workspace for target."
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
