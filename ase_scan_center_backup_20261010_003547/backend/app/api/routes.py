from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
import uuid
from datetime import datetime

from app.config.database import get_db
from app.models.project import Project, Target
from app.models.finding import Finding
from app.models.user import User
from app.schemas import core as schemas
from app.api.auth import get_current_user

router = APIRouter()

# --- Projects ---
@router.post("/projects", response_model=schemas.ProjectResponse)
def create_project(project: schemas.ProjectCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_project = Project(name=project.name, description=project.description, owner_id=current_user.id)
    db.add(db_project)
    db.commit()
    db.refresh(db_project)
    return db_project

@router.get("/projects", response_model=List[schemas.ProjectResponse])
def get_projects(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Project).filter(Project.owner_id == current_user.id).all()

# --- Targets ---
@router.post("/targets", response_model=schemas.TargetResponse)
def create_target(target: schemas.TargetCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    project = db.query(Project).filter(Project.id == target.project_id, Project.owner_id == current_user.id).first()
    if not project:
        raise HTTPException(status_code=403, detail="Not authorized to add targets to this project.")
        
    db_target = Target(**target.model_dump())
    db.add(db_target)
    db.commit()
    db.refresh(db_target)
    return db_target

@router.get("/targets", response_model=List[schemas.TargetResponse])
def get_targets(project_id: uuid.UUID = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(Target).join(Project).filter(Project.owner_id == current_user.id)
    if project_id:
        query = query.filter(Target.project_id == project_id)
    return query.all()

from app.utils.validators import validate_scope_syntax, is_url_in_scope

@router.post("/targets/{target_id}/approve")
def approve_target(target_id: uuid.UUID, scope: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    target = db.query(Target).join(Project).filter(Target.id == target_id, Project.owner_id == current_user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found or unauthorized")
        
    try:
        valid_scope = validate_scope_syntax(scope)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
        
    target.authorization_status = "APPROVED"
    target.explicit_scope = valid_scope
    target.approved_by = current_user.id
    target.approval_timestamp = datetime.utcnow()
    target.is_active = True
    db.commit()
    return {"message": "Target approved", "scope": valid_scope}

@router.post("/targets/{target_id}/revoke")
def revoke_target(target_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    target = db.query(Target).join(Project).filter(Target.id == target_id, Project.owner_id == current_user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found or unauthorized")
        
    target.authorization_status = "REJECTED"
    target.is_active = False
    db.commit()
    return {"message": "Target authorization revoked"}

# --- Findings ---
@router.get("/findings", response_model=List[schemas.FindingResponse])
def get_findings(project_id: uuid.UUID = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(Finding).join(Project).filter(Project.owner_id == current_user.id)
    if project_id:
        query = query.filter(Finding.project_id == project_id)
    return query.all()

from app.workers.scan_jobs import run_security_scan
from app.workers.diagnostic_jobs import run_diagnostic_job
from app.workers.remediation_jobs import generate_ai_fix
from app.models.project import ScanJob

# --- Jobs / Scans ---
@router.post("/targets/{target_id}/jobs", response_model=schemas.JobSubmitResponse)
def submit_job(target_id: uuid.UUID, job_type: str = "SECURITY_SCAN", db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Enforce ownership, APPROVED status, active status before dispatching
    target = db.query(Target).join(Project).filter(Target.id == target_id, Project.owner_id == current_user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found or unauthorized")
        
    if target.authorization_status != "APPROVED" or not target.is_active:
        raise HTTPException(status_code=403, detail="Target is not approved or is inactive. Scanning is blocked.")
        
    if not target.explicit_scope or not is_url_in_scope(target.url, target.explicit_scope):
        raise HTTPException(status_code=403, detail="Target URL is outside of the approved explicit scope.")
        
    if job_type not in ("SECURITY_SCAN", "DIAGNOSTIC"):
        raise HTTPException(status_code=400, detail="Invalid job type")
        
    # Commit the job record before dispatching
    new_job = ScanJob(
        target_id=target.id,
        requesting_user_id=current_user.id,
        job_type=job_type,
        status="QUEUED",
        current_stage="INITIALIZING",
        message="Job queued for processing."
    )
    db.add(new_job)
    db.commit()
    db.refresh(new_job)
    
    # Handle broker submission explicitly
    try:
        if job_type == "SECURITY_SCAN":
            task = run_security_scan.delay(str(new_job.id))
        else:
            task = run_diagnostic_job.delay(str(new_job.id))
            
        new_job.celery_task_id = task.id
        db.commit()
    except Exception as e:
        # Only queued jobs can fail here; claimed/terminal jobs are never overwritten.
        db.rollback() # Rollback the commit of the celery_task_id attempt
        db.query(ScanJob).filter(ScanJob.id == new_job.id, ScanJob.status.in_(["QUEUED", "INITIALIZING"])).update({
            "status": "FAILED", "current_stage": "BROKER_ERROR",
            "message": "Failed to submit job to the message broker.",
            "failure_code": "BROKER_SUBMISSION_FAILED",
            "failure_message": "Message broker submission failed or was rejected.",
            "finished_at": datetime.utcnow(),
        }, synchronize_session=False)
        db.commit()
        raise HTTPException(status_code=503, detail="Failed to dispatch job to background workers.")
    
    return {"message": "Job dispatched to background workers.", "job_id": new_job.id}

@router.get("/jobs", response_model=List[schemas.JobResponse])
def get_jobs(target_id: uuid.UUID = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = db.query(ScanJob).join(Target).join(Project).filter(Project.owner_id == current_user.id)
    if target_id:
        query = query.filter(ScanJob.target_id == target_id)
    # Order by newest
    query = query.order_by(ScanJob.created_at.desc())
    return query.all()

@router.get("/jobs/{job_id}", response_model=schemas.JobResponse)
def get_job(job_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    job = db.query(ScanJob).join(Target).join(Project).filter(ScanJob.id == job_id, Project.owner_id == current_user.id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found or unauthorized")
    return job

# --- AI Remediation ---
@router.post("/findings/{finding_id}/remediate")
def trigger_ai_remediation(finding_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    finding = db.query(Finding).join(Project).filter(Finding.id == finding_id, Project.owner_id == current_user.id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found or unauthorized")
        
    task = generate_ai_fix.delay(str(finding_id))
    
    return {"message": "AI remediation job dispatched.", "task_id": task.id, "finding_id": finding_id}

# --- Analytics & Metrics ---
@router.get("/metrics")
def get_metrics(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    projects_query = db.query(Project.id).filter(Project.owner_id == current_user.id)
    
    total_projects = projects_query.count()
    total_targets = db.query(Target).filter(Target.project_id.in_(projects_query)).count()
    total_findings = db.query(Finding).filter(Finding.project_id.in_(projects_query)).count()
    
    findings_query = db.query(Finding).filter(Finding.project_id.in_(projects_query))
    
    critical = findings_query.filter(Finding.severity == "CRITICAL").count()
    high = findings_query.filter(Finding.severity == "HIGH").count()
    medium = findings_query.filter(Finding.severity == "MEDIUM").count()
    low = findings_query.filter(Finding.severity == "LOW").count()
    info = findings_query.filter(Finding.severity == "INFO").count()
    
    open_findings = findings_query.filter(Finding.status == "OPEN").count()
    fixed_findings = findings_query.filter(Finding.status.in_(["FIXED", "VERIFIED_FIXED"])).count()
    
    return {
        "overview": {
            "projects": total_projects,
            "targets": total_targets,
            "findings": total_findings
        },
        "severity": {
            "CRITICAL": critical,
            "HIGH": high,
            "MEDIUM": medium,
            "LOW": low,
            "INFO": info
        },
        "status": {
            "OPEN": open_findings,
            "FIXED": fixed_findings
        }
    }
