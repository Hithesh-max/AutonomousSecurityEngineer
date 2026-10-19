import asyncio
import hashlib
import logging
import shutil
from datetime import datetime, timezone
from uuid import UUID, uuid4
import zipfile

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from starlette.requests import ClientDisconnect
from app.api.auth import get_current_user
from app.config.database import get_db
from app.config.settings import settings
from app.models.project import Project, Target, ScanJob
from app.models.repository import Repository
from app.models.user import User
from app.repositories.access import require_authorized_target
from app.repositories.storage import repository_directory
from app.schemas.repository import RepositoryResponse, RepositoryUploadResponse
from app.workers.ingestion_jobs import ingest_zip_repository

router = APIRouter()
logger = logging.getLogger(__name__)


def owned_target(db, target_id, user):
    target = db.query(Target).join(Project).filter(Target.id == target_id, Project.owner_id == user.id).first()
    if not target:
        raise HTTPException(404, detail='Target not found.')
    try:
        return require_authorized_target(db, target_id, user.id)
    except PermissionError:
        raise HTTPException(403, detail='Target must be active, approved, and inside its scope.') from None


def check_quota(db, user_id):
    count = db.query(Repository).join(Project).filter(Project.owner_id == user_id).count()
    if count >= settings.REPOSITORY_LIMIT_PER_USER:
        raise HTTPException(409, detail='Repository storage limit reached. Contact the local operator.')


@router.post('/targets/{target_id}/repositories/upload', status_code=202,
             response_model=RepositoryUploadResponse)
async def upload_repository(
    target_id: UUID,
    request: Request,
    name: str = Query(..., min_length=1, max_length=120),
    source_authorized: bool = Query(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Raw ZIP body, streamed to disk with a hard byte cap; not multipart buffering."""
    target = owned_target(db, target_id, current_user)
    name = name.strip()
    if not name or any(ord(c) < 32 for c in name):
        raise HTTPException(422, detail='Repository name must contain printable text.')
    if not source_authorized:
        raise HTTPException(403, detail='Confirm that you are authorized to upload this source code.')
    if request.headers.get('content-type', '').split(';')[0].strip().lower() not in ('application/zip', 'application/octet-stream'):
        raise HTTPException(415, detail='Upload a ZIP using application/zip.')
    content_length = request.headers.get('content-length')
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError:
            raise HTTPException(400, detail='Invalid Content-Length.') from None
        if declared < 0:
            raise HTTPException(400, detail='Invalid Content-Length.')
        if declared > settings.ZIP_MAX_UPLOAD_BYTES:
            raise HTTPException(413, detail='ZIP exceeds the upload-size limit.')
    check_quota(db, current_user.id)
    repository_id, job_id, task_id = uuid4(), uuid4(), str(uuid4())
    directory = None
    persisted = False
    try:
        directory = repository_directory(settings.SCAN_WORKSPACE_ROOT, repository_id, create=True)
        archive = directory / 'upload.zip'
        digest = hashlib.sha256()
        size = 0
        async with asyncio.timeout(settings.ZIP_UPLOAD_SECONDS):
            with archive.open('xb') as output:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > settings.ZIP_MAX_UPLOAD_BYTES:
                        raise HTTPException(413, detail='ZIP exceeds the upload-size limit.')
                    digest.update(chunk)
                    output.write(chunk)
        if not size or not zipfile.is_zipfile(archive):
            raise HTTPException(400, detail='Upload is not a valid ZIP archive.')
        # Serialize final admissions per owner to keep the repository count bounded.
        db.query(User).filter(User.id == current_user.id).with_for_update().one()
        check_quota(db, current_user.id)
        target = owned_target(db, target_id, current_user)  # Recheck after streaming.
        repository = Repository(
            id=repository_id, project_id=target.project_id, target_id=target_id,
            uploaded_by=current_user.id, name=name, source_type='ZIP',
            ingestion_status='QUEUED', analysis_status='NOT_STARTED',
            archive_sha256=digest.hexdigest(), upload_bytes=size,
            source_authorized_at=datetime.now(timezone.utc),
        )
        job = ScanJob(id=job_id, target_id=target_id, repository_id=repository_id,
                      requesting_user_id=current_user.id, celery_task_id=task_id,
                      job_type='REPOSITORY_INGESTION', scan_profile='INGESTION_ONLY',
                      status='QUEUED', current_stage='QUEUED', message='ZIP uploaded; ingestion queued.')
        db.add(repository)
        db.add(job)
        db.commit()
        persisted = True
    except (TimeoutError, ClientDisconnect):
        raise HTTPException(408, detail='ZIP upload timed out or was interrupted.') from None
    except HTTPException:
        raise
    except Exception:
        logger.error('repository_upload_failed', extra={'repository_id': str(repository_id)})
        raise HTTPException(503, detail='Unable to store the repository upload.') from None
    finally:
        if not persisted:
            db.rollback()
            if directory is not None:
                shutil.rmtree(directory)
    try:
        # Task ID is committed before dispatch, including ambiguous publication failures.
        ingest_zip_repository.apply_async(args=[str(job_id)], task_id=task_id)
    except Exception:
        db.rollback()
        changed = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.status == 'QUEUED').update({
            'status': 'FAILED', 'current_stage': 'BROKER_ERROR',
            'message': 'Unable to dispatch repository ingestion.',
            'failure_code': 'BROKER_SUBMISSION_FAILED',
            'failure_message': 'The background queue is unavailable.',
            'finished_at': datetime.now(timezone.utc),
        }, synchronize_session=False)
        if changed:
            db.query(Repository).filter(Repository.id == repository_id, Repository.ingestion_status == 'QUEUED').update({
                'ingestion_status': 'FAILED', 'failure_code': 'BROKER_SUBMISSION_FAILED',
                'failure_message': 'The background queue is unavailable.',
            }, synchronize_session=False)
        db.commit()
        raise HTTPException(503, detail={'message': 'Queue dispatch was not acknowledged. Check the repository status.',
                                       'repository_id': str(repository_id), 'job_id': str(job_id)}) from None
    logger.info('repository_ingestion_queued', extra={'repository_id': str(repository_id), 'job_id': str(job_id)})
    return {'repository_id': repository_id, 'job_id': job_id, 'message': 'ZIP ingestion queued. No security scan has run.'}


@router.get('/repositories', response_model=list[RepositoryResponse])
def list_repositories(project_id: UUID | None = None, db: Session = Depends(get_db),
                      current_user: User = Depends(get_current_user)):
    query = db.query(Repository).join(Project).filter(Project.owner_id == current_user.id)
    if project_id:
        query = query.filter(Repository.project_id == project_id)
    return query.order_by(Repository.created_at.desc()).all()


@router.get('/repositories/{repository_id}', response_model=RepositoryResponse)
def get_repository(repository_id: UUID, db: Session = Depends(get_db),
                   current_user: User = Depends(get_current_user)):
    repository = db.query(Repository).join(Project).filter(Repository.id == repository_id, Project.owner_id == current_user.id).first()
    if not repository:
        raise HTTPException(404, detail='Repository not found.')
    return repository


# Analysis APIs use only server-managed repository UUIDs, never client filesystem paths.
from pathlib import Path
from app.models.finding import Finding
from app.schemas.core import FindingResponse
from app.repositories.analysis import source_context
from app.workers.analysis_jobs import analyze_repository


def owned_repository(db, repository_id, user):
    repository = db.query(Repository).join(Project).filter(Repository.id == repository_id, Project.owner_id == user.id).first()
    if repository is None: raise HTTPException(404, detail='Repository not found.')
    return repository


@router.post('/repositories/{repository_id}/analyze', status_code=202)
def start_analysis(repository_id: UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    repository = db.query(Repository).join(Project).filter(Repository.id == repository_id, Project.owner_id == current_user.id).with_for_update(of=Repository).first()
    if repository is None: raise HTTPException(404, detail='Repository not found.')
    owned_target(db, repository.target_id, current_user)
    if repository.ingestion_status != 'READY': raise HTTPException(409, detail='Wait for ZIP ingestion to reach READY.')
    if repository.analysis_status in {'QUEUED', 'RUNNING'}: raise HTTPException(409, detail='This repository already has an active analysis.')
    # Bound repeated analyses and retained index metadata per repository.
    if db.query(ScanJob).filter(ScanJob.repository_id == repository_id, ScanJob.job_type == 'REPOSITORY_ANALYSIS').count() >= 20:
        raise HTTPException(409, detail='Analysis history limit reached. Contact the local operator.')
    job_id, task_id = uuid4(), str(uuid4())
    job = ScanJob(id=job_id, target_id=repository.target_id, repository_id=repository_id,
                  requesting_user_id=current_user.id, celery_task_id=task_id,
                  job_type='REPOSITORY_ANALYSIS', scan_profile='REPOSITORY_STATIC', status='QUEUED',
                  current_stage='QUEUED', message='Repository analysis queued; no scanner has finished.')
    db.add(job)
    db.flush()  # Job must exist before the latest-analysis FK pointer is set.
    repository.latest_analysis_job_id = job_id
    repository.analysis_status = 'QUEUED'
    db.commit()
    try:
        analyze_repository.apply_async(args=[str(job_id)], task_id=task_id)
    except Exception:
        db.rollback()
        changed = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.status == 'QUEUED').update({
            'status': 'FAILED', 'current_stage': 'BROKER_ERROR', 'message': 'Queue dispatch was not acknowledged.',
            'failure_code': 'BROKER_SUBMISSION_FAILED', 'failure_message': 'The background queue is unavailable.',
            'finished_at': datetime.now(timezone.utc),
        }, synchronize_session=False)
        if changed:
            db.query(Repository).filter(Repository.id == repository_id, Repository.latest_analysis_job_id == job_id).update({'analysis_status': 'FAILED'}, synchronize_session=False)
        db.commit()
        raise HTTPException(503, detail={'message': 'Queue dispatch was not acknowledged. Check analysis status.', 'job_id': str(job_id)}) from None
    return {'job_id': job_id, 'message': 'Real Semgrep and Gitleaks analysis queued.'}


@router.get('/repositories/{repository_id}/analyses')
def analysis_history(repository_id: UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    owned_repository(db, repository_id, current_user)
    jobs = db.query(ScanJob).filter(ScanJob.repository_id == repository_id, ScanJob.job_type == 'REPOSITORY_ANALYSIS').order_by(ScanJob.created_at.desc()).all()
    # File index has its own endpoint; do not repeatedly send it in polling responses.
    return [{'id': job.id, 'status': job.status, 'current_stage': job.current_stage, 'message': job.message,
             'created_at': job.created_at, 'started_at': job.started_at, 'finished_at': job.finished_at,
             'failure_code': job.failure_code, 'failure_message': job.failure_message,
             'result': {key: value for key, value in (job.result_summary or {}).items() if key != 'intelligence'}} for job in jobs]


@router.get('/repositories/{repository_id}/findings', response_model=list[FindingResponse])
def repository_findings(repository_id: UUID, scan_id: UUID | None = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    repository = owned_repository(db, repository_id, current_user)
    effective_scan = scan_id or repository.latest_analysis_job_id
    if effective_scan is None: return []
    return db.query(Finding).filter(Finding.repository_id == repository_id, Finding.scan_id == effective_scan).order_by(Finding.created_at).all()


def analysis_job(db, repository, scan_id):
    effective_scan = scan_id or repository.latest_analysis_job_id
    job = db.query(ScanJob).filter(ScanJob.id == effective_scan, ScanJob.repository_id == repository.id,
                                  ScanJob.job_type == 'REPOSITORY_ANALYSIS').first()
    if job is None: raise HTTPException(404, detail='Analysis not found.')
    return job


@router.get('/repositories/{repository_id}/files')
def indexed_files(repository_id: UUID, scan_id: UUID | None = None, search: str = Query('', max_length=120),
                  db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    repository = owned_repository(db, repository_id, current_user)
    job = analysis_job(db, repository, scan_id)
    files = (job.result_summary or {}).get('intelligence', {}).get('files', [])
    return [file for file in files if search.lower() in file['path'].lower()]


@router.get('/repositories/{repository_id}/source')
def view_source(repository_id: UUID, path: str = Query(..., max_length=500), line: int = Query(1, ge=1, le=1000000),
                scan_id: UUID | None = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    repository = owned_repository(db, repository_id, current_user)
    job = analysis_job(db, repository, scan_id)
    summary = job.result_summary or {}
    if job.status not in {'COMPLETED', 'PARTIALLY_COMPLETED'}:
        raise HTTPException(409, detail='Source viewing requires a finished analysis.')
    if not any(t['tool'] == 'gitleaks' and t['status'] == 'COMPLETED' for t in summary.get('tools', [])):
        raise HTTPException(409, detail='Source is withheld until secret detection completes successfully.')
    entry = next((file for file in summary.get('intelligence', {}).get('files', []) if file['path'] == path), None)
    if entry is None: raise HTTPException(404, detail='Indexed file not found.')
    secret_paths = {finding.source_location['file'] for finding in db.query(Finding).filter(
        Finding.scan_id == job.id, Finding.repository_id == repository.id, Finding.source == 'SECRET_DETECTION').all()}
    try:
        directory = repository_directory(settings.SCAN_WORKSPACE_ROOT, repository.id)
        return source_context(directory / 'source', entry, line=line, secret_paths=secret_paths)
    except PermissionError as error:
        raise HTTPException(403, detail=str(error)) from None
    except (ValueError, OSError):
        raise HTTPException(409, detail='Requested source context is unavailable or changed.') from None
