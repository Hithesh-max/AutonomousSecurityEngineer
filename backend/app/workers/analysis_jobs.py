"""Real repository analysis. Scanner failures are durable, separate tool results."""
from dataclasses import asdict
from datetime import datetime, timezone
import logging
import shutil
from uuid import UUID
from app.workers.celery_app import celery
from app.config.database import SessionLocal
from app.config.settings import settings
from app.models.project import ScanJob
from app.models.repository import Repository
from app.models.finding import Finding
from app.repositories.access import require_authorized_target
from app.repositories.storage import repository_directory
from app.repositories.intelligence import inspect_repository
from app.repositories.analysis import create_snapshot, verify_snapshot, prepare_findings, rule_pack_hash
from app.scanners.controlled import ToolFailure
from app.scanners.semgrep import SemgrepScanner
from app.scanners.gitleaks import GitleaksScanner
from app.utils.redaction import redact_evidence

logger = logging.getLogger(__name__)


@celery.task(bind=True, name='analyze_repository', soft_time_limit=550, time_limit=600)
def analyze_repository(self, job_id: str):
    job_id = UUID(job_id)
    db, snapshot, summary = SessionLocal(), None, None
    try:
        claimed = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.job_type == 'REPOSITORY_ANALYSIS', ScanJob.status == 'QUEUED').update({
            'status': 'RUNNING', 'current_stage': 'INDEXING', 'message': 'Inspecting source without executing application code.',
            'started_at': datetime.now(timezone.utc),
        }, synchronize_session=False)
        db.commit()
        if not claimed: return 'Aborted: job already claimed, terminal, or missing.'
        job = db.query(ScanJob).filter(ScanJob.id == job_id).one()
        repository = db.query(Repository).filter(Repository.id == job.repository_id).one()
        def authorize():
            db.expire_all()
            target = require_authorized_target(db, job.target_id, job.requesting_user_id)
            if repository.latest_analysis_job_id != job_id or repository.ingestion_status != 'READY' or repository.target_id != target.id or repository.project_id != target.project_id or repository.uploaded_by != job.requesting_user_id:
                raise PermissionError('Analysis provenance or authorization mismatch.')
        def progress(stage, summary):
            changed = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.status == 'RUNNING').update({
                'current_stage': stage, 'message': f'Repository analysis: {stage.lower()}.', 'result_summary': summary,
            }, synchronize_session=False)
            if not changed: raise PermissionError('Job is no longer running.')
            db.commit()
        authorize()
        db.query(Repository).filter(Repository.id == repository.id).update({'analysis_status': 'RUNNING'}, synchronize_session=False)
        db.commit()
        directory = repository_directory(settings.SCAN_WORKSPACE_ROOT, repository.id)
        inspection = inspect_repository(directory / 'source')
        intelligence = redact_evidence(asdict(inspection))
        snapshot = directory / f'analysis-{job_id}'
        create_snapshot(directory / 'source', snapshot, inspection.files)
        summary = {'repository_id': str(repository.id), 'archive_sha256': repository.archive_sha256,
                   'intelligence': intelligence, 'tools': [], 'finding_count': 0,
                   'coverage_note': 'ASE local rules are limited patterns; absence of findings does not prove security.'}
        db.query(Repository).filter(Repository.id == repository.id, Repository.latest_analysis_job_id == job_id).update({'intelligence': intelligence}, synchronize_session=False)
        progress('ANALYZING', summary)
        all_findings = []
        for adapter in [SemgrepScanner(), GitleaksScanner()]:
            authorize()
            verify_snapshot(snapshot, inspection.files)
            tool = {'tool': adapter.tool, 'status': 'RUNNING', 'finding_count': 0}
            summary['tools'].append(tool)
            progress(adapter.tool.upper(), summary)
            began = datetime.now(timezone.utc)
            try:
                info = {**adapter.health_check(), 'rule_pack_sha256': rule_pack_hash()}
                tool.update(info)
                raw = adapter.scan(snapshot)
                verify_snapshot(snapshot, inspection.files)
                prepared = prepare_findings(adapter, raw, snapshot, inspection.files, repository.project_id, job_id,
                                             repository.id, repository.archive_sha256, info)
                errors = len(raw.get('errors', [])) if adapter.tool == 'semgrep' else 0
                tool.update(status='PARTIAL' if errors else 'COMPLETED', finding_count=len(prepared), error_count=errors)
                if adapter.tool == 'semgrep':
                    tool['scanned_files'] = len(raw.get('paths', {}).get('scanned', []))
                    if not tool['scanned_files']:
                        tool.update(status='PARTIAL', failure_code='NO_SUPPORTED_FILES', failure_message='Semgrep reported no scanned files.')
                    if errors: tool.update(failure_code='INCOMPLETE_COVERAGE', failure_message='Semgrep reported scan or parsing errors.')
                all_findings.extend(prepared)
            except FileNotFoundError:
                tool.update(status='FAILED', failure_code='TOOL_NOT_INSTALLED', failure_message=f'{adapter.display_name} is not installed in the worker.')
            except ToolFailure as error:
                tool.update(status='FAILED', failure_code=error.code, failure_message=error.message)
                if error.code == 'PROVENANCE_ERROR': raise
            except (OSError, ValueError, TypeError, AttributeError):
                tool.update(status='FAILED', failure_code='TOOL_EXECUTION_ERROR', failure_message='Scanner execution or output validation failed.')
            tool['duration_seconds'] = round((datetime.now(timezone.utc) - began).total_seconds(), 2)
            progress('NORMALIZING', summary)
        authorize()
        verify_snapshot(snapshot, inspection.files)
        # Findings and terminal job state commit together. Late recovered workers cannot publish.
        complete = sum(t['status'] == 'COMPLETED' for t in summary['tools'])
        failed = sum(t['status'] == 'FAILED' for t in summary['tools'])
        status = 'FAILED' if failed == len(summary['tools']) else 'COMPLETED' if complete == len(summary['tools']) and not inspection.warnings else 'PARTIALLY_COMPLETED'
        summary['finding_count'] = len(all_findings)
        changed = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.status == 'RUNNING').update({
            'status': status, 'current_stage': status, 'message': 'Repository analysis finished. Review tool coverage and findings.',
            'result_summary': summary, 'finished_at': datetime.now(timezone.utc),
            'failure_code': 'ALL_TOOLS_FAILED' if status == 'FAILED' else None,
            'failure_message': 'Source indexed, but both scanners failed.' if status == 'FAILED' else None,
        }, synchronize_session=False)
        if not changed:
            db.rollback()
            return 'Aborted: late completion ignored.'
        for finding in all_findings: db.add(Finding(**finding))
        db.query(Repository).filter(Repository.id == repository.id, Repository.latest_analysis_job_id == job_id).update({'analysis_status': status}, synchronize_session=False)
        db.commit()
        logger.info('repository_analysis_finished', extra={'job_id': str(job_id), 'status': status, 'finding_count': len(all_findings)})
        if status == 'FAILED': raise ToolFailure('ALL_TOOLS_FAILED', 'Source indexed, but both scanners failed.')
        return status
    except Exception as error:
        db.rollback()
        code = 'AUTHORIZATION_ERROR' if isinstance(error, PermissionError) else error.code if isinstance(error, ToolFailure) else 'ANALYSIS_ERROR'
        message = 'Repository access or target authorization is no longer valid.' if isinstance(error, PermissionError) else error.message if isinstance(error, ToolFailure) else 'Repository analysis failed. Check worker resources and source validity.'
        try:
            if summary is not None:
                for tool in summary.get('tools', []):
                    if tool['status'] == 'RUNNING':
                        tool.update(status='FAILED', failure_code=code, failure_message=message)
            job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
            changed = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.status == 'RUNNING').update({
                'status': 'FAILED', 'current_stage': 'ERROR', 'message': message, 'failure_code': code,
                'failure_message': message, 'finished_at': datetime.now(timezone.utc),
                **({'result_summary': summary} if summary is not None else {}),
            }, synchronize_session=False)
            if changed and job:
                db.query(Repository).filter(Repository.id == job.repository_id, Repository.latest_analysis_job_id == job_id).update({'analysis_status': 'FAILED'}, synchronize_session=False)
            db.commit()
        except Exception:
            db.rollback()
            logger.critical('analysis_failure_persistence_failed', extra={'job_id': str(job_id)})
        logger.error('repository_analysis_failed', extra={'job_id': str(job_id), 'failure_code': code})
        raise RuntimeError(message) from None
    finally:
        db.close()
        if snapshot is not None and snapshot.exists(): shutil.rmtree(snapshot)
