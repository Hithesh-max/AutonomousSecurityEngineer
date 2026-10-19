"""Network scanning with repeated authorization, SSRF validation, and exclusive ZAP ownership."""
from datetime import datetime, timezone
import logging
from urllib.parse import urlsplit
from uuid import UUID
import redis
from app.workers.celery_app import celery
from app.config.database import SessionLocal
from app.config.settings import settings
from app.models.project import ScanJob
from app.models.finding import Finding
from app.repositories.access import require_authorized_target
from app.network.scope import (
    LAB_URL, validate_lab_target, resolve_lab, is_lab_target,
    resolve_and_verify_destination
)
from app.scanners.nmap import NmapScanner
from app.scanners.zap import ZAPScanner
from app.scanners.controlled import ToolFailure
from app.utils.redaction import redact_evidence

logger = logging.getLogger(__name__)

@celery.task(bind=True, name='run_web_scan', soft_time_limit=620, time_limit=650)
def run_web_scan(self, job_id: str):
    job_id = UUID(job_id)
    db, summary, lease, zap = SessionLocal(), None, None, None
    owns_lease = False
    try:
        claimed = db.query(ScanJob).filter(
            ScanJob.id == job_id, ScanJob.job_type == 'WEB_SCAN', ScanJob.status == 'QUEUED'
        ).update({
            'status': 'RUNNING',
            'current_stage': 'AUTHORIZATION_CHECK',
            'message': 'Checking target authorization, destination, and SSRF policies.',
            'started_at': datetime.now(timezone.utc)
        }, synchronize_session=False)
        db.commit()
        if not claimed:
            return 'Aborted: job already claimed or terminal.'

        job = db.query(ScanJob).filter(ScanJob.id == job_id).one()
        summary = dict(job.result_summary or {})
        config = summary.get('configuration', {})
        if config.get('profile') not in {'SAFE', 'STANDARD'} or type(config.get('active_testing')) is not bool or type(config.get('active_consent')) is not bool:
            raise ToolFailure('CONFIGURATION_ERROR', 'Stored scan configuration is invalid.')
        if config['active_testing'] and not config['active_consent']:
            raise PermissionError('Active consent is absent.')

        def authorize():
            db.expire_all()
            if job.status != 'RUNNING':
                raise PermissionError('Scan no longer permitted.')
            target = require_authorized_target(db, job.target_id, job.requesting_user_id)
            is_lab = is_lab_target(target.url)
            if is_lab:
                if not settings.LAB_SCANNING_ENABLED:
                    raise PermissionError('Lab scanning is disabled.')
                validate_lab_target(target.url)
                resolved = resolve_lab()
            else:
                resolved = resolve_and_verify_destination(target.url, target.explicit_scope)

            if summary.get('target_url') and summary.get('target_url') != target.url:
                raise PermissionError('Stored target mismatch.')

            if owns_lease and (lease is None or not lease.owned()):
                raise PermissionError('Exclusive ZAP lease lost.')
            return target, resolved, is_lab

        def progress(stage, percent=None):
            event = {'stage': stage, 'at': datetime.now(timezone.utc).isoformat()}
            if percent is not None:
                event['percent'] = percent
            summary.setdefault('events', []).append(event)
            summary['events'] = summary['events'][-250:]
            changed = db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.status == 'RUNNING').update({
                'current_stage': stage,
                'message': f'Web assessment: {stage.lower()}' + (f' ({percent}%)' if percent is not None else ''),
                'result_summary': summary
            }, synchronize_session=False)
            if not changed:
                raise PermissionError('Job was marked terminal.')
            db.commit()

        target, resolved_ip, is_lab = authorize()
        project_id = target.project_id
        summary['resolved_ip'] = resolved_ip
        parsed_target = urlsplit(target.url)
        target_port = parsed_target.port or (443 if parsed_target.scheme == 'https' else 80)
        prepared = []

        for name in ['nmap', 'zap']:
            target, resolved_ip, is_lab = authorize()
            tool = {'tool': name, 'status': 'RUNNING', 'finding_count': 0}
            summary.setdefault('tools', []).append(tool)
            progress('RECONNAISSANCE' if name == 'nmap' else 'ZAP_CONNECTING')
            began = datetime.now(timezone.utc)
            try:
                if name == 'nmap':
                    adapter = NmapScanner(config['profile'], check=authorize, port=target_port)
                    info = adapter.health_check()
                    tool.update(tool=name, version=info['version'], profile=config['profile'])
                    tool.update(redact_evidence(adapter.scan(summary['resolved_ip'])))
                else:
                    connection = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=3, socket_timeout=3)
                    lease_name = 'ase:lab:zap:exclusive' if is_lab else 'ase:zap:exclusive'
                    lease = connection.lock(lease_name, timeout=900, blocking=False, thread_local=False)
                    if not lease.acquire():
                        raise ToolFailure('ZAP_BUSY', 'Another job owns ZAP. Retry after it finishes.')
                    owns_lease = True
                    zap = ZAPScanner(settings.ZAP_API_KEY.get_secret_value(), check=authorize, progress=progress)
                    info = zap.health_check()
                    tool.update(info)
                    raw = zap.scan(target.url, active=config['active_testing'], explicit_scope=target.explicit_scope)
                    prepared = zap.normalize(raw, project_id, explicit_scope=target.explicit_scope)
                    tool.update(
                        endpoints=raw['endpoints'],
                        spider_id=raw['spider_id'],
                        active_scan_id=raw['active_scan_id'],
                        active_testing=config['active_testing'],
                        finding_count=len(prepared)
                    )
                    for finding in prepared:
                        finding['scan_id'] = job_id
                        finding['evidence'].update(
                            scanner_version=info['version'],
                            policy_version=info['policy_version'],
                            target_url=target.url,
                            target_ip=summary['resolved_ip']
                        )
                tool['status'] = 'COMPLETED'
            except PermissionError:
                raise
            except FileNotFoundError:
                tool.update(status='FAILED', failure_code='TOOL_NOT_INSTALLED', failure_message='Required scanner executable is unavailable.')
            except ToolFailure as error:
                tool.update(status='FAILED', failure_code=error.code, failure_message=error.message)
            except (OSError, redis.RedisError):
                tool.update(status='FAILED', failure_code='TOOL_UNAVAILABLE', failure_message='Scanner or exclusive queue lease is unavailable.')
            finally:
                if name == 'zap' and zap is not None and owns_lease:
                    try:
                        if lease.owned():
                            zap.stop()
                        else:
                            raise ToolFailure('ZAP_LEASE_LOST', 'ZAP ownership could not be confirmed.')
                    except (ToolFailure, redis.RedisError):
                        tool.update(status='FAILED', failure_code='ZAP_STOP_UNCONFIRMED', failure_message='ZAP stop could not be confirmed. Restart ZAP before retrying.')
                        prepared = []
                        tool['finding_count'] = 0
                        owns_lease = False
                if name == 'zap' and owns_lease:
                    lease.release()
                    owns_lease = False

            tool['duration_seconds'] = round((datetime.now(timezone.utc) - began).total_seconds(), 2)
            progress('COLLECTING_RESULTS')

        authorize()
        for item in prepared:
            db.add(Finding(**item))
        db.flush()
        summary['finding_count'] = len(prepared)
        summary['finished_at'] = datetime.now(timezone.utc).isoformat()
        db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.status == 'RUNNING').update({
            'status': 'COMPLETED',
            'current_stage': 'COMPLETED',
            'message': f'Web scan completed with {len(prepared)} findings.',
            'finished_at': datetime.now(timezone.utc),
            'result_summary': summary
        }, synchronize_session=False)
        db.commit()
        return f'Success: web scan completed with {len(prepared)} findings.'
    except Exception as error:
        db.rollback()
        failure_code = getattr(error, 'code', 'SCAN_FAILED') if isinstance(error, ToolFailure) else 'PERMISSION_DENIED' if isinstance(error, PermissionError) else 'WORKER_INTERNAL_ERROR'
        failure_message = getattr(error, 'message', str(error))[:400]
        if summary is None:
            summary = {}
        summary.update(failure_code=failure_code, failure_message=failure_message)
        try:
            db.query(ScanJob).filter(ScanJob.id == job_id, ScanJob.status == 'RUNNING').update({
                'status': 'FAILED',
                'current_stage': 'FAILED',
                'message': failure_message[:200],
                'failure_code': failure_code,
                'failure_message': failure_message,
                'finished_at': datetime.now(timezone.utc),
                'result_summary': summary
            }, synchronize_session=False)
            db.commit()
        except Exception:
            db.rollback()
        raise
    finally:
        if owns_lease and lease is not None:
            try:
                lease.release()
            except Exception:
                pass
        db.close()
