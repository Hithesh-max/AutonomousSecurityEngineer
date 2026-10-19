"""One finding per task, durable checkpoints, no unbounded parallel provider calls."""
from datetime import datetime
from uuid import UUID
from sqlalchemy import text
from app.config.database import SessionLocal, engine
from app.models.remediation import RemediationBatch, AIAnalysis, PatchProposal
from app.models.repository import Repository
from app.models.user import User
from app.remediation import service
from app.remediation.source import locator_for, SourceUnavailable
from app.workers.celery_app import celery


def dispatch(batch_id):
    try:
        process_remediation_batch.apply_async(args=[str(batch_id)])
    except Exception:
        with SessionLocal() as db:
            db.query(RemediationBatch).filter(RemediationBatch.id == batch_id,
                RemediationBatch.status == 'QUEUED').update({'status': 'PAUSED', 'message': 'Queue unavailable. Resume when the worker is available.'})
            db.commit()
        return False
    return True


@celery.task(name='process_remediation_batch', soft_time_limit=400, time_limit=450)
def process_remediation_batch(batch_id):
    batch_id = UUID(batch_id)
    # Dedicated connection holds a session lock across service commits; worker death releases it.
    with engine.connect() as lease:
        key = {'key': f'ase-remediation-batch:{batch_id}'}
        if not lease.execute(text('SELECT pg_try_advisory_lock(hashtext(:key))'), key).scalar(): return
        try:
            again = process_one(batch_id)
        finally:
            lease.execute(text('SELECT pg_advisory_unlock(hashtext(:key))'), key)
    if again: dispatch(batch_id)


def process_one(batch_id):
    again = False
    with SessionLocal() as db:
        changed = db.query(RemediationBatch).filter(RemediationBatch.id == batch_id,
            RemediationBatch.status == 'QUEUED').update({'status': 'RUNNING', 'updated_at': datetime.utcnow()})
        db.commit()
        if not changed: return
        batch = db.get(RemediationBatch, batch_id)
        try:
            repo = db.get(Repository, batch.repository_id)
            user = db.get(User, batch.requested_by)
            if not user or not user.is_active or not repo or repo.latest_analysis_job_id != batch.scan_id:
                raise service.RemediationError(409, 'BATCH_STALE', 'Repository scan or user authorization changed; start a new batch.')
            if batch.cursor >= len(batch.items):
                batch.status = 'COMPLETED'; db.commit(); return
            item = dict(batch.items[batch.cursor])
            fid = UUID(item['finding_id'])
            finding = service.get_owned_finding(db, fid, user)
            source = None
            try:
                source = locator_for(finding).locate(db, finding, user.id)
                item["source_status"] = source.mapping_status
            except SourceUnavailable as error:
                item['source_status'] = error.code
                if batch.mode == 'PROPOSE':
                    item.update(status='SKIPPED', detail=error.message)
            if source is not None and batch.mode == 'PROPOSE':
                from app.remediation.languages import supports
                if not supports(source.path):
                    source = None
                    item.update(status='SKIPPED', detail='No installed syntax adapter for this language; manual review required.')
            if batch.mode == 'ANALYZE' or source is not None:
                existing = db.query(PatchProposal).filter(PatchProposal.finding_id == fid,
                    PatchProposal.status.in_(['PATCH_PROPOSED', 'APPROVED', 'INCONCLUSIVE', 'VERIFIED'])).order_by(PatchProposal.created_at.desc()).first()
                if batch.mode == 'PROPOSE' and existing and existing.source_sha256 == source.sha256:
                    item.update(status='PRESERVED', detail='Existing proposal retained for review.')
                else:
                    analysis = db.query(AIAnalysis).filter(AIAnalysis.finding_id == fid,
                        AIAnalysis.status == 'COMPLETED').order_by(AIAnalysis.created_at.desc()).first()
                    if not analysis or analysis.source_sha256 != (source.sha256 if source else None):
                        analysis = service.analyze(db, user, fid, batch.consent)
                    db.refresh(batch)
                    if batch.status == 'PAUSING':
                        batch.status = 'PAUSED'; batch.message = 'Paused after analysis; resume to generate proposal.'; db.commit(); return
                    if batch.mode == 'PROPOSE':
                        service.generate_patch(db, user, fid, analysis.id, batch.consent)
                    item.update(status='PROPOSED' if batch.mode == 'PROPOSE' else 'ANALYZED', detail='Saved; human review required. Not security-verified.')
            db.refresh(batch)
            items = list(batch.items); items[batch.cursor] = item
            batch.items = items; batch.cursor += 1
            batch.status = 'PAUSED' if batch.status == 'PAUSING' else 'COMPLETED' if batch.cursor == len(items) else 'QUEUED'
            batch.message = f'{batch.cursor}/{len(items)} findings processed.'
            again = batch.status == 'QUEUED'; db.commit()
        except service.RemediationError as error:
            db.rollback(); batch = db.get(RemediationBatch, batch_id)
            if error.code in {'AI_RATE_LIMITED', 'AI_AUTH_FAILED', 'BATCH_STALE', 'EXTERNAL_TRANSMISSION_NOT_CONFIRMED'}:
                batch.status = 'PAUSED'; batch.message = error.message
            else:
                items = list(batch.items)
                if batch.cursor < len(items):
                    items[batch.cursor] = {**items[batch.cursor], 'status': 'FAILED', 'detail': error.message, 'code': error.code}
                    batch.items = items; batch.cursor += 1
                batch.status = 'PAUSED' if batch.status == 'PAUSING' else 'COMPLETED' if batch.cursor == len(items) else 'QUEUED'
                again = batch.status == 'QUEUED'
            db.commit()
        except Exception:
            db.rollback(); batch = db.get(RemediationBatch, batch_id)
            if batch:
                batch.status = 'PAUSED'; batch.message = 'Worker interrupted or processing failed. Completed results are preserved; resume to retry.'; db.commit()
    return again
