"""Authenticated remediation, durable batch control, review and corrected-project export."""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, StrictBool
from sqlalchemy.orm import Session

from app.ai.factory import provider_status
from app.api.auth import get_current_user
from app.config.database import get_db
from app.models.remediation import AIAnalysis, PatchProposal, RemediationEvent
from app.models.user import User
from app.remediation import service
from app.remediation.service import RemediationError
from app.remediation.source import SourceUnavailable, locator_for

router = APIRouter()


class AIRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    acknowledge_external_transmission: StrictBool = False


class PatchRequest(AIRequest):
    analysis_id: UUID | None = None


def _fail(error: RemediationError):
    return HTTPException(error.status, detail={"code": error.code, "message": error.message, **error.extra})


def _analysis(a: AIAnalysis) -> dict:
    return {"id": a.id, "finding_id": a.finding_id, "status": a.status, "provider": a.provider, "model": a.model,
            "is_mock": a.is_mock, "result": a.result, "error_code": a.error_code, "error_message": a.error_message,
            "source_sha256": a.source_sha256, "created_at": a.created_at, "latency_ms": a.latency_ms,
            "label": "MOCK RESULT - not produced by a real AI model" if a.is_mock else "AI-generated, unverified"}


def _patch(p: PatchProposal) -> dict:
    return {"id": p.id, "finding_id": p.finding_id, "analysis_id": p.analysis_id, "status": p.status,
            "provider": p.provider, "model": p.model, "is_mock": p.is_mock, "source_path": p.source_path,
            "source_sha256": p.source_sha256, "patched_sha256": p.patched_sha256, "patch_sha256": p.patch_sha256,
            "unified_diff": p.unified_diff, "explanation": p.explanation, "behavior_notes": p.behavior_notes,
            "limitations": p.limitations or [], "static_checks": p.static_checks,
            "verification_status": p.verification_status, "created_at": p.created_at,
            "label": "MOCK RESULT - not produced by a real AI model" if p.is_mock else "AI-generated proposal, unverified",
            "approved_by": p.approved_by, "approved_at": p.approved_at}


@router.get("/ai/status")
def ai_status(current_user: User = Depends(get_current_user)):
    return provider_status()


@router.get("/findings/{finding_id}/remediation")
def remediation_summary(finding_id: UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        finding = service.get_owned_finding(db, finding_id, current_user)
    except RemediationError as error:
        raise _fail(error)
    try:
        src = locator_for(finding).locate(db, finding, current_user.id)
        source = {"available": True, "path": src.path, "start_line": src.start_line, "end_line": src.end_line,
                  "highlight_line": src.highlight_line, "sha256": src.sha256, "mapping_status": src.mapping_status,
                  "content": src.window_text(with_numbers=False)}
    except SourceUnavailable as error:
        source = {"available": False, "code": error.code, "message": error.message}
    analyses = (db.query(AIAnalysis).filter(AIAnalysis.finding_id == finding.id)
                .order_by(AIAnalysis.created_at.desc()).limit(10).all())
    patches = (db.query(PatchProposal).filter(PatchProposal.finding_id == finding.id)
               .order_by(PatchProposal.created_at.desc()).limit(10).all())
    events = (db.query(RemediationEvent).filter(RemediationEvent.finding_id == finding.id)
              .order_by(RemediationEvent.created_at.desc()).limit(50).all())
    return {"finding_id": finding.id, "ai": provider_status(), "source": source,
            "analyses": [_analysis(a) for a in analyses], "patches": [_patch(p) for p in patches],
            "events": [{"event_type": e.event_type, "from_state": e.from_state, "to_state": e.to_state,
                        "actor_id": e.actor_id, "created_at": e.created_at, "details": e.details} for e in events]}


@router.post("/findings/{finding_id}/analysis", status_code=201)
def create_analysis(finding_id: UUID, body: AIRequest, db: Session = Depends(get_db),
                    current_user: User = Depends(get_current_user)):
    try:
        return _analysis(service.analyze(db, current_user, finding_id, body.acknowledge_external_transmission))
    except RemediationError as error:
        db.rollback()
        raise _fail(error)


@router.post("/findings/{finding_id}/patches", status_code=201)
def create_patch(finding_id: UUID, body: PatchRequest, db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)):
    try:
        return _patch(service.generate_patch(db, current_user, finding_id, body.analysis_id,
                                             body.acknowledge_external_transmission))
    except RemediationError as error:
        db.rollback()
        raise _fail(error)


@router.get("/patches/{patch_id}")
def get_patch(patch_id: UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    patch = db.query(PatchProposal).filter(PatchProposal.id == patch_id).first()
    try:
        if not patch:
            raise RemediationError(404, "PATCH_NOT_FOUND", "Patch not found.")
        service.get_owned_finding(db, patch.finding_id, current_user)
    except RemediationError as error:
        raise _fail(error)
    return _patch(patch)


class PatchDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    patch_sha256: str


@router.post("/patches/{patch_id}/approve")
def approve_patch(patch_id: UUID, body: PatchDecision, db: Session = Depends(get_db),
                  current_user: User = Depends(get_current_user)):
    try:
        return _patch(service.decide_patch(db, current_user, patch_id, "APPROVED", body.patch_sha256))
    except RemediationError as error:
        db.rollback()
        raise _fail(error)


@router.post("/patches/{patch_id}/reject")
def reject_patch(patch_id: UUID, body: PatchDecision, db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)):
    try:
        return _patch(service.decide_patch(db, current_user, patch_id, "REJECTED", body.patch_sha256))
    except RemediationError as error:
        db.rollback()
        raise _fail(error)


@router.post("/patches/{patch_id}/verify")
def verify_patch(patch_id: UUID, db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)):
    try:
        return service.verify_approved_patch(db, current_user, patch_id)
    except RemediationError as error:
        db.rollback()
        raise _fail(error)


@router.get('/repositories/{repository_id}/corrected-zip')
def download_corrected_repository(repository_id: UUID, patch_ids: str = "", all_approved: bool = False,
                                  db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Export one or more explicitly approved, nonconflicting proposals as a complete project ZIP."""
    from fastapi.responses import Response
    from app.remediation.export import export_repository_zip, ExportRejected
    if all_approved:
        from app.models.finding import Finding
        from app.models.project import Project
        from app.models.repository import Repository
        owned = db.query(Repository).join(Project).filter(
            Repository.id == repository_id, Project.owner_id == current_user.id).first()
        if not owned:
            raise HTTPException(404, detail='Repository not found.')
        proposals = (db.query(PatchProposal).join(Finding, Finding.id == PatchProposal.finding_id)
                     .filter(Finding.repository_id == repository_id,
                             PatchProposal.status.in_(['APPROVED', 'INCONCLUSIVE', 'VERIFIED']),
                             Finding.scan_id == owned.latest_analysis_job_id)
                     .order_by(PatchProposal.created_at.desc()).limit(1001).all())
        if len(proposals) > 1000:
            raise HTTPException(409, detail='Over 1000 approved patches; split the export safely.')
    else:
        ids = patch_ids.split(',')
        if not 1 <= len(ids) <= 1000:
            raise HTTPException(422, detail='Select between 1 and 1000 approved patches.')
        try:
            parsed = [UUID(i.strip()) for i in ids]
        except ValueError:
            raise HTTPException(422, detail='Invalid patch identifier.') from None
        if len(set(parsed)) != len(parsed):
            raise HTTPException(422, detail='Duplicate patch identifier.')
        proposals = []
        for pid in parsed:
            proposal = db.query(PatchProposal).filter(PatchProposal.id == pid).first()
            if not proposal:
                raise HTTPException(404, detail='Patch not found.')
            try:
                service.get_owned_finding(db, proposal.finding_id, current_user)
            except RemediationError as error:
                raise _fail(error)
            proposals.append(proposal)
    try:
        content = export_repository_zip(db, current_user, repository_id, proposals)
    except (ExportRejected, ValueError) as error:
        raise HTTPException(409, detail=str(error)) from None
    for proposal in proposals:
        finding = service.get_owned_finding(db, proposal.finding_id, current_user)
        service._event(db, finding, current_user, 'PATCH_EXPORTED', patch=proposal,
                       details={'patch_sha256': proposal.patch_sha256, 'verification_status': 'INCONCLUSIVE'})
    db.commit()
    return Response(content, media_type='application/zip', headers={
        'Content-Disposition': f'attachment; filename="ase-corrected-{repository_id}.zip"',
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
    })


@router.get('/patches/{patch_id}/corrected-source')
def corrected_source_preview(patch_id: UUID, db: Session = Depends(get_db),
                             current_user: User = Depends(get_current_user)):
    """Return the complete proposed corrected file for review; original remains unchanged."""
    from app.remediation.export import _patched_bytes, ExportRejected
    from app.remediation.patching import PatchRejected
    from pydantic import ValidationError
    try:
        patch, finding = service.get_owned_patch(db, patch_id, current_user)
        source = locator_for(finding).locate(db, finding, current_user.id)
        corrected = _patched_bytes(source, patch)
        return {'path': source.path, 'content': corrected.decode('utf-8'), 'original_content': '\n'.join(source.lines) + '\n',
                'patched_sha256': patch.patched_sha256,
                'status': 'PROPOSED_UNVERIFIED', 'original_unchanged': True}
    except RemediationError as error:
        raise _fail(error)
    except SourceUnavailable:
        raise HTTPException(409, detail='Source is unavailable or stale.') from None
    except (ExportRejected, PatchRejected, ValidationError, ValueError):
        raise HTTPException(409, detail='Proposed patch failed integrity validation.') from None


@router.get('/repositories/{repository_id}/remediation-inventory')
def remediation_inventory(repository_id: UUID, db: Session = Depends(get_db),
                          current_user: User = Depends(get_current_user)):
    """Classify EVERY finding from the repository's latest scan without invoking an AI.

    A source location is eligible only if the existing provenance-checked locator accepts it.
    Missing source, secrets, and unsupported languages are never reported as repaired.
    """
    from app.models.repository import Repository
    from app.models.project import Project
    from app.models.finding import Finding

    repo = db.query(Repository).join(Project).filter(
        Repository.id == repository_id, Project.owner_id == current_user.id,
        Repository.ingestion_status == 'READY').first()
    if not repo:
        raise HTTPException(404, detail='Uploaded repository not found.')
    if repo.latest_analysis_job_id is None:
        return {'repository_id': str(repo.id), 'scan_id': None, 'items': [],
                'total': 0, 'eligible': 0, 'unsupported': 0, 'approved': 0}
    findings = db.query(Finding).filter(
        Finding.repository_id == repo.id, Finding.scan_id == repo.latest_analysis_job_id
    ).order_by(Finding.created_at, Finding.id).all()
    ids = [f.id for f in findings]
    patches = (db.query(PatchProposal).filter(PatchProposal.finding_id.in_(ids))
               .order_by(PatchProposal.created_at.desc()).all()) if ids else []
    analyses = (db.query(AIAnalysis).filter(AIAnalysis.finding_id.in_(ids))
                .order_by(AIAnalysis.created_at.desc()).all()) if ids else []
    latest_patch, latest_analysis = {}, {}
    for patch in patches:
        latest_patch.setdefault(patch.finding_id, patch)
    for analysis in analyses:
        latest_analysis.setdefault(analysis.finding_id, analysis)
    items = []
    for finding in findings:
        try:
            source = locator_for(finding).locate(db, finding, current_user.id)
            eligible, reason = True, None
            source_path = source.path
            source_status = getattr(source, "mapping_status", "VERIFIED_SOURCE")
            from app.remediation.languages import supports
            if not supports(source.path):
                eligible, reason = False, 'No configured syntax validator for this language; manual review required.'
        except SourceUnavailable as exc:
            eligible, reason = False, exc.message
            source_status = exc.code
            source_path = (finding.source_location or {}).get('file')
        patch = latest_patch.get(finding.id)
        analysis = latest_analysis.get(finding.id)
        items.append({
            'finding_id': str(finding.id), 'title': finding.title,
            'scan_id': str(getattr(finding, 'scan_id', repo.latest_analysis_job_id)), 'project_id': str(getattr(finding, 'project_id', '')),
            'scanner': getattr(finding, 'source_tools', []), 'rule_id': getattr(finding, 'tool_rule_id', None),
            'confidence': getattr(finding, 'confidence', None), 'cwe': getattr(finding, 'cwe', None), 'fingerprint': getattr(finding, 'fingerprint', None),
            'severity': finding.severity, 'source': finding.source,
            'source_path': source_path, 'source_status': source_status, 'eligible': eligible,
            'reason': reason, 'patch_id': str(patch.id) if patch else None,
            'patch_status': patch.status if patch else None,
            'patch_sha256': patch.patch_sha256 if patch else None,
            'analysis_status': analysis.status if analysis else None,
            'verification_status': patch.verification_status if patch else 'NOT_VERIFIED',
        })
    return {
        'repository_id': str(repo.id), 'scan_id': str(repo.latest_analysis_job_id),
        'total': len(items), 'eligible': sum(x['eligible'] for x in items),
        'unsupported': sum(not x['eligible'] for x in items),
        'approved': sum(x['patch_status'] in ('APPROVED', 'INCONCLUSIVE', 'VERIFIED') for x in items),
        'items': items,
    }


class BatchRequest(AIRequest):
    mode: str = 'PROPOSE'


def _batch_response(batch):
    return {'id': str(batch.id), 'repository_id': str(batch.repository_id), 'scan_id': str(batch.scan_id),
            'status': batch.status, 'mode': batch.mode, 'processed': batch.cursor, 'total': len(batch.items),
            'message': batch.message, 'items': batch.items, 'created_at': batch.created_at, 'updated_at': batch.updated_at}


@router.get('/repositories/{repository_id}/remediation-batches')
def list_batches(repository_id: UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from app.models.remediation import RemediationBatch
    from app.api.repositories import owned_repository
    owned_repository(db, repository_id, current_user)
    return [_batch_response(b) for b in db.query(RemediationBatch).filter(
        RemediationBatch.repository_id == repository_id, RemediationBatch.requested_by == current_user.id
    ).order_by(RemediationBatch.created_at.desc()).limit(30).all()]


@router.post('/repositories/{repository_id}/remediation-batches', status_code=202)
def start_batch(repository_id: UUID, body: BatchRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from app.models.remediation import RemediationBatch
    from app.models.repository import Repository
    from app.ai import factory
    from app.ai.errors import AIError
    from app.workers.remediation_batch import dispatch
    if body.mode not in {'ANALYZE', 'PROPOSE'}: raise HTTPException(422, detail='Invalid batch mode.')
    inventory = remediation_inventory(repository_id, db, current_user)
    if not inventory['scan_id']: raise HTTPException(409, detail='Run repository analysis first.')
    try: provider = factory.get_provider()
    except AIError as error: raise HTTPException(error.http_status, detail={'code': error.code, 'message': error.message}) from None
    if provider.is_external and not body.acknowledge_external_transmission:
        raise HTTPException(400, detail='Confirm external AI transmission before starting a batch.')
    db.query(Repository).filter(Repository.id == repository_id).with_for_update().one()
    active = db.query(RemediationBatch).filter(RemediationBatch.repository_id == repository_id,
        RemediationBatch.status.in_(['QUEUED', 'RUNNING', 'PAUSING'])).first()
    if active: raise HTTPException(409, detail='An active batch already exists for this repository.')
    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    items = [{'finding_id': i['finding_id'], 'title': i['title'], 'status': 'PENDING'}
             for i in sorted(inventory['items'], key=lambda i: order.get(i['severity'], 5))]
    batch = RemediationBatch(repository_id=repository_id, scan_id=UUID(inventory['scan_id']),
        requested_by=current_user.id, mode=body.mode, consent=body.acknowledge_external_transmission,
        status='QUEUED', items=items, cursor=0)
    db.add(batch); db.commit(); db.refresh(batch)
    dispatch(batch.id); db.refresh(batch)
    return _batch_response(batch)


@router.post('/remediation-batches/{batch_id}/{action}')
def control_batch(batch_id: UUID, action: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from datetime import datetime, timedelta
    from app.models.remediation import RemediationBatch
    from app.models.repository import Repository
    from app.api.repositories import owned_repository
    from app.workers.remediation_batch import dispatch
    batch = db.query(RemediationBatch).filter(RemediationBatch.id == batch_id,
        RemediationBatch.requested_by == current_user.id).with_for_update().first()
    if not batch: raise HTTPException(404, detail='Batch not found.')
    repo = owned_repository(db, batch.repository_id, current_user)
    if action == 'pause':
        if batch.status == 'QUEUED': batch.status = 'PAUSED'
        elif batch.status == 'RUNNING': batch.status = 'PAUSING'
    elif action == 'resume':
        if repo.latest_analysis_job_id != batch.scan_id: raise HTTPException(409, detail='Scan changed; start a new batch.')
        stale = batch.status in {'RUNNING', 'PAUSING', 'QUEUED'} and batch.updated_at < datetime.utcnow() - timedelta(minutes=15)
        if batch.status not in {'PAUSED', 'FAILED'} and not stale:
            raise HTTPException(409, detail='Only paused/failed batches or workers stale for 15 minutes can resume.')
        db.query(Repository).filter(Repository.id == batch.repository_id).with_for_update().one()
        other = db.query(RemediationBatch).filter(RemediationBatch.repository_id == batch.repository_id,
            RemediationBatch.id != batch.id, RemediationBatch.status.in_(['QUEUED', 'RUNNING', 'PAUSING'])).first()
        if other: raise HTTPException(409, detail='Another batch is active.')
        batch.status = 'QUEUED'; batch.message = 'Resuming from saved checkpoint.'
    else: raise HTTPException(422, detail='Use pause or resume.')
    db.commit()
    if action == 'resume': dispatch(batch.id)
    db.refresh(batch)
    return _batch_response(batch)


@router.post('/patches/{patch_id}/revoke')
def revoke_patch(patch_id: UUID, body: PatchDecision, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        patch, finding = service.get_owned_patch(db, patch_id, current_user, lock=True)
        if patch.patch_sha256 != body.patch_sha256 or patch.status not in {'APPROVED', 'INCONCLUSIVE', 'VERIFIED'}:
            raise RemediationError(409, 'INVALID_PATCH_STATE', 'Only the exact approved proposal can be revoked.')
        if finding.repository_id is not None:
            from app.models.repository import Repository
            db.query(Repository).filter(Repository.id == finding.repository_id).with_for_update().one()
        previous = patch.status
        patch.status = 'REJECTED'; patch.approved_by = None; patch.approved_at = None
        service._event(db, finding, current_user, 'PATCH_APPROVAL_REVOKED', patch=patch, frm=previous,
                       to='REJECTED', details={'patch_sha256': patch.patch_sha256})
        db.commit(); db.refresh(patch)
        return _patch(patch)
    except RemediationError as error:
        db.rollback(); raise _fail(error)


@router.get('/repositories/{repository_id}/remediation-report')
def remediation_report(repository_id: UUID, format: str = 'json', db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from datetime import datetime, timezone
    from fastapi.responses import HTMLResponse
    from app.models.finding import Finding
    import html, json
    result = remediation_inventory(repository_id, db, current_user)
    result.update(generated_at=datetime.now(timezone.utc).isoformat(),
        limitations=['Proposals and syntax checks are not security verification.', 'Build, functional and dynamic verification are not run for uploaded applications.'])
    events = db.query(RemediationEvent).join(Finding, Finding.id == RemediationEvent.finding_id).filter(
        Finding.repository_id == repository_id).order_by(RemediationEvent.created_at).all()
    result['audit_history'] = [{'event': e.event_type, 'finding_id': str(e.finding_id),
        'actor_id': str(e.actor_id), 'created_at': str(e.created_at), 'details': e.details} for e in events]
    result['batches'] = list_batches(repository_id, db, current_user)
    if format == 'html':
        items_html = ''.join(f"<tr><td><span class='badge {html.escape(str(item.get('severity','')))}'>{html.escape(str(item.get('severity','')))}</span></td><td>{html.escape(str(item.get('title','')))}</td><td>{html.escape(str(item.get('cwe') or '-'))}</td><td>{html.escape(str(item.get('source_status','')))}</td><td>{html.escape(str(item.get('patch_status') or 'NO_PATCH'))}</td><td>{html.escape(str(item.get('verification_status') or 'UNVERIFIED'))}</td></tr>" for item in result.get('items', []))
        audit_html = ''.join(f"<tr><td>{html.escape(str(e.get('created_at','')))}</td><td>{html.escape(str(e.get('event','')))}</td><td>{html.escape(str(e.get('finding_id',''))[:8])}</td><td>{html.escape(json.dumps(e.get('details',{})))}</td></tr>" for e in result.get('audit_history', [])[:30])
        html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ASE Security Remediation & Audit Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 30px; color: #1e293b; background: #fff; line-height: 1.5; }}
h1, h2, h3 {{ color: #0f172a; margin-top: 24px; }}
.header {{ border-bottom: 2px solid #e2e8f0; padding-bottom: 15px; margin-bottom: 20px; }}
.stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 25px; }}
.stat-card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; text-align: center; }}
.stat-val {{ font-size: 24px; font-weight: bold; color: #3b82f6; }}
.stat-lbl {{ font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 25px; font-size: 13px; }}
th, td {{ border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; }}
th {{ background: #f1f5f9; font-weight: 600; color: #334155; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }}
.CRITICAL {{ background: #fee2e2; color: #991b1b; }}
.HIGH {{ background: #ffedd5; color: #9a3412; }}
.MEDIUM {{ background: #fef9c3; color: #854d0e; }}
.LOW {{ background: #e0f2fe; color: #075985; }}
.limitations {{ background: #fffbeb; border-left: 4px solid #f59e0b; padding: 12px 16px; margin-top: 20px; border-radius: 4px; }}
@media print {{ body {{ margin: 10mm; }} .no-print {{ display: none; }} }}
</style>
</head>
<body>
<div class="header">
  <h1>ASE Security Remediation & Audit Report</h1>
  <p><strong>Repository ID:</strong> {html.escape(str(repository_id))} | <strong>Scan ID:</strong> {html.escape(str(result.get('scan_id','')))} | <strong>Generated:</strong> {html.escape(result.get('generated_at',''))}</p>
</div>

<div class="stat-grid">
  <div class="stat-card"><div class="stat-val">{result.get('total', 0)}</div><div class="stat-lbl">Total Findings</div></div>
  <div class="stat-card"><div class="stat-val">{result.get('eligible', 0)}</div><div class="stat-lbl">Eligible For Fix</div></div>
  <div class="stat-card"><div class="stat-val">{result.get('approved', 0)}</div><div class="stat-lbl">Approved Patches</div></div>
  <div class="stat-card"><div class="stat-val">{result.get('unsupported', 0)}</div><div class="stat-lbl">Manual / Unsupported</div></div>
</div>

<h2>Findings & Remediation Status</h2>
<table>
  <thead>
    <tr><th>Severity</th><th>Title</th><th>CWE</th><th>Source Status</th><th>Patch Status</th><th>Verification</th></tr>
  </thead>
  <tbody>
    {items_html}
  </tbody>
</table>

<h2>Audit Trail (Recent Actions)</h2>
<table>
  <thead>
    <tr><th>Timestamp</th><th>Action</th><th>Finding</th><th>Details</th></tr>
  </thead>
  <tbody>
    {audit_html if audit_html else "<tr><td colspan='4'>No audit events recorded.</td></tr>"}
  </tbody>
</table>

<div class="limitations">
  <h3>Evaluation & Limitations</h3>
  <ul>
    <li>Syntax validation verifies grammar only; it is not proof of a behavioral or functional security fix.</li>
    <li>Build, functional, and dynamic verifications are bounded to isolated execution environments.</li>
    <li>Credentials and private artifacts are excluded from exported project archives.</li>
  </ul>
</div>
</body>
</html>"""
        return HTMLResponse(html_doc, headers={'Content-Security-Policy': "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'", 'Cache-Control': 'no-store'})
    if format != 'json': raise HTTPException(422, detail='Use json or html.')
    return result


@router.get('/repositories/{repository_id}/remediation-diff')
def project_diff(repository_id: UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Review consolidated approved edits without creating or modifying project files."""
    import difflib
    from collections import defaultdict
    from app.api.repositories import owned_repository
    from app.models.finding import Finding
    from app.remediation.export import _patched_bytes, apply_edits, ExportRejected
    from app.remediation.languages import syntax_check
    from app.remediation.patching import PatchRejected
    repo = owned_repository(db, repository_id, current_user)
    rows = db.query(PatchProposal, Finding).join(Finding, Finding.id == PatchProposal.finding_id).filter(
        Finding.repository_id == repo.id, Finding.scan_id == repo.latest_analysis_job_id,
        PatchProposal.status.in_(['APPROVED', 'INCONCLUSIVE', 'VERIFIED'])).all()
    groups, sources = defaultdict(list), {}
    try:
        for proposal, finding in rows:
            source = locator_for(finding).locate(db, finding, current_user.id)
            _patched_bytes(source, proposal)
            groups[source.path].extend(proposal.edits); sources[source.path] = source
        files = []
        for path, edits in groups.items():
            source = sources[path]
            content = apply_edits(source.lines, edits).decode('utf-8')
            check = syntax_check(path, content)
            if check['status'] != 'PASS': raise ExportRejected('Combined approved edits do not pass syntax validation.')
            diff = ''.join(difflib.unified_diff([line+'\n' for line in source.lines], content.splitlines(keepends=True), fromfile='a/'+path, tofile='b/'+path))
            files.append({'path': path, 'diff': diff, 'syntax': check})
        return {'repository_id': str(repo.id), 'files': files, 'status': 'APPROVED_UNVERIFIED'}
    except (SourceUnavailable, ExportRejected, PatchRejected, ValueError):
        raise HTTPException(409, detail='Approved edits conflict or source changed. Review individual proposals.') from None


@router.get('/repositories/{repository_id}/remediation-conflicts')
def get_remediation_conflicts(repository_id: UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Analyze all approved proposals for line overlaps and semantic conflicts."""
    from app.api.repositories import owned_repository
    from app.models.finding import Finding
    from app.remediation.conflicts import detect_conflicts
    repo = owned_repository(db, repository_id, current_user)
    rows = db.query(PatchProposal, Finding).join(Finding, Finding.id == PatchProposal.finding_id).filter(
        Finding.repository_id == repo.id, Finding.scan_id == repo.latest_analysis_job_id,
        PatchProposal.status.in_(['APPROVED', 'INCONCLUSIVE', 'VERIFIED'])).all()
    proposals = [p for p, _ in rows]
    sources = {}
    for proposal, finding in rows:
        try:
            source = locator_for(finding).locate(db, finding, current_user.id)
            sources[source.path] = source
        except Exception:
            pass
    report = detect_conflicts(proposals, sources)
    report['repository_id'] = str(repo.id)
    report['approved_count'] = len(proposals)
    return report


@router.post('/repositories/{repository_id}/verify')
def verify_repository_fixes(repository_id: UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Check reviewed hashes, combined syntax and trusted static rules; never execute uploaded code."""
    from app.api.repositories import owned_repository
    from app.models.finding import Finding
    from app.repositories.storage import repository_directory
    from app.config.settings import settings
    from app.verification.runner import verify_project_changes
    from app.remediation.patching import PatchRejected
    from app.remediation.source import locator_for

    repo = owned_repository(db, repository_id, current_user)
    source_dir = repository_directory(settings.SCAN_WORKSPACE_ROOT, repo.id) / 'source'
    if not source_dir.is_dir():
        raise HTTPException(404, detail="Original repository source directory is unavailable.")

    rows = db.query(PatchProposal, Finding).join(Finding, Finding.id == PatchProposal.finding_id).filter(
        Finding.repository_id == repo.id, Finding.scan_id == repo.latest_analysis_job_id,
        PatchProposal.status.in_(['APPROVED', 'INCONCLUSIVE', 'VERIFIED'])).all()

    if not rows:
        raise HTTPException(409, detail="No approved patches for the latest scan. Generate, review and approve changes first.")
    if any(p.approved_by != current_user.id or not p.approved_at for p, _ in rows):
        raise HTTPException(409, detail="Every checked patch must have a current approval by this user.")
    proposals = [p for p, _ in rows]
    findings = [f for _, f in rows]
    sources = {}
    for p, f in rows:
        try:
            src = locator_for(f).locate(db, f, current_user.id)
            sources[src.path] = src
        except Exception:
            pass

    try:
        result = verify_project_changes(source_dir, proposals, sources, findings)
    except (ValueError, SourceUnavailable, PatchRejected) as exc:
        raise HTTPException(409, detail=str(exc)) from None

    # Update patch proposal verification_status based on runner results
    for eval_item in result.get("finding_evaluations", []):
        fid = eval_item["finding_id"]
        status = eval_item["status"]
        for p in proposals:
            if str(p.finding_id) == fid:
                p.verification_status = status
                db.add(p)

    db.commit()
    return result


