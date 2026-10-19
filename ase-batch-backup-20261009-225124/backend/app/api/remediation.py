"""Stage 3 AI remediation API (analysis + patch proposal). Approval/apply/verify arrive in later phases."""
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
                             PatchProposal.status.in_(['APPROVED', 'INCONCLUSIVE', 'VERIFIED']))
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
        return {'path': source.path, 'content': corrected.decode('utf-8'),
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
        except SourceUnavailable as exc:
            eligible, reason = False, exc.message
            source_path = (finding.source_location or {}).get('file')
        patch = latest_patch.get(finding.id)
        analysis = latest_analysis.get(finding.id)
        items.append({
            'finding_id': str(finding.id), 'title': finding.title,
            'severity': finding.severity, 'source': finding.source,
            'source_path': source_path, 'eligible': eligible,
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
