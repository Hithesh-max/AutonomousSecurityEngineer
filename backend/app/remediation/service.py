"""Orchestrates analysis and patch *proposal*. Nothing here modifies any project file or runs model output."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.ai import factory
from app.ai.errors import AIError, AIOutputInvalid
from app.ai.prompts import build_analysis_prompt, build_patch_prompt
from app.ai.schemas import ModelAnalysis, ModelPatch
from app.config.settings import settings
from app.models.finding import Finding
from app.models.project import Project
from app.models.remediation import AIAnalysis, PatchProposal, RemediationEvent
from app.remediation import states
from app.remediation.patching import PatchRejected, validate_and_render
from app.remediation.source import SourceContext, SourceUnavailable, locator_for
from app.remediation.strategies import GUIDANCE, family_for


class RemediationError(Exception):
    def __init__(self, status: int, code: str, message: str, extra: dict | None = None):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra or {}


def get_owned_finding(db: Session, finding_id, user) -> Finding:
    finding = (db.query(Finding).join(Project, Project.id == Finding.project_id)
               .filter(Finding.id == finding_id, Project.owner_id == user.id).first())
    if not finding:  # 404 for both missing and foreign findings so ids cannot be probed
        raise RemediationError(404, "FINDING_NOT_FOUND", "Finding not found.")
    return finding


def _event(db, finding, actor, event_type, *, analysis=None, patch=None, frm=None, to=None, details=None):
    db.add(RemediationEvent(finding_id=finding.id, analysis_id=analysis.id if analysis else None,
                            patch_id=patch.id if patch else None, actor_id=actor.id, event_type=event_type,
                            from_state=frm, to_state=to, details=details))


def _begin(db: Session, finding: Finding, user, kind: str, acknowledged: bool):
    """Shared preflight: provider configured, consent given, rate limit ok, no concurrent run for this finding."""
    try:
        provider = factory.get_provider()
    except AIError as error:
        raise RemediationError(error.http_status, error.code, error.message) from None
    if provider.is_external and not acknowledged:
        raise RemediationError(400, "EXTERNAL_TRANSMISSION_NOT_CONFIRMED",
                               "Confirm that redacted finding data and the relevant source snippet may be sent to the external AI provider.")
    account_locked = db.execute(text("SELECT pg_try_advisory_xact_lock(hashtext(:k))"),
                                {"k": f"ase-ai-account:{user.id}"}).scalar()
    if not account_locked:
        raise RemediationError(409, "AI_JOB_IN_PROGRESS", "Another AI request for this account is running. Retry when it finishes.")
    since = datetime.utcnow() - timedelta(hours=1)
    used = (db.query(RemediationEvent).filter(RemediationEvent.actor_id == user.id,
            RemediationEvent.event_type.in_(["ANALYSIS_REQUESTED", "PATCH_REQUESTED"]),
            RemediationEvent.created_at >= since).count())
    if used >= settings.AI_MAX_REQUESTS_PER_HOUR:
        raise RemediationError(429, "AI_RATE_LIMITED", "Hourly AI request limit reached. Try again later.")
    locked = db.execute(text("SELECT pg_try_advisory_xact_lock(hashtext(:k))"), {"k": f"ase-ai:{finding.id}"}).scalar()
    if not locked:
        raise RemediationError(409, "AI_JOB_IN_PROGRESS", "An AI request for this finding is already running.")
    _event(db, finding, user, f"{kind}_REQUESTED", details={"provider": provider.name, "model": provider.model,
           "external": provider.is_external, "consent": acknowledged})
    db.flush()
    return provider


def _parse(model_cls, raw: str):
    try:
        return model_cls.model_validate(json.loads(raw))
    except (json.JSONDecodeError, ValidationError, TypeError):
        raise AIOutputInvalid("The AI response did not match the required structure and was discarded.") from None


def _load_source(db, finding, user) -> SourceContext | None:
    try:
        return locator_for(finding).locate(db, finding, user.id)
    except SourceUnavailable as error:
        if error.code in {"SOURCE_MAPPING_STALE", "SOURCE_CHANGED"}:
            raise RemediationError(409, error.code, error.message) from None
        return None


def analyze(db: Session, user, finding_id, acknowledged: bool) -> AIAnalysis:
    finding = get_owned_finding(db, finding_id, user)
    provider = _begin(db, finding, user, "ANALYSIS", acknowledged)
    source = _load_source(db, finding, user)
    family = family_for(finding.tool_rule_id)
    system, prompt = build_analysis_prompt(finding, source, GUIDANCE.get(family), settings.AI_MAX_CONTEXT_CHARS)
    record = AIAnalysis(finding_id=finding.id, project_id=finding.project_id, requested_by=user.id, status="FAILED",
                        provider=provider.name, model=provider.model, is_mock=provider.is_mock,
                        external_transmission_acknowledged=bool(acknowledged and provider.is_external),
                        source_kind=source.kind if source else None, source_path=source.path if source else None,
                        source_sha256=source.sha256 if source else None)
    try:
        response = provider.complete_json(system=system, user=prompt, max_output_tokens=settings.AI_MAX_OUTPUT_TOKENS)
        parsed = _parse(ModelAnalysis, response.text)
    except AIError as error:
        record.error_code, record.error_message = error.code, error.message[:300]
        db.add(record); db.flush()
        _event(db, finding, user, "ANALYSIS_FAILED", analysis=record, details={"code": error.code})
        db.commit()
        raise RemediationError(error.http_status, error.code, error.message, {"analysis_id": str(record.id)}) from None
    limitations = list(parsed.limitations)
    if source is None:
        limitations.append("No verified source code was available, so no code-level analysis or patch is possible.")
    result = parsed.model_dump()
    result["limitations"] = limitations
    result.update({
        "finding_id": str(finding.id), "analysis_status": "COMPLETED", "scanner_cwe": finding.cwe,
        "affected_location": ({"kind": source.kind, "path": source.path, "start_line": source.start_line,
                               "end_line": source.end_line, "highlight_line": source.highlight_line,
                               "source_sha256": source.sha256} if source else None),
        "model_information": {"provider": provider.name, "model": response.model, "is_mock": provider.is_mock,
                              "ai_generated": True, "label": "AI-generated, unverified"}})
    record.status, record.result = "COMPLETED", result
    record.prompt_tokens, record.completion_tokens, record.latency_ms = (
        response.prompt_tokens, response.completion_tokens, response.latency_ms)
    db.add(record); db.flush()
    _event(db, finding, user, "ANALYSIS_COMPLETED", analysis=record,
           details={"model": response.model, "source_sha256": record.source_sha256})
    db.commit(); db.refresh(record)
    return record


def generate_patch(db: Session, user, finding_id, analysis_id, acknowledged: bool) -> PatchProposal:
    finding = get_owned_finding(db, finding_id, user)
    query = db.query(AIAnalysis).filter(AIAnalysis.finding_id == finding.id, AIAnalysis.status == "COMPLETED")
    analysis = (query.filter(AIAnalysis.id == analysis_id).first() if analysis_id
                else query.order_by(AIAnalysis.created_at.desc()).first())
    if not analysis:
        raise RemediationError(409, "ANALYSIS_REQUIRED", "Run Analyze Vulnerability before generating a patch.")
    provider = _begin(db, finding, user, "PATCH", acknowledged)
    source = _load_source(db, finding, user)
    if source is None:
        raise RemediationError(422, "SOURCE_UNAVAILABLE", "No verified source is available; ASE will not fabricate a patch.")
    if analysis.source_sha256 != source.sha256:
        raise RemediationError(409, "ANALYSIS_STALE", "Source changed since the analysis; run the analysis again.")
    family = family_for(finding.tool_rule_id)
    system, prompt = build_patch_prompt(finding, source, analysis.result or {}, GUIDANCE.get(family),
                                        settings.AI_MAX_CONTEXT_CHARS)
    try:
        response = provider.complete_json(system=system, user=prompt, max_output_tokens=settings.AI_MAX_OUTPUT_TOKENS)
        parsed = _parse(ModelPatch, response.text)
        validated = validate_and_render(source, parsed)
    except (AIError, PatchRejected) as error:
        code = error.code
        _event(db, finding, user, "PATCH_REJECTED_BY_VALIDATION" if isinstance(error, PatchRejected) else "PATCH_FAILED",
               analysis=analysis, details={"code": code})
        db.commit()
        status = 422 if isinstance(error, PatchRejected) else error.http_status
        raise RemediationError(status, code, error.message) from None

    for old in db.query(PatchProposal).filter(PatchProposal.finding_id == finding.id,
                                              PatchProposal.status == "PATCH_PROPOSED").all():
        states.require_transition(old.status, "SUPERSEDED")
        _event(db, finding, user, "PATCH_SUPERSEDED", patch=old, frm=old.status, to="SUPERSEDED")
        old.status = "SUPERSEDED"
    patch = PatchProposal(
        finding_id=finding.id, analysis_id=analysis.id, project_id=finding.project_id, requested_by=user.id,
        status="PATCH_PROPOSED", provider=provider.name, model=response.model, is_mock=provider.is_mock,
        source_kind=source.kind, source_path=source.path, source_sha256=source.sha256,
        patched_sha256=validated.patched_sha256, patch_sha256=validated.patch_sha256,
        unified_diff=validated.unified_diff, edits=validated.edits, explanation=parsed.explanation,
        behavior_notes=parsed.behavior_notes, limitations=parsed.limitations, static_checks=validated.checks,
        prompt_tokens=response.prompt_tokens, completion_tokens=response.completion_tokens,
        latency_ms=response.latency_ms, verification_status="NOT_VERIFIED")
    db.add(patch); db.flush()
    _event(db, finding, user, "PATCH_PROPOSED", analysis=analysis, patch=patch, to="PATCH_PROPOSED",
           details={"patch_sha256": patch.patch_sha256, "source_sha256": patch.source_sha256})
    db.commit(); db.refresh(patch)
    return patch


def get_owned_patch(db: Session, patch_id, user, lock=False):
    query = db.query(PatchProposal).filter(PatchProposal.id == patch_id)
    if lock:
        query = query.with_for_update()
    patch = query.first()
    if patch is None:
        raise RemediationError(404, "PATCH_NOT_FOUND", "Patch not found.")
    finding = get_owned_finding(db, patch.finding_id, user)
    return patch, finding


def decide_patch(db: Session, user, patch_id, decision: str, expected_hash: str):
    if decision not in ("APPROVED", "REJECTED"):
        raise RemediationError(422, "INVALID_DECISION", "Unsupported decision.")
    patch, finding = get_owned_patch(db, patch_id, user, lock=True)
    if finding.repository_id is not None:
        from app.models.repository import Repository
        db.query(Repository).filter(Repository.id == finding.repository_id).with_for_update().one()
    if patch.status != "PATCH_PROPOSED":
        raise RemediationError(409, "INVALID_PATCH_STATE", "Patch has already been decided or superseded.")
    if patch.patch_sha256 != expected_hash:
        raise RemediationError(409, "PATCH_HASH_MISMATCH", "Proposal has changed; review the latest diff.")
    if decision == "REJECTED":
        states.require_transition(patch.status, decision)
        previous = patch.status
        patch.status = decision
        _event(db, finding, user, "PATCH_REJECTED", patch=patch, frm=previous, to=decision,
               details={"patch_sha256": patch.patch_sha256})
        db.commit(); db.refresh(patch)
        return patch
    source = _load_source(db, finding, user)
    if source is None or source.sha256 != patch.source_sha256:
        raise RemediationError(409, "SOURCE_STALE", "Source changed; generate a fresh patch.")
    from app.ai.schemas import ModelPatch
    from app.remediation.patching import validate_and_render
    try:
        proposed = ModelPatch.model_validate({"edits": patch.edits, "explanation": patch.explanation,
                                               "behavior_notes": patch.behavior_notes or "",
                                               "limitations": patch.limitations or []})
        validated = validate_and_render(source, proposed)
    except Exception:
        raise RemediationError(409, "PATCH_INVALID", "Stored proposal no longer validates.") from None
    if validated.patch_sha256 != patch.patch_sha256 or validated.patched_sha256 != patch.patched_sha256:
        raise RemediationError(409, "PATCH_HASH_MISMATCH", "Stored patch integrity check failed.")
    if decision == "APPROVED" and source.kind == "MANAGED_REPOSITORY":
        peers = db.query(PatchProposal).filter(PatchProposal.project_id == patch.project_id,
            PatchProposal.source_path == patch.source_path, PatchProposal.id != patch.id,
            PatchProposal.status.in_(["APPROVED", "INCONCLUSIVE", "VERIFIED"])).all()
        for peer in peers:
            peer_finding = db.query(Finding).filter(Finding.id == peer.finding_id).first()
            if not peer_finding or peer_finding.repository_id != finding.repository_id or peer_finding.scan_id != finding.scan_id:
                continue
            if peer.source_sha256 != patch.source_sha256:
                raise RemediationError(409, "PATCH_CONFLICT", "An approved proposal targets a different source version.")
            if any(a['start_line'] <= b['end_line'] and b['start_line'] <= a['end_line']
                   for a in patch.edits for b in peer.edits):
                raise RemediationError(409, "PATCH_CONFLICT", "This proposal overlaps an approved edit. Revoke that approval or generate a consolidated fix.")
    states.require_transition(patch.status, decision)
    previous = patch.status
    patch.status = decision
    if decision == "APPROVED":
        patch.approved_by = user.id
        patch.approved_at = datetime.now(timezone.utc)
    _event(db, finding, user, "PATCH_" + decision, patch=patch, frm=previous, to=decision,
           details={"patch_sha256": patch.patch_sha256})
    db.commit(); db.refresh(patch)
    return patch


def verify_approved_patch(db: Session, user, patch_id):
    patch, finding = get_owned_patch(db, patch_id, user, lock=True)
    if patch.status != "APPROVED":
        raise RemediationError(409, "INVALID_PATCH_STATE", "Only approved patches may be verified.")
    source = _load_source(db, finding, user)
    if source is None or source.sha256 != patch.source_sha256:
        raise RemediationError(409, "SOURCE_STALE", "Source changed since approval.")
    from app.remediation.verification import isolated_verify
    from app.remediation.patching import PatchRejected
    try:
        result = isolated_verify(source, patch)
    except (ValueError, PatchRejected) as exc:
        raise RemediationError(409, "PATCH_VERIFICATION_REJECTED", str(exc)[:250]) from None
    # Record the actual workflow transitions, including the limited verification scope.
    for next_state, label in (("APPLYING", "PATCH_APPLYING_TO_ISOLATED_COPY"),
                              ("APPLIED", "PATCH_APPLIED_TO_ISOLATED_COPY"),
                              ("VERIFYING", "PATCH_SYNTAX_CHECK_STARTED"),
                              ("INCONCLUSIVE", "PATCH_ISOLATED_SYNTAX_CHECK")):
        previous = patch.status
        states.require_transition(previous, next_state)
        patch.status = next_state
        _event(db, finding, user, label, patch=patch, frm=previous, to=next_state,
               details=result if next_state == "INCONCLUSIVE" else {"patch_sha256": patch.patch_sha256})
    patch.verification_status = "INCONCLUSIVE"
    db.commit(); db.refresh(patch)
    return result
