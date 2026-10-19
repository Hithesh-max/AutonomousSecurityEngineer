from sqlalchemy import Boolean, CheckConstraint, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.models.base import Base
from app.remediation.states import PATCH_STATES


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"
    __table_args__ = (CheckConstraint("status IN ('COMPLETED', 'FAILED')", name="ck_ai_analyses_status"),
                      Index("ix_ai_analyses_finding_created", "finding_id", "created_at"))
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False, index=True)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False, index=True)
    requested_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    status = Column(String(16), nullable=False)
    provider = Column(String(32), nullable=False)
    model = Column(String(64), nullable=False)
    is_mock = Column(Boolean, nullable=False, default=False)
    external_transmission_acknowledged = Column(Boolean, nullable=False, default=False)
    source_kind = Column(String(32), nullable=True)
    source_path = Column(String(255), nullable=True)
    source_sha256 = Column(String(64), nullable=True)
    result = Column(JSONB, nullable=True)           # validated ModelAnalysis + ASE-added fields
    error_code = Column(String(64), nullable=True)
    error_message = Column(String(300), nullable=True)
    prompt_tokens = Column(Integer, nullable=True)
    completion_tokens = Column(Integer, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    finding = relationship("Finding")


class PatchProposal(Base):
    __tablename__ = "patch_proposals"
    __table_args__ = (
        CheckConstraint("status IN (" + ", ".join(f"'{s}'" for s in PATCH_STATES) + ")", name="ck_patch_proposals_status"),
        Index("ix_patch_proposals_finding_created", "finding_id", "created_at"))
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False, index=True)
    analysis_id = Column(UUID(as_uuid=True), ForeignKey("ai_analyses.id"), nullable=False)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False, index=True)
    requested_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    status = Column(String(16), nullable=False, default="PATCH_PROPOSED")
    provider = Column(String(32), nullable=False)
    model = Column(String(64), nullable=False)
    is_mock = Column(Boolean, nullable=False, default=False)
    source_kind = Column(String(32), nullable=False)
    source_path = Column(String(255), nullable=False)
    source_sha256 = Column(String(64), nullable=False)     # hash of the file the patch was built against
    patched_sha256 = Column(String(64), nullable=False)
    patch_sha256 = Column(String(64), nullable=False)      # approval (later phase) binds to this exact hash
    unified_diff = Column(Text, nullable=False)
    edits = Column(JSONB, nullable=False)
    explanation = Column(Text, nullable=False)
    behavior_notes = Column(Text, nullable=True)
    limitations = Column(JSONB, nullable=True)
    static_checks = Column(JSONB, nullable=False)
    prompt_tokens = Column(Integer, nullable=True)
    completion_tokens = Column(Integer, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)   # unused until the approval phase
    approved_at = Column(DateTime(timezone=True), nullable=True)
    verification_status = Column(String(32), nullable=False, default="NOT_VERIFIED")


class RemediationEvent(Base):
    """Append-only audit trail. Rows are never updated or deleted by application code."""
    __tablename__ = "remediation_events"
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False, index=True)
    analysis_id = Column(UUID(as_uuid=True), ForeignKey("ai_analyses.id"), nullable=True)
    patch_id = Column(UUID(as_uuid=True), ForeignKey("patch_proposals.id"), nullable=True)
    actor_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    event_type = Column(String(48), nullable=False)
    from_state = Column(String(16), nullable=True)
    to_state = Column(String(16), nullable=True)
    details = Column(JSONB, nullable=True)


class RemediationBatch(Base):
    __tablename__ = 'remediation_batches'
    __table_args__ = (CheckConstraint("status IN ('QUEUED','RUNNING','PAUSING','PAUSED','COMPLETED','FAILED')", name='ck_remediation_batch_status'),)
    repository_id = Column(UUID(as_uuid=True), ForeignKey('repositories.id'), nullable=False, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey('scan_jobs.id'), nullable=False)
    requested_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False, index=True)
    status = Column(String(16), nullable=False, default='QUEUED')
    mode = Column(String(16), nullable=False, default='PROPOSE')
    consent = Column(Boolean, nullable=False, default=False)
    items = Column(JSONB, nullable=False, default=list)
    cursor = Column(Integer, nullable=False, default=0)
    message = Column(String(300), nullable=True)
