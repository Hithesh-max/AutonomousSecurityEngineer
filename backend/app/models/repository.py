from sqlalchemy import Column, String, ForeignKey, Integer, BigInteger, DateTime, CheckConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship
from app.models.base import Base


class Repository(Base):
    __tablename__ = 'repositories'
    __table_args__ = (
        CheckConstraint("source_type = 'ZIP'", name='ck_repositories_source_type'),
        CheckConstraint("ingestion_status IN ('QUEUED', 'RUNNING', 'READY', 'FAILED')", name='ck_repositories_ingestion_status'),
    )
    project_id = Column(ForeignKey('projects.id'), nullable=False, index=True)
    target_id = Column(ForeignKey('targets.id'), nullable=False, index=True)
    uploaded_by = Column(ForeignKey('users.id'), nullable=False)
    name = Column(String(120), nullable=False)
    source_type = Column(String(16), nullable=False, default='ZIP')
    ingestion_status = Column(String(16), nullable=False, default='QUEUED')
    analysis_status = Column(String(24), nullable=False, default='NOT_STARTED')
    archive_sha256 = Column(String(64), nullable=False)
    upload_bytes = Column(BigInteger, nullable=False)
    extracted_bytes = Column(BigInteger, nullable=True)
    file_count = Column(Integer, nullable=True)
    source_authorized_at = Column(DateTime(timezone=True), nullable=False)
    ingested_at = Column(DateTime(timezone=True), nullable=True)
    failure_code = Column(String(64), nullable=True)
    failure_message = Column(String(256), nullable=True)
    latest_analysis_job_id = Column(UUID(as_uuid=True), ForeignKey('scan_jobs.id', name='fk_repository_latest_analysis'), nullable=True)
    intelligence = Column(JSONB, nullable=True)
    project = relationship('Project')
    target = relationship('Target')
    uploader = relationship('User')
    jobs = relationship('ScanJob', back_populates='repository', foreign_keys='ScanJob.repository_id')
