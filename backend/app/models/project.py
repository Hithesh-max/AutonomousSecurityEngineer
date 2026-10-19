from sqlalchemy import Column, String, ForeignKey, JSON, Boolean, DateTime, Index
from sqlalchemy.orm import relationship
from app.models.base import Base
from sqlalchemy.dialects.postgresql import UUID

class Project(Base):
    __tablename__ = "projects"
    name = Column(String, index=True)
    description = Column(String, nullable=True)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True) # Will make non-nullable after migration
    
    # Relationships
    targets = relationship("Target", back_populates="project")
    findings = relationship("Finding", back_populates="project")
    owner = relationship("User")

class Target(Base):
    __tablename__ = "targets"
    project_id = Column(ForeignKey("projects.id"))
    name = Column(String)
    url = Column(String)
    repo_url = Column(String, nullable=True)
    
    # Target Authorization Fields
    authorization_status = Column(String, default="PENDING") # PENDING, APPROVED, REJECTED
    explicit_scope = Column(String, nullable=True) # e.g., "api.example.com/*", "frontend only"
    is_active = Column(Boolean, default=True)
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    approval_timestamp = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    project = relationship("Project", back_populates="targets")
    scans = relationship("ScanJob", back_populates="target")
    approver = relationship("User")

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (Index("ix_scan_jobs_status_created_at", "status", "created_at"),)
    target_id = Column(ForeignKey("targets.id"))
    repository_id = Column(ForeignKey("repositories.id"), nullable=True, index=True)
    requesting_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    celery_task_id = Column(String, nullable=True)
    
    job_type = Column(String, default="SECURITY_SCAN") # DIAGNOSTIC, SECURITY_SCAN
    status = Column(String, default="QUEUED") # QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED
    current_stage = Column(String, default="INITIALIZING")
    message = Column(String, nullable=True)
    
    scan_profile = Column(String, default="FULL_LAB_ACTIVE")
    result_summary = Column(JSON, nullable=True)
    failure_code = Column(String, nullable=True)
    failure_message = Column(String, nullable=True)
    
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    
    target = relationship("Target", back_populates="scans")
    requesting_user = relationship("User")
    repository = relationship("Repository", back_populates="jobs", foreign_keys=[repository_id])
