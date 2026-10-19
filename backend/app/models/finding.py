from sqlalchemy import Column, String, ForeignKey, JSON, Float, UniqueConstraint
from sqlalchemy.orm import relationship
from app.models.base import Base
from sqlalchemy.dialects.postgresql import JSONB

class Finding(Base):
    __tablename__ = "findings"
    
    __table_args__ = (UniqueConstraint('scan_id', 'fingerprint', name='uq_findings_scan_fingerprint'),)
    scan_id = Column(ForeignKey('scan_jobs.id'), nullable=True, index=True)
    repository_id = Column(ForeignKey('repositories.id'), nullable=True, index=True)
    fingerprint = Column(String(64), nullable=True)
    description = Column(String, nullable=True)
    source = Column(String(32), nullable=True)
    tool_rule_id = Column(String(255), nullable=True)
    project_id = Column(ForeignKey("projects.id"))
    title = Column(String)
    category = Column(String) # e.g., BROKEN_ACCESS_CONTROL
    subcategory = Column(String, nullable=True) # e.g., IDOR
    severity = Column(String) # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence = Column(String) # HIGH, MEDIUM, LOW
    status = Column(String, default="OPEN") # OPEN, CONFIRMED, FIXED, VERIFIED_FIXED, FALSE_POSITIVE
    
    source_tools = Column(JSON) # e.g., ["zap", "semgrep"]
    
    # Context
    asset = Column(JSONB, nullable=True) # {host, port}
    endpoint = Column(JSONB, nullable=True) # {method, path}
    parameter = Column(String, nullable=True)
    source_location = Column(JSONB, nullable=True) # {file, function, start_line, end_line}
    
    evidence = Column(JSONB, nullable=True)
    cwe = Column(String, nullable=True)
    cvss = Column(Float, nullable=True)
    
    # AI Enrichment
    root_cause = Column(String, nullable=True)
    impact = Column(String, nullable=True)
    remediation_plan = Column(String, nullable=True)
    
    verification_status = Column(String, default="NOT_VERIFIED") # NOT_VERIFIED, VERIFIED, REGRESSION
    
    project = relationship("Project", back_populates="findings")
