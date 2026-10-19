from pydantic import BaseModel, ConfigDict, model_validator
from typing import Optional, List, Any, Dict
from uuid import UUID
from datetime import datetime
from app.utils.redaction import redact_finding_context

# --- Project Schemas ---
class ProjectBase(BaseModel):
    name: str
    description: Optional[str] = None

class ProjectCreate(ProjectBase):
    pass

class ProjectResponse(ProjectBase):
    id: UUID
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

# --- Target Schemas ---
class TargetBase(BaseModel):
    name: str
    url: str
    repo_url: Optional[str] = None
    project_id: UUID

class TargetCreate(TargetBase):
    pass

class TargetResponse(TargetBase):
    id: UUID
    authorization_status: str
    explicit_scope: Optional[str] = None
    is_active: Optional[bool] = None
    approved_by: Optional[UUID] = None
    
    model_config = ConfigDict(from_attributes=True)

# --- Job Schemas ---
class JobResponse(BaseModel):
    id: UUID
    repository_id: Optional[UUID] = None
    target_id: Optional[UUID] = None
    job_type: str
    status: str
    current_stage: str
    message: Optional[str] = None
    scan_profile: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    failure_code: Optional[str] = None
    failure_message: Optional[str] = None
    created_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)

class JobSubmitResponse(BaseModel):
    message: str
    job_id: UUID

# --- Finding Schemas ---
class FindingBase(BaseModel):
    title: str
    category: Optional[str] = None
    severity: str
    status: str
    project_id: UUID

class FindingResponse(FindingBase):
    id: UUID
    scan_id: Optional[UUID] = None
    repository_id: Optional[UUID] = None
    description: Optional[str] = None
    source: Optional[str] = None
    tool_rule_id: Optional[str] = None
    cwe: Optional[str] = None
    parameter: Optional[str] = None
    confidence: Optional[str] = None
    source_tools: Optional[List[str]] = []
    asset: Optional[Dict] = None
    endpoint: Optional[Dict] = None
    source_location: Optional[Dict] = None
    evidence: Optional[Dict] = None
    remediation_plan: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode='after')
    def redact_secrets(self) -> 'FindingResponse':
        # Apply redaction to evidence and source_location
        if self.evidence or self.source_location:
            data = {"evidence": self.evidence, "source_location": self.source_location}
            redacted = redact_finding_context(data)
            self.evidence = redacted.get("evidence")
            self.source_location = redacted.get("source_location")
        return self
