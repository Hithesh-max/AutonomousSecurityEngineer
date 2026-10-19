from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict


class RepositoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    project_id: UUID
    target_id: UUID
    name: str
    source_type: str
    ingestion_status: str
    analysis_status: str
    latest_analysis_job_id: UUID | None = None
    intelligence: dict | None = None
    archive_sha256: str
    upload_bytes: int
    extracted_bytes: int | None = None
    file_count: int | None = None
    created_at: datetime
    source_authorized_at: datetime
    ingested_at: datetime | None = None
    failure_code: str | None = None
    failure_message: str | None = None


class RepositoryUploadResponse(BaseModel):
    repository_id: UUID
    job_id: UUID
    message: str
