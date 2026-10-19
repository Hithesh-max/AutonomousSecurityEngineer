"""Register every ORM model for API, CLI, Alembic, and fresh worker processes."""
from app.models.user import User
from app.models.project import Project, Target, ScanJob
from app.models.finding import Finding
from app.models.repository import Repository
from app.models.remediation import AIAnalysis, PatchProposal, RemediationEvent, RemediationBatch
from app.models.secure_share import SecureShare

__all__ = ["User", "Project", "Target", "ScanJob", "Finding", "Repository", "AIAnalysis", "PatchProposal", "RemediationEvent", "SecureShare"]
