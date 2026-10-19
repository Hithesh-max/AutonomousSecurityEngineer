"""API routes for supply chain inventory, SBOM generation, and dependency upgrades."""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.api.repositories import owned_repository
from app.config.database import get_db
from app.config.settings import settings
from app.models.user import User
from app.models.repository import Repository
from app.models.finding import Finding
from app.models.remediation import PatchProposal
from app.repositories.storage import repository_directory
from app.repositories.intelligence import parse_manifest
from app.supply_chain.sbom import generate_cyclonedx_sbom, generate_spdx_sbom
from app.supply_chain.advisories import lookup_advisories
from app.supply_chain.upgrades import propose_dependency_upgrade
from app.remediation.source import locator_for, SourceUnavailable
from app.remediation.repository_source import safe_source_path

router = APIRouter()


class UpgradeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    manifest_path: str
    package_name: str
    target_version: str


@router.get("/repositories/{repository_id}/sbom")
def get_sbom(
    repository_id: UUID,
    format: str = Query("cyclonedx", pattern="^(cyclonedx|spdx)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate and export a standard SBOM (CycloneDX v1.5 JSON or SPDX 2.3 JSON)."""
    repo = owned_repository(db, repository_id, current_user)
    source_dir = repository_directory(settings.SCAN_WORKSPACE_ROOT, repo.id) / "source"
    if not source_dir.is_dir():
        raise HTTPException(404, detail="Repository source files are unavailable.")

    # Extract all dependencies across manifests
    all_deps = []
    manifest_names = ["requirements.txt", "package.json", "package-lock.json", "pyproject.toml", "Pipfile"]
    for mname in manifest_names:
        for mpath in source_dir.rglob(mname):
            try:
                rel = str(mpath.relative_to(source_dir)).replace("\\", "/")
                content = mpath.read_text(encoding="utf-8", errors="replace")
                deps = parse_manifest(rel, content)
                all_deps.extend(deps)
            except Exception:
                pass

    if format == "spdx":
        return generate_spdx_sbom(repo.name, str(repo.id), all_deps)
    return generate_cyclonedx_sbom(repo.name, str(repo.id), all_deps, str(repo.latest_analysis_job_id or ""))


@router.get("/repositories/{repository_id}/dependencies")
def get_dependencies_and_advisories(
    repository_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve complete dependency inventory with direct/transitive relationships and advisory status."""
    repo = owned_repository(db, repository_id, current_user)
    source_dir = repository_directory(settings.SCAN_WORKSPACE_ROOT, repo.id) / "source"
    if not source_dir.is_dir():
        raise HTTPException(404, detail="Repository source files are unavailable.")

    all_deps = []
    manifest_names = ["requirements.txt", "package.json", "package-lock.json", "pyproject.toml", "Pipfile"]
    for mname in manifest_names:
        for mpath in source_dir.rglob(mname):
            try:
                rel = str(mpath.relative_to(source_dir)).replace("\\", "/")
                content = mpath.read_text(encoding="utf-8", errors="replace")
                deps = parse_manifest(rel, content)
                all_deps.extend(deps)
            except Exception:
                pass

    advisory_report = lookup_advisories(all_deps, upstream_online=True)
    return {
        "repository_id": str(repo.id),
        "total_dependencies": len(all_deps),
        "advisory_report": advisory_report
    }


@router.post("/repositories/{repository_id}/dependency-upgrade", status_code=201)
def upgrade_dependency(
    repository_id: UUID,
    body: UpgradeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Propose an automated dependency upgrade with manifest consistency for review and approval."""
    repo = owned_repository(db, repository_id, current_user)
    source_dir = repository_directory(settings.SCAN_WORKSPACE_ROOT, repo.id) / "source"
    try:
        manifest_file = safe_source_path(source_dir, body.manifest_path)
    except (SourceUnavailable, ValueError):
        raise HTTPException(400, detail="Manifest path is invalid or outside this repository.") from None
    if manifest_file.name not in {"requirements.txt", "package.json"}:
        raise HTTPException(400, detail="Upgrade previews support requirements.txt and package.json only.")

    if not manifest_file.is_file():
        raise HTTPException(404, detail=f"Manifest file '{body.manifest_path}' not found in repository.")

    content = manifest_file.read_text(encoding="utf-8", errors="replace")
    try:
        proposal_data = propose_dependency_upgrade(
            body.manifest_path,
            content,
            body.package_name,
            body.target_version
        )
    except ValueError as e:
        raise HTTPException(400, detail=str(e))

    proposal_data["status"] = "DRAFT_NOT_SAVED"
    return proposal_data
