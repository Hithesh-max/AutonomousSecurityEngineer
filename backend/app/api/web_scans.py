
from datetime import datetime, timezone
from pathlib import Path
from hashlib import sha256
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, StrictBool, model_validator
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.config.database import get_db
from app.config.settings import settings
from app.models.user import User
from app.models.project import Project, Target, ScanJob
from app.models.finding import Finding
from app.schemas.core import FindingResponse
from app.repositories.access import require_authorized_target
from app.network.scope import (
    LAB_URL, validate_lab_target, is_lab_target, resolve_and_verify_destination
)
from app.utils.validators import validate_scope_syntax
from app.workers.web_jobs import run_web_scan


router = APIRouter()


# ============================================================
# WEB SCAN REQUESTS
# ============================================================

class WebScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: Literal["SAFE", "STANDARD"] = "SAFE"
    active_testing: StrictBool = False
    active_consent: StrictBool = False

    @model_validator(mode="after")
    def validate_consent(self):
        if self.active_testing and not self.active_consent:
            raise ValueError(
                "Explicit consent is required for active testing."
            )
        return self


class DeployedTargetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    url: str
    explicit_scope: str
    ownership_declaration: str


# ============================================================
# WEB LAB CONFIGURATION
# ============================================================

@router.get("/web-scans/config")
def configuration(
    current_user: User = Depends(get_current_user)
):
    return {
        "enabled": settings.LAB_SCANNING_ENABLED,
        "lab_url": LAB_URL,
        "scope": "ase-lab",
        "profiles": ["SAFE", "STANDARD"],
        "active_testing_default": False,
    }


# ============================================================
# REGISTER LAB TARGET
# ============================================================

@router.post("/projects/{project_id}/lab-target", status_code=201)
def register_lab(
    project_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = (
        db.query(Project)
        .filter(
            Project.id == project_id,
            Project.owner_id == current_user.id,
        )
        .with_for_update()
        .first()
    )

    if not project:
        raise HTTPException(404, detail="Project not found.")

    target = (
        db.query(Target)
        .filter(
            Target.project_id == project.id,
            Target.url == LAB_URL,
        )
        .first()
    )

    if target:
        return {
            "target_id": target.id,
            "message": (
                "Existing lab target selected. "
                "Authorization is still required."
            ),
        }

    target = Target(
        project_id=project.id,
        name="ASE isolated web lab",
        url=LAB_URL,
        authorization_status="PENDING",
        is_active=True,
    )

    db.add(target)
    db.commit()
    db.refresh(target)

    return {
        "target_id": target.id,
        "message": (
            "Lab target registered. "
            "Confirm authorization before scanning."
        ),
    }


# ============================================================
# REGISTER DEPLOYED TARGET
# ============================================================

@router.post("/projects/{project_id}/deployed-target", status_code=201)
def register_deployed_target(
    project_id: UUID,
    body: DeployedTargetRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = (
        db.query(Project)
        .filter(
            Project.id == project_id,
            Project.owner_id == current_user.id,
        )
        .with_for_update()
        .first()
    )

    if not project:
        raise HTTPException(404, detail="Project not found.")

    try:
        valid_scope = validate_scope_syntax(body.explicit_scope)
    except ValueError as e:
        raise HTTPException(400, detail=f"Invalid explicit scope: {str(e)}")

    try:
        # Pre-flight SSRF check: ensures target URL can be resolved and is not targeting forbidden ranges
        resolve_and_verify_destination(body.url, valid_scope)
    except PermissionError as e:
        raise HTTPException(400, detail=f"Target rejected by SSRF protection policy: {str(e)}")

    target = Target(
        project_id=project.id,
        name=body.name.strip(),
        url=body.url.strip(),
        authorization_status="PENDING",
        explicit_scope=valid_scope,
        is_active=True,
    )

    db.add(target)
    db.commit()
    db.refresh(target)

    return {
        "target_id": target.id,
        "name": target.name,
        "url": target.url,
        "explicit_scope": target.explicit_scope,
        "authorization_status": target.authorization_status,
        "message": "Deployed target registered in PENDING status. Operator approval is required before scanning.",
    }


# ============================================================
# START WEB SCAN
# ============================================================

@router.post("/targets/{target_id}/web-scans", status_code=202)
def start_scan(
    target_id: UUID,
    body: WebScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target = (
        db.query(Target)
        .join(Project)
        .filter(
            Target.id == target_id,
            Project.owner_id == current_user.id,
        )
        .with_for_update(of=Target)
        .first()
    )

    if not target:
        raise HTTPException(404, detail="Target not found.")

    is_lab = is_lab_target(target.url)
    try:
        require_authorized_target(
            db,
            target.id,
            current_user.id,
        )
        if is_lab:
            validate_lab_target(target.url)
            if not settings.LAB_SCANNING_ENABLED:
                raise HTTPException(
                    503,
                    detail="Lab services are not enabled. Start the lab Compose configuration.",
                )
        else:
            resolve_and_verify_destination(target.url, target.explicit_scope)
    except PermissionError as e:
        raise HTTPException(403, detail=str(e)) from None

    existing = (
        db.query(ScanJob)
        .filter(
            ScanJob.target_id == target.id,
            ScanJob.job_type == "WEB_SCAN",
            ScanJob.status.in_(["QUEUED", "RUNNING"]),
        )
        .first()
    )

    if existing:
        raise HTTPException(
            409,
            detail="This target already has an active web scan.",
        )

    job_id = uuid4()
    task_id = str(uuid4())
    now = datetime.now(timezone.utc)

    summary = {
        "configuration": body.model_dump(),
        "target_url": target.url,
        "is_lab": is_lab,
        "tools": [],
        "events": [],
        "authorization": {
            "requested_by": str(current_user.id),
            "approved_by": (
                str(target.approved_by)
                if target.approved_by
                else None
            ),
            "scope": target.explicit_scope,
            "requested_at": now.isoformat(),
            "approved_at": (
                target.approval_timestamp.isoformat()
                if target.approval_timestamp
                else None
            ),
        },
        "coverage_note": (
            "Bundled lab demonstration target."
            if is_lab else
            "Authorized deployed application target. Bounded reconnaissance, crawl, passive analysis, and opt-in consent-controlled active testing."
        ),
    }

    job = ScanJob(
        id=job_id,
        target_id=target.id,
        requesting_user_id=current_user.id,
        celery_task_id=task_id,
        job_type="WEB_SCAN",
        scan_profile=body.profile,
        status="QUEUED",
        current_stage="QUEUED",
        message="Authorized web scan queued.",
        result_summary=summary,
    )

    db.add(job)
    db.commit()

    try:
        run_web_scan.apply_async(
            args=[str(job_id)],
            task_id=task_id,
        )
    except Exception:
        db.rollback()

        (
            db.query(ScanJob)
            .filter(
                ScanJob.id == job_id,
                ScanJob.status == "QUEUED",
            )
            .update(
                {
                    "status": "FAILED",
                    "current_stage": "BROKER_ERROR",
                    "failure_code": "BROKER_SUBMISSION_FAILED",
                    "failure_message": (
                        "Queue dispatch was not acknowledged."
                    ),
                    "message": "Check scan history.",
                    "finished_at": datetime.now(timezone.utc),
                },
                synchronize_session=False,
            )
        )

        db.commit()

        raise HTTPException(
            503,
            detail={
                "message": (
                    "Queue dispatch was not acknowledged. "
                    "Check scan history."
                ),
                "job_id": str(job_id),
            },
        ) from None

    return {
        "job_id": job_id,
        "message": "Web scan queued.",
    }


# ============================================================
# WEB SCAN HISTORY
# ============================================================

@router.get("/web-scans")
def history(
    project_id: UUID | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = (
        db.query(ScanJob)
        .join(Target)
        .join(Project)
        .filter(
            Project.owner_id == current_user.id,
            ScanJob.job_type == "WEB_SCAN",
        )
    )

    if project_id:
        query = query.filter(Project.id == project_id)

    jobs = (
        query.order_by(ScanJob.created_at.desc())
        .limit(50)
        .all()
    )

    return [
        {
            "id": job.id,
            "target_id": job.target_id,
            "status": job.status,
            "current_stage": job.current_stage,
            "message": job.message,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "failure_code": job.failure_code,
            "failure_message": job.failure_message,
            "result": job.result_summary or {},
        }
        for job in jobs
    ]


# ============================================================
# STORED WEB FINDINGS
# ============================================================

@router.get(
    "/web-scans/{job_id}/findings",
    response_model=list[FindingResponse],
)
def findings(
    job_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    job = (
        db.query(ScanJob)
        .join(Target)
        .join(Project)
        .filter(
            ScanJob.id == job_id,
            Project.owner_id == current_user.id,
            ScanJob.job_type == "WEB_SCAN",
        )
        .first()
    )

    if not job:
        raise HTTPException(
            404,
            detail="Web scan not found.",
        )

    return (
        db.query(Finding)
        .filter(Finding.scan_id == job.id)
        .order_by(Finding.created_at)
        .all()
    )


# ============================================================
# BUNDLED LAB SOURCE MAPPINGS
# ============================================================

# Only the bundled training application's source is exposed.
# Never accept arbitrary filesystem paths from the frontend.

_LAB_SOURCE = Path("/opt/ase-lab-source/app.py")

# Each mapping:
# rule_id -> (
#     route,
#     parameter,
#     start_line,
#     end_line,
#     highlight_line,
#     expected_source_text
# )

_LAB_MAPPINGS = {
    # Reflected XSS
    "40012": (
        "/echo",
        "text",
        28,
        30,
        30,
        "query.get('text'",
    ),

    # SQL Injection
    "40018": (
        "/search",
        "q",
        31,
        41,
        37,
        'database.execute("SELECT owner, amount',
    ),

    # Content Security Policy Header Not Set
    "10038": (
        None,
        None,
        44,
        51,
        46,
        "self.send_header('Content-Type'",
    ),

    # Missing Anti-clickjacking Header
    "10020": (
        None,
        None,
        44,
        51,
        46,
        "self.send_header('Content-Type'",
    ),

    # X-Content-Type-Options Header Missing
    "10021": (
        None,
        None,
        44,
        51,
        46,
        "self.send_header('Content-Type'",
    ),

    # Cookie No HttpOnly Flag
    "10010": (
        None,
        None,
        48,
        50,
        49,
        "self.send_header('Set-Cookie'",
    ),

    # Cookie without SameSite Attribute
    "10054": (
        None,
        None,
        48,
        50,
        49,
        "self.send_header('Set-Cookie'",
    ),

    # Server Version Information Disclosure
    "10036": (
        None,
        None,
        7,
        10,
        8,
        "server_version =",
    ),
}


# ============================================================
# FINDING -> SOURCE CODE ENDPOINT
# ============================================================

@router.get(
    "/web-scans/{job_id}/findings/{finding_id}/lab-source"
)
def lab_finding_source(
    job_id: UUID,
    finding_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Verify that the user owns the authorized lab scan.
    job = (
        db.query(ScanJob)
        .join(Target)
        .join(Project)
        .filter(
            ScanJob.id == job_id,
            Project.owner_id == current_user.id,
            ScanJob.job_type == "WEB_SCAN",
            Target.url == LAB_URL,
        )
        .first()
    )

    if not job:
        raise HTTPException(
            404,
            detail="Authorized lab scan not found.",
        )

    # Verify that the finding belongs to this scan.
    finding = (
        db.query(Finding)
        .filter(
            Finding.id == finding_id,
            Finding.scan_id == job.id,
        )
        .first()
    )

    if not finding or finding.source != "DAST":
        raise HTTPException(
            404,
            detail="ZAP finding not found.",
        )

    # Identify the source mapping using the ZAP rule ID.
    mapping = _LAB_MAPPINGS.get(
        str(finding.tool_rule_id)
    )

    if not mapping:
        raise HTTPException(
            404,
            detail=(
                "No verified bundled-lab source mapping "
                "for this rule."
            ),
        )

    (
        route,
        parameter,
        start,
        end,
        highlight,
        expected,
    ) = mapping

    # ========================================================
    # VALIDATE AUTHORIZED LAB ENDPOINT
    # ========================================================

    endpoint = (finding.endpoint or {}).get(
        "path",
        "",
    )

    parsed = urlsplit(endpoint)

    # All mapped findings must belong to the lab.
    if (
        parsed.scheme != "http"
        or parsed.hostname != "ase-lab"
        or parsed.port != 8080
    ):
        raise HTTPException(
            404,
            detail=(
                "Finding endpoint is outside "
                "the bundled lab."
            ),
        )

    # Exact route and parameter matching for XSS and SQLi.
    # Header and cookie findings may occur on multiple routes.
    if route is not None:
        if (
            parsed.path != route
            or finding.parameter != parameter
        ):
            raise HTTPException(
                404,
                detail=(
                    "Finding does not match the bundled-lab "
                    "route and parameter."
                ),
            )

    # ========================================================
    # READ SOURCE CODE SAFELY
    # ========================================================

    try:
        data = _LAB_SOURCE.read_bytes()

        if len(data) > 100_000:
            raise ValueError(
                "Lab source exceeds maximum allowed size."
            )

        lines = data.decode("utf-8").splitlines()

        if len(lines) < end:
            raise ValueError(
                "Lab source does not contain mapped lines."
            )

    except (OSError, UnicodeError, ValueError):
        raise HTTPException(
            503,
            detail=(
                "Bundled lab source is unavailable "
                "or changed."
            ),
        ) from None

    # ========================================================
    # VERIFY SOURCE MAPPING
    # ========================================================

    if expected not in lines[highlight - 1]:
        raise HTTPException(
            409,
            detail=(
                "Lab source changed; mapping needs review."
            ),
        )

    snippet = "\n".join(
        lines[start - 1:end]
    )

    # ========================================================
    # RETURN SOURCE SNIPPET
    # ========================================================

    return {
        "path": "lab/app.py",
        "start_line": start,
        "end_line": end,
        "highlight_line": highlight,
        "content": snippet,
        "sha256": sha256(data).hexdigest(),
        "mapping_status": "BUNDLED_LAB_VERIFIED",
        "mapping_note": (
            "Matched against the bundled lab route, "
            "ZAP rule and parameter where applicable. "
            "For missing security headers, the snippet "
            "shows the relevant response-generation code "
            "rather than a single vulnerable statement."
        ),
    }
