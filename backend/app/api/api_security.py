from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Body, Request, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.config.database import get_db
from app.models.user import User
from app.models.project import Project, Target
from app.repositories.access import require_authorized_target
from app.api_testing.openapi_parser import parse_openapi_spec
from app.api_testing.authorization_checker import run_authorization_tests
from app.network.scope import resolve_and_verify_destination

router = APIRouter()


class OpenAPIImportRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    spec_content: str = Field(min_length=10, max_length=5000000)


class ApiAuthTestRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    target_id: UUID | None = None
    spec_content: str | None = None
    user_a_token: str | None = None
    user_b_token: str | None = None
    admin_token: str | None = None


@router.post("/projects/{project_id}/openapi-import")
async def import_openapi(
    project_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Import OpenAPI schema (JSON or YAML) from multipart form or JSON body."""
    project = db.query(Project).filter(Project.id == project_id, Project.owner_id == current_user.id).first()
    if not project:
        raise HTTPException(404, detail="Project not found.")

    content_type = request.headers.get("content-type", "")
    spec_text = ""
    if "multipart/form-data" in content_type:
        form = await request.form()
        uploaded_file = form.get("file")
        if uploaded_file and hasattr(uploaded_file, "read"):
            content_bytes = await uploaded_file.read(5000001)
            if len(content_bytes) > 5000000:
                raise HTTPException(413, detail="OpenAPI maximum size is 5 MB.")
            spec_text = content_bytes.decode("utf-8", errors="replace")
    else:
        try:
            body = await request.json()
            if isinstance(body, dict):
                spec_text = body.get("spec_content", "")
        except Exception:
            raw_bytes = await request.body()
            spec_text = raw_bytes.decode("utf-8", errors="replace")

    if not isinstance(spec_text, str) or len(spec_text) > 5000000:
        raise HTTPException(413, detail="OpenAPI maximum size is 5 MB.")
    if len(spec_text.strip()) < 10:
        raise HTTPException(400, detail="OpenAPI specification content is empty or too short.")

    try:
        inventory = parse_openapi_spec(spec_text)
        return inventory
    except ValueError as e:
        raise HTTPException(400, detail=str(e))


@router.post("/projects/{project_id}/api-auth-test")
async def test_api_authorization(
    project_id: UUID,
    request: Request,
    target_id: UUID | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Execute controlled BOLA and BFLA checks against authorized target with synthetic personas."""
    project = db.query(Project).filter(Project.id == project_id, Project.owner_id == current_user.id).first()
    if not project:
        raise HTTPException(404, detail="Project not found.")

    tid = target_id
    spec_content = None
    user_a = user_b = admin_tok = resource_id = None

    try:
        body = await request.json()
        if isinstance(body, dict):
            if not tid and "target_id" in body and body["target_id"]:
                tid = UUID(body["target_id"])
            spec_content = body.get("spec_content")
            user_a = body.get("user_a_token")
            user_b = body.get("user_b_token")
            admin_tok = body.get("admin_token")
            resource_id = body.get("resource_id")
    except Exception:
        pass

    if not tid:
        raise HTTPException(400, detail="target_id is required.")

    target = db.query(Target).filter(Target.id == tid, Target.project_id == project.id).first()
    if not target:
        raise HTTPException(404, detail="Target not found in this project.")

    try:
        require_authorized_target(db, target.id, current_user.id)
    except PermissionError as e:
        raise HTTPException(403, detail=str(e))

    if not isinstance(spec_content, str) or not (10 <= len(spec_content) <= 5000000):
        raise HTTPException(400, detail="Import and submit your actual OpenAPI specification before running tests.")
    spec_to_parse = spec_content

    try:
        inventory = parse_openapi_spec(spec_to_parse)
    except ValueError as e:
        raise HTTPException(400, detail=f"OpenAPI parsing failed: {str(e)}")

    synthetic_users = {
        "USER_A": {"token": user_a, "resource_id": resource_id},
        "USER_B": {"token": user_b},
        "ADMIN": {"token": admin_tok}
    }

    try:
        test_results = run_authorization_tests(
            base_url=target.url,
            endpoints=inventory["endpoints"],
            synthetic_users=synthetic_users,
            explicit_scope=target.explicit_scope
        )
        return test_results
    except PermissionError as e:
        raise HTTPException(403, detail=f"Authorization testing blocked by SSRF/Scope policy: {str(e)}")
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
