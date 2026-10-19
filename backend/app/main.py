from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router
from app.api.auth import router as auth_router
from app.api.repositories import router as repository_router
from app.api.web_scans import router as web_scan_router
from app.api.remediation import router as remediation_router
from app.api.supply_chain import router as supply_chain_router
from app.api.api_security import router as api_security_router
from app.api.evaluation import router as evaluation_router
from app.api.collaboration import router as collaboration_router
from app.api.secure_shares import router as secure_share_router
from app.config.database import engine
from app.models.base import Base
from app.models.project import Project, Target
from app.models.finding import Finding
from app.models.user import User

# Database schema is managed by Alembic. Base.metadata.create_all is removed.

app = FastAPI(
    title="Autonomous Security Engineer (ASE)",
    description="AI-Powered Autonomous Penetration Testing & Remediation Platform",
    version="1.0.0"
)

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For dev only, restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api/auth", tags=["auth"])
app.include_router(api_router, prefix="/api", tags=["core"])
app.include_router(repository_router, prefix="/api", tags=["repositories"])
app.include_router(web_scan_router, prefix="/api", tags=["web scans"])
app.include_router(remediation_router, prefix="/api", tags=["ai remediation"])
app.include_router(supply_chain_router, prefix="/api", tags=["supply chain"])
app.include_router(api_security_router, prefix="/api", tags=["api security"])
app.include_router(evaluation_router, prefix="/api", tags=["evaluation"])
app.include_router(collaboration_router, prefix="/api", tags=["collaboration"])
app.include_router(secure_share_router, prefix="/api", tags=["secure file shares"])

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "message": "Backend is reachable. (Note: Does not guarantee DB/Worker liveness)"}
