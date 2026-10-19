import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import uuid
import os
from pathlib import Path

# Load project root .env into os.environ if present
_root_env = Path(__file__).resolve().parents[2] / ".env"
if _root_env.exists():
    with open(_root_env, "r", encoding="utf-8-sig") as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())

from app.main import app
from app.config.database import get_db, engine, SessionLocal
from app.models.base import Base
from app.models.user import User
from app.core import security

from app.config.settings import settings

import urllib.parse

# Parse application database URL structurally
parsed_app_url = urllib.parse.urlparse(settings.DATABASE_URL)
app_db_name = parsed_app_url.path.lstrip('/')

# Create a unique database name for this test run
unique_test_db_name = f"ase_test_{uuid.uuid4().hex[:8]}"
parsed_test_url = parsed_app_url._replace(path=f"/{unique_test_db_name}")
TEST_DB_URL = urllib.parse.urlunparse(parsed_test_url)

# Refuse to select the application database
if app_db_name == unique_test_db_name or app_db_name.startswith("ase_test_"):
    # This shouldn't happen with UUIDs, but as a sanity check against bad parsing
    raise RuntimeError("Test database name collided with application database name.")

test_engine = create_engine(TEST_DB_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# Eagerly patch it so module-level imports get the test DB
import app.config.database as db_config
db_config.SessionLocal = TestingSessionLocal
db_config.engine = test_engine

import app.workers.scan_jobs as sj
sj.SessionLocal = TestingSessionLocal

import app.workers.remediation_jobs as rj
rj.SessionLocal = TestingSessionLocal

import app.workers.diagnostic_jobs as dj
dj.SessionLocal = TestingSessionLocal

import app.workers.ingestion_jobs as ij
ij.SessionLocal = TestingSessionLocal

import app.workers.analysis_jobs as analysis
analysis.SessionLocal = TestingSessionLocal

import app.workers.web_jobs as web_jobs
web_jobs.SessionLocal = TestingSessionLocal

import app.workers.recovery_jobs as recovery
recovery.SessionLocal = TestingSessionLocal

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

import psycopg
from psycopg import sql

_POSTGRES_AVAILABLE = False

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    global _POSTGRES_AVAILABLE
    user = parsed_app_url.username
    password = parsed_app_url.password
    host = parsed_app_url.hostname
    port = parsed_app_url.port or 5432
    conn_str = f"postgresql://{user}:{password}@{host}:{port}/postgres"
    
    try:
        with psycopg.connect(conn_str, autocommit=True, connect_timeout=2) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (unique_test_db_name,))
                if cur.fetchone():
                    raise RuntimeError(f"Database {unique_test_db_name} already exists. Refusing to reuse or drop it.")
                cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(unique_test_db_name)))
        _POSTGRES_AVAILABLE = True
    except (psycopg.OperationalError, OSError, RuntimeError):
        _POSTGRES_AVAILABLE = False
        yield
        return

    # Now run migrations on the test DB
    from alembic.config import Config
    from alembic import command
    alembic_cfg = Config("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", TEST_DB_URL)
    command.upgrade(alembic_cfg, "head")
    
    yield
    
    # Clean up afterwards (only drop the database this test run successfully created)
    test_engine.dispose()
    try:
        with psycopg.connect(conn_str, autocommit=True, connect_timeout=2) as conn:
            with conn.cursor() as cur:
                cur.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(unique_test_db_name)))
    except Exception:
        pass

@pytest.fixture(scope="session")
def test_db(setup_test_db):
    if not _POSTGRES_AVAILABLE:
        pytest.skip("PostgreSQL test database not available in this environment.")
    db = TestingSessionLocal()
    yield db
    db.close()

@pytest.fixture(scope="module")
def client():
    return TestClient(app)

@pytest.fixture(scope="module")
def test_user(test_db):
    user = test_db.query(User).filter(User.username == "test_user").first()
    if not user:
        user = User(username="test_user", hashed_password=security.get_password_hash("test_pass"))
        test_db.add(user)
        test_db.commit()
        test_db.refresh(user)
    return user

@pytest.fixture(scope="module")
def test_user_token(test_user):
    return security.create_access_token(data={"sub": test_user.username, "t_ver": test_user.token_version})

@pytest.fixture(scope="module")
def test_user_2(test_db):
    user = test_db.query(User).filter(User.username == "test_user_2").first()
    if not user:
        user = User(username="test_user_2", hashed_password=security.get_password_hash("test_pass"))
        test_db.add(user)
        test_db.commit()
        test_db.refresh(user)
    return user

@pytest.fixture(scope="module")
def test_user_2_token(test_user_2):
    return security.create_access_token(data={"sub": test_user_2.username, "t_ver": test_user_2.token_version})
