import pytest
import urllib.parse
import uuid
import psycopg
from psycopg import sql
from alembic.config import Config
from alembic import command
import os

from app.config.settings import settings

@pytest.fixture
def disposable_db():
    parsed = urllib.parse.urlparse(settings.DATABASE_URL)
    db_name = f"ase_test_migr_{uuid.uuid4().hex[:8]}"
    user = parsed.username
    password = parsed.password
    host = parsed.hostname
    port = parsed.port or 5432
    
    conn_str = f"postgresql://{user}:{password}@{host}:{port}/postgres"
    test_db_url = f"postgresql://{user}:{password}@{host}:{port}/{db_name}"
    
    with psycopg.connect(conn_str, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name)))
            
    yield test_db_url
    
    with psycopg.connect(conn_str, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(db_name)))

def test_empty_database_migration(disposable_db):
    """Path 1: Empty databases initialized through migrations."""
    alembic_cfg = Config("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", disposable_db)
    
    # Run upgrade head
    command.upgrade(alembic_cfg, "head")
    
    # Verify tables
    with psycopg.connect(disposable_db) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            tables = {r[0] for r in cur.fetchall()}
            assert {"projects", "targets", "findings", "scan_jobs", "users", "repositories", "alembic_version"}.issubset(tables)
            
            # Verify findings columns are correct (e.g. cvss is double precision, remediation_plan is varchar)
            cur.execute("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'findings'")
            cols = {r[0]: r[1] for r in cur.fetchall()}
            assert cols["cvss"] == "double precision"
            assert "character" in cols["remediation_plan"]

def test_existing_database_migration(disposable_db):
    """Path 2: Existing databases containing scan_jobs and the original Finding columns."""
    
    # 1. Manually create the FULL original schema (the one that actually existed before Alembic)
    with psycopg.connect(disposable_db) as conn:
        with conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE projects (
                id UUID PRIMARY KEY,
                name VARCHAR NOT NULL,
                description VARCHAR,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            );
            
            CREATE TABLE targets (
                id UUID PRIMARY KEY,
                project_id UUID REFERENCES projects(id),
                name VARCHAR NOT NULL,
                url VARCHAR NOT NULL,
                repo_url VARCHAR,
                authorization_status VARCHAR,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            );
            
            CREATE TABLE findings (
                id UUID PRIMARY KEY,
                project_id UUID REFERENCES projects(id),
                title VARCHAR NOT NULL,
                category VARCHAR,
                subcategory VARCHAR,
                severity VARCHAR,
                confidence VARCHAR,
                status VARCHAR,
                source_tools JSON,
                asset JSON,
                endpoint JSON,
                parameter VARCHAR,
                source_location JSON,
                evidence JSON,
                cwe VARCHAR,
                cvss DOUBLE PRECISION,
                root_cause VARCHAR,
                impact VARCHAR,
                remediation_plan JSON,
                verification_status VARCHAR,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            );
            
            CREATE TABLE scan_jobs (
                id UUID PRIMARY KEY,
                target_id UUID REFERENCES targets(id),
                status VARCHAR,
                scan_profile VARCHAR,
                result_summary JSON,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            );
            """)
            
            # Seed data
            cur.execute("INSERT INTO projects (id, name) VALUES ('11111111-1111-1111-1111-111111111111', 'Seed Project')")
            cur.execute("INSERT INTO targets (id, project_id, name, url) VALUES ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111', 'Seed Target', 'http://test.com')")
            cur.execute("INSERT INTO scan_jobs (id, target_id, status) VALUES ('33333333-3333-3333-3333-333333333333', '22222222-2222-2222-2222-222222222222', 'COMPLETED')")
            cur.execute("INSERT INTO findings (id, project_id, title, category, evidence, remediation_plan) VALUES ('44444444-4444-4444-4444-444444444444', '11111111-1111-1111-1111-111111111111', 'Seed Finding', 'SQLi', '{\"match\": \"data\"}', '{\"steps\": \"fix it\"}')")
            
        conn.commit()
    
    # 2. Emulate the script: stamp legacy baseline
    from sqlalchemy import create_engine
    engine = create_engine(disposable_db)
    with engine.connect() as conn2:
        from sqlalchemy import text
        conn2.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL, CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"))
        conn2.execute(text("INSERT INTO alembic_version (version_num) VALUES ('03477d2d740d')"))
        conn2.commit()

    # 3. Run upgrade head to apply cf4525e8f56c (users), 76786986deb0, b1246aa56459, and bf6caf7316fa (repair schema)
    alembic_cfg = Config("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", disposable_db)
    command.upgrade(alembic_cfg, "head")
    
    # 4. Verify data survived and schema changed correctly
    with psycopg.connect(disposable_db) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT title, category, remediation_plan FROM findings WHERE id = '44444444-4444-4444-4444-444444444444'")
            row = cur.fetchone()
            assert row[0] == "Seed Finding"
            assert row[1] == "SQLi"
            # Remediation plan was converted from JSON to String
            assert "fix it" in row[2]
            assert isinstance(row[2], str)
            
            cur.execute("SELECT name FROM projects WHERE id = '11111111-1111-1111-1111-111111111111'")
            assert cur.fetchone()[0] == "Seed Project"
