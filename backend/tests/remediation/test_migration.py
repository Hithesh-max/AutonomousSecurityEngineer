import urllib.parse
import uuid

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from psycopg import sql

from app.config.settings import settings

PREV, HEAD = "e821ac6093fb", "a3f1c0de5b21"


@pytest.fixture
def disposable():
    p = urllib.parse.urlparse(settings.DATABASE_URL)
    name = f"ase_test_{uuid.uuid4().hex[:8]}"
    admin = f"postgresql://{p.username}:{p.password}@{p.hostname}:{p.port or 5432}/postgres"
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    yield f"postgresql://{p.username}:{p.password}@{p.hostname}:{p.port or 5432}/{name}"
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))


def test_upgrade_downgrade_roundtrip_preserves_existing_rows(disposable):
    cfg = Config("alembic.ini"); cfg.set_main_option("sqlalchemy.url", disposable)
    command.upgrade(cfg, PREV)
    with psycopg.connect(disposable, autocommit=True) as c:
        c.execute("INSERT INTO users (id, username, hashed_password, is_active, token_version) VALUES (gen_random_uuid(), 'm', 'x', true, 1)")
        pid = c.execute("INSERT INTO projects (id, name, owner_id) SELECT gen_random_uuid(), 'p', id FROM users RETURNING id").fetchone()[0]
        c.execute("INSERT INTO findings (id, project_id, title, severity) VALUES (gen_random_uuid(), %s, 'keep me', 'HIGH')", (pid,))
    command.upgrade(cfg, HEAD)
    with psycopg.connect(disposable) as c:
        tables = {r[0] for r in c.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'")}
        assert {"ai_analyses", "patch_proposals", "remediation_events"} <= tables
        assert c.execute("SELECT count(*) FROM findings WHERE title='keep me'").fetchone()[0] == 1
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute("INSERT INTO patch_proposals (id, finding_id, analysis_id, project_id, requested_by, status, provider, model, source_kind,"
                      " source_path, source_sha256, patched_sha256, patch_sha256, unified_diff, edits, explanation, static_checks)"
                      " VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 'BOGUS','p','m','k','p','s','s','s','d','[]','e','{}')")
    command.downgrade(cfg, PREV)
    with psycopg.connect(disposable) as c:
        assert c.execute("SELECT count(*) FROM findings WHERE title='keep me'").fetchone()[0] == 1
        assert c.execute("SELECT to_regclass('public.patch_proposals')").fetchone()[0] is None
    command.upgrade(cfg, HEAD)
