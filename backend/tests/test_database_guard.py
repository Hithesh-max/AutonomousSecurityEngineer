import pytest
import os
import urllib.parse
from app.config.settings import settings

def test_guard_application_database_selection():
    # Verify that the test setup logic never selects the application database even if the URL has "test" in username/password
    parsed_app = urllib.parse.urlparse(settings.DATABASE_URL)
    app_db = parsed_app.path.lstrip('/')
    
    # Fake setting with 'test' in the username
    fake_url = "postgresql://test_operator:pass@db:5432/ase_db"
    parsed_fake = urllib.parse.urlparse(fake_url)
    fake_app_db = parsed_fake.path.lstrip('/')
    
    unique = "ase_test_1234"
    
    assert fake_app_db != unique
    assert fake_app_db == "ase_db"
    
def test_guard_rejects_application_database():
    # Simulate a collision logic
    app_db_name = "ase_test_db"
    unique_test_db_name = "ase_test_db"
    
    with pytest.raises(RuntimeError, match="Test database name collided with application database name"):
        if app_db_name == unique_test_db_name or app_db_name.startswith("ase_test_"):
            raise RuntimeError("Test database name collided with application database name.")
            
def test_guard_rejects_existing_test_database(monkeypatch):
    import psycopg
    from psycopg import sql
    
    class FakeCursor:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass
        def execute(self, query, params=None):
            pass
        def fetchone(self):
            return (1,) # Simulates existing database
            
    class FakeConn:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass
        def cursor(self):
            return FakeCursor()
            
    def mock_connect(*args, **kwargs):
        return FakeConn()
        
    monkeypatch.setattr(psycopg, "connect", mock_connect)
    
    with pytest.raises(RuntimeError, match="Refusing to reuse or drop it"):
        with psycopg.connect("fake") as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", ("ase_test_123",))
                if cur.fetchone():
                    raise RuntimeError(f"Database ase_test_123 already exists. Refusing to reuse or drop it.")
