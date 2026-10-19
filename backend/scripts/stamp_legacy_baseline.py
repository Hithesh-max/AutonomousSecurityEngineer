import os
import sys
from sqlalchemy import create_engine, inspect, text

# Assumes this script runs from the backend directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config.settings import settings

def stamp_legacy_baseline():
    engine = create_engine(settings.DATABASE_URL)
    with engine.connect() as conn:
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        required_tables = {"projects", "targets", "findings", "scan_jobs"}
        
        if "alembic_version" in tables:
            print("Database already has alembic_version. Stamping not needed.")
            return
            
        if not required_tables.issubset(set(tables)):
            print(f"Cannot stamp database. Missing required legacy tables. Found: {tables}")
            return
            
        finding_cols = {c['name']: c for c in inspector.get_columns('findings')}
        expected_cols = [
            'id', 'project_id', 'title', 'category', 'subcategory', 'severity', 
            'confidence', 'status', 'source_tools', 'asset', 'endpoint', 'parameter', 
            'source_location', 'evidence', 'cwe', 'cvss', 'root_cause', 'impact', 
            'remediation_plan', 'verification_status', 'created_at', 'updated_at'
        ]
        
        for col in expected_cols:
            if col not in finding_cols:
                print(f"Validation failed: missing column '{col}' in 'findings' table.")
                print(f"This database does not match the full legacy baseline.")
                return
                
        # Validate some critical constraints/types if necessary
        # e.g., ensure remediation_plan is string or json
        rem_plan_type = finding_cols.get('remediation_plan', {}).get('type')
        if not type(rem_plan_type).__name__ in ('JSON', 'JSONB', 'VARCHAR', 'String', 'TEXT'):
            print(f"Validation failed: remediation_plan type {rem_plan_type} is completely unknown.")
            return
            
        print("Pre-Alembic legacy database verified. Stamping baseline '03477d2d740d'.")
        conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL, CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"))
        conn.execute(text("INSERT INTO alembic_version (version_num) VALUES ('03477d2d740d')"))
        conn.commit()
        print("Stamping complete.")

if __name__ == "__main__":
    stamp_legacy_baseline()
