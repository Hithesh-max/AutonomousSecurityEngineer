"""Repair schema drift

Revision ID: bf6caf7316fa
Revises: b1246aa56459
Create Date: 2026-10-06 23:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'bf6caf7316fa'
down_revision: Union[str, Sequence[str], None] = 'b1246aa56459'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    # 1. Create scan_jobs table if missing
    if 'scan_jobs' not in tables:
        op.create_table('scan_jobs',
            sa.Column('id', sa.UUID(), nullable=False),
            sa.Column('target_id', sa.UUID(), nullable=True),
            sa.Column('status', sa.String(), nullable=True),
            sa.Column('scan_profile', sa.String(), nullable=True),
            sa.Column('result_summary', sa.JSON(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.Column('updated_at', sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ),
            sa.PrimaryKeyConstraint('id')
        )
    else:
        print("MIGRATION INFO: scan_jobs table already exists, skipping creation.")

    # 2. Add missing columns to findings
    finding_cols = {c['name']: c for c in inspector.get_columns('findings')}
    
    missing_cols = [
        ('category', sa.String()),
        ('subcategory', sa.String()),
        ('confidence', sa.String()),
        ('source_tools', sa.JSON()),
        ('asset', postgresql.JSONB(astext_type=sa.Text())),
        ('endpoint', postgresql.JSONB(astext_type=sa.Text())),
        ('parameter', sa.String()),
        ('cwe', sa.String()),
        ('cvss', sa.Float()),
        ('root_cause', sa.String()),
        ('impact', sa.String()),
        ('verification_status', sa.String())
    ]
    
    for col_name, col_type in missing_cols:
        if col_name not in finding_cols:
            op.add_column('findings', sa.Column(col_name, col_type, nullable=True))
        else:
            # We assume the legacy type is roughly compatible; actual validation happens in stamp_legacy_baseline
            print(f"MIGRATION INFO: column {col_name} already exists in findings, skipping addition.")
    
    # 3. Alter remediation_plan from JSON to String if needed
    if 'remediation_plan' in finding_cols:
        col_type = finding_cols['remediation_plan']['type']
        # If it's literally JSON or JSONB, we alter it
        if type(col_type).__name__ in ('JSON', 'JSONB'):
            op.alter_column('findings', 'remediation_plan',
                       existing_type=col_type,
                       type_=sa.String(),
                       existing_nullable=True,
                       postgresql_using='remediation_plan::text')
               
    # 4. Alter evidence and source_location to JSONB if they are plain JSON
    for col_name in ['evidence', 'source_location']:
        if col_name in finding_cols:
            col_type = finding_cols[col_name]['type']
            if type(col_type).__name__ == 'JSON':
                op.alter_column('findings', col_name,
                           existing_type=col_type,
                           type_=postgresql.JSONB(astext_type=sa.Text()),
                           existing_nullable=True,
                           postgresql_using=f'{col_name}::jsonb')

def downgrade() -> None:
    op.alter_column('findings', 'source_location',
               existing_type=postgresql.JSONB(astext_type=sa.Text()),
               type_=sa.JSON(),
               existing_nullable=True,
               postgresql_using='source_location::json')
               
    op.alter_column('findings', 'evidence',
               existing_type=postgresql.JSONB(astext_type=sa.Text()),
               type_=sa.JSON(),
               existing_nullable=True,
               postgresql_using='evidence::json')
               
    op.alter_column('findings', 'remediation_plan',
               existing_type=sa.String(),
               type_=sa.JSON(),
               existing_nullable=True,
               postgresql_using='remediation_plan::json')
               
    op.drop_column('findings', 'verification_status')
    op.drop_column('findings', 'impact')
    op.drop_column('findings', 'root_cause')
    op.drop_column('findings', 'cvss')
    op.drop_column('findings', 'cwe')
    op.drop_column('findings', 'parameter')
    op.drop_column('findings', 'endpoint')
    op.drop_column('findings', 'asset')
    op.drop_column('findings', 'source_tools')
    op.drop_column('findings', 'confidence')
    op.drop_column('findings', 'subcategory')
    op.drop_column('findings', 'category')
    
    op.drop_table('scan_jobs')
