"""Managed ZIP repositories; no changes to existing data.

Revision ID: d7a104c892ab
Revises: c51c30681a14
"""
from alembic import op
import sqlalchemy as sa

revision = 'd7a104c892ab'
down_revision = 'c51c30681a14'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'repositories',
        sa.Column('id', sa.UUID(), primary_key=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('project_id', sa.UUID(), sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('target_id', sa.UUID(), sa.ForeignKey('targets.id'), nullable=False),
        sa.Column('uploaded_by', sa.UUID(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(120), nullable=False),
        sa.Column('source_type', sa.String(16), nullable=False),
        sa.Column('ingestion_status', sa.String(16), nullable=False),
        sa.Column('analysis_status', sa.String(24), nullable=False),
        sa.Column('archive_sha256', sa.String(64), nullable=False),
        sa.Column('upload_bytes', sa.BigInteger(), nullable=False),
        sa.Column('extracted_bytes', sa.BigInteger()),
        sa.Column('file_count', sa.Integer()),
        sa.Column('source_authorized_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ingested_at', sa.DateTime(timezone=True)),
        sa.Column('failure_code', sa.String(64)),
        sa.Column('failure_message', sa.String(256)),
        sa.CheckConstraint("source_type = 'ZIP'", name='ck_repositories_source_type'),
        sa.CheckConstraint("ingestion_status IN ('QUEUED', 'RUNNING', 'READY', 'FAILED')", name='ck_repositories_ingestion_status'),
    )
    op.create_index('ix_repositories_project_id', 'repositories', ['project_id'])
    op.create_index('ix_repositories_target_id', 'repositories', ['target_id'])
    op.add_column('scan_jobs', sa.Column('repository_id', sa.UUID(), nullable=True))
    op.create_foreign_key('fk_scan_jobs_repository_id', 'scan_jobs', 'repositories', ['repository_id'], ['id'])
    op.create_index('ix_scan_jobs_repository_id', 'scan_jobs', ['repository_id'])
    op.create_index('ix_scan_jobs_status_created_at', 'scan_jobs', ['status', 'created_at'])


def downgrade():
    op.drop_index('ix_scan_jobs_status_created_at', table_name='scan_jobs')
    op.drop_index('ix_scan_jobs_repository_id', table_name='scan_jobs')
    op.drop_constraint('fk_scan_jobs_repository_id', 'scan_jobs', type_='foreignkey')
    op.drop_column('scan_jobs', 'repository_id')
    op.drop_index('ix_repositories_target_id', table_name='repositories')
    op.drop_index('ix_repositories_project_id', table_name='repositories')
    op.drop_table('repositories')
