"""Repository intelligence and scan provenance; existing findings preserved."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
revision = 'e821ac6093fb'
down_revision = 'd7a104c892ab'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('repositories', sa.Column('latest_analysis_job_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column('repositories', sa.Column('intelligence', postgresql.JSONB(), nullable=True))
    op.create_foreign_key('fk_repository_latest_analysis', 'repositories', 'scan_jobs', ['latest_analysis_job_id'], ['id'])
    # The baseline already owns description. Some legacy installations lack it.
    existing_columns = {column['name'] for column in sa.inspect(op.get_bind()).get_columns('findings')}
    for name, column in [
        ('scan_id', sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=True)),
        ('repository_id', sa.Column('repository_id', postgresql.UUID(as_uuid=True), nullable=True)),
        ('fingerprint', sa.Column('fingerprint', sa.String(64), nullable=True)),
        ('description', sa.Column('description', sa.String(), nullable=True)),
        ('source', sa.Column('source', sa.String(32), nullable=True)),
        ('tool_rule_id', sa.Column('tool_rule_id', sa.String(255), nullable=True)),
    ]:
        if name == 'description' and name in existing_columns:
            continue
        op.add_column('findings', column)
    op.create_foreign_key('fk_finding_scan', 'findings', 'scan_jobs', ['scan_id'], ['id'])
    op.create_foreign_key('fk_finding_repository', 'findings', 'repositories', ['repository_id'], ['id'])
    op.create_index('ix_findings_scan_id', 'findings', ['scan_id'])
    op.create_index('ix_findings_repository_id', 'findings', ['repository_id'])
    op.create_unique_constraint('uq_findings_scan_fingerprint', 'findings', ['scan_id', 'fingerprint'])


def downgrade():
    op.drop_constraint('uq_findings_scan_fingerprint', 'findings', type_='unique')
    op.drop_index('ix_findings_repository_id', table_name='findings')
    op.drop_index('ix_findings_scan_id', table_name='findings')
    op.drop_constraint('fk_finding_repository', 'findings', type_='foreignkey')
    op.drop_constraint('fk_finding_scan', 'findings', type_='foreignkey')
    # Preserve description: it predates this revision and may contain legacy data.
    for name in ['tool_rule_id', 'source', 'fingerprint', 'repository_id', 'scan_id']:
        op.drop_column('findings', name)
    op.drop_constraint('fk_repository_latest_analysis', 'repositories', type_='foreignkey')
    op.drop_column('repositories', 'intelligence')
    op.drop_column('repositories', 'latest_analysis_job_id')
