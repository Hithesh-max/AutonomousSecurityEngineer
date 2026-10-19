"""Persistent, resumable whole-project remediation. Additive; no existing rows changed."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB
revision = 'f19b6c20aa01'
down_revision = 'a3f1c0de5b21'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('remediation_batches',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('created_at', sa.DateTime()), sa.Column('updated_at', sa.DateTime()),
        sa.Column('repository_id', UUID(as_uuid=True), sa.ForeignKey('repositories.id'), nullable=False),
        sa.Column('scan_id', UUID(as_uuid=True), sa.ForeignKey('scan_jobs.id'), nullable=False),
        sa.Column('requested_by', UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('status', sa.String(16), nullable=False), sa.Column('mode', sa.String(16), nullable=False),
        sa.Column('consent', sa.Boolean(), nullable=False), sa.Column('items', JSONB(), nullable=False),
        sa.Column('cursor', sa.Integer(), nullable=False), sa.Column('message', sa.String(300)),
        sa.CheckConstraint("status IN ('QUEUED','RUNNING','PAUSING','PAUSED','COMPLETED','FAILED')", name='ck_remediation_batch_status'))
    op.create_index('ix_remediation_batches_repository_id', 'remediation_batches', ['repository_id'])
    op.create_index('ix_remediation_batches_requested_by', 'remediation_batches', ['requested_by'])
    op.create_index('uq_remediation_batch_active_repository', 'remediation_batches', ['repository_id'], unique=True,
        postgresql_where=sa.text("status IN ('QUEUED','RUNNING','PAUSING')"))


def downgrade():
    op.drop_table('remediation_batches')
