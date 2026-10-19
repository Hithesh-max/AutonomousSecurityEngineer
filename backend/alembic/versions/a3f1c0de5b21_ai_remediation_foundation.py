"""AI remediation foundation: analyses, patch proposals, audit events. Purely additive."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'a3f1c0de5b21'
down_revision = 'e821ac6093fb'
branch_labels = None
depends_on = None

STATES = ("PATCH_PROPOSED", "APPROVED", "APPLYING", "APPLIED", "VERIFYING", "VERIFIED",
          "REJECTED", "FAILED", "INCONCLUSIVE", "SUPERSEDED")
UUID = postgresql.UUID(as_uuid=True)


def _base():
    return [sa.Column('id', UUID, primary_key=True), sa.Column('created_at', sa.DateTime()), sa.Column('updated_at', sa.DateTime())]


def upgrade():
    op.create_table('ai_analyses', *_base(),
        sa.Column('finding_id', UUID, sa.ForeignKey('findings.id'), nullable=False),
        sa.Column('project_id', UUID, sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('requested_by', UUID, sa.ForeignKey('users.id'), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('provider', sa.String(32), nullable=False),
        sa.Column('model', sa.String(64), nullable=False),
        sa.Column('is_mock', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('external_transmission_acknowledged', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('source_kind', sa.String(32)), sa.Column('source_path', sa.String(255)), sa.Column('source_sha256', sa.String(64)),
        sa.Column('result', postgresql.JSONB()),
        sa.Column('error_code', sa.String(64)), sa.Column('error_message', sa.String(300)),
        sa.Column('prompt_tokens', sa.Integer()), sa.Column('completion_tokens', sa.Integer()), sa.Column('latency_ms', sa.Integer()),
        sa.CheckConstraint("status IN ('COMPLETED', 'FAILED')", name='ck_ai_analyses_status'))
    op.create_index('ix_ai_analyses_finding_id', 'ai_analyses', ['finding_id'])
    op.create_index('ix_ai_analyses_project_id', 'ai_analyses', ['project_id'])
    op.create_index('ix_ai_analyses_finding_created', 'ai_analyses', ['finding_id', 'created_at'])

    op.create_table('patch_proposals', *_base(),
        sa.Column('finding_id', UUID, sa.ForeignKey('findings.id'), nullable=False),
        sa.Column('analysis_id', UUID, sa.ForeignKey('ai_analyses.id'), nullable=False),
        sa.Column('project_id', UUID, sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('requested_by', UUID, sa.ForeignKey('users.id'), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('provider', sa.String(32), nullable=False), sa.Column('model', sa.String(64), nullable=False),
        sa.Column('is_mock', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('source_kind', sa.String(32), nullable=False), sa.Column('source_path', sa.String(255), nullable=False),
        sa.Column('source_sha256', sa.String(64), nullable=False), sa.Column('patched_sha256', sa.String(64), nullable=False),
        sa.Column('patch_sha256', sa.String(64), nullable=False),
        sa.Column('unified_diff', sa.Text(), nullable=False), sa.Column('edits', postgresql.JSONB(), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False), sa.Column('behavior_notes', sa.Text()),
        sa.Column('limitations', postgresql.JSONB()), sa.Column('static_checks', postgresql.JSONB(), nullable=False),
        sa.Column('prompt_tokens', sa.Integer()), sa.Column('completion_tokens', sa.Integer()), sa.Column('latency_ms', sa.Integer()),
        sa.Column('approved_by', UUID, sa.ForeignKey('users.id')), sa.Column('approved_at', sa.DateTime(timezone=True)),
        sa.Column('verification_status', sa.String(32), nullable=False, server_default='NOT_VERIFIED'),
        sa.CheckConstraint("status IN (" + ", ".join(f"'{s}'" for s in STATES) + ")", name='ck_patch_proposals_status'))
    op.create_index('ix_patch_proposals_finding_id', 'patch_proposals', ['finding_id'])
    op.create_index('ix_patch_proposals_project_id', 'patch_proposals', ['project_id'])
    op.create_index('ix_patch_proposals_finding_created', 'patch_proposals', ['finding_id', 'created_at'])

    op.create_table('remediation_events', *_base(),
        sa.Column('finding_id', UUID, sa.ForeignKey('findings.id'), nullable=False),
        sa.Column('analysis_id', UUID, sa.ForeignKey('ai_analyses.id')),
        sa.Column('patch_id', UUID, sa.ForeignKey('patch_proposals.id')),
        sa.Column('actor_id', UUID, sa.ForeignKey('users.id'), nullable=False),
        sa.Column('event_type', sa.String(48), nullable=False),
        sa.Column('from_state', sa.String(16)), sa.Column('to_state', sa.String(16)),
        sa.Column('details', postgresql.JSONB()))
    op.create_index('ix_remediation_events_finding_id', 'remediation_events', ['finding_id'])


def downgrade():
    op.drop_table('remediation_events')
    op.drop_table('patch_proposals')
    op.drop_table('ai_analyses')
