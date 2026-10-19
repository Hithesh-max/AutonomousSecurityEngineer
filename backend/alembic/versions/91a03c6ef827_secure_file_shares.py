"""Store short-lived encrypted file-share metadata."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "91a03c6ef827"
down_revision = "f19b6c20aa01"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "secure_shares",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("storage_key", sa.String(80), nullable=False, unique=True),
        sa.Column("reader_token_sha256", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("download_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_downloads", sa.Integer(), nullable=False),
        sa.CheckConstraint("download_count >= 0", name="ck_secure_shares_download_count"),
        sa.CheckConstraint("max_downloads BETWEEN 1 AND 100", name="ck_secure_shares_max_downloads"),
    )
    op.create_index("ix_secure_shares_owner_id", "secure_shares", ["owner_id"])
    op.create_index("ix_secure_shares_expires_at", "secure_shares", ["expires_at"])


def downgrade():
    op.drop_index("ix_secure_shares_expires_at", table_name="secure_shares")
    op.drop_index("ix_secure_shares_owner_id", table_name="secure_shares")
    op.drop_table("secure_shares")
