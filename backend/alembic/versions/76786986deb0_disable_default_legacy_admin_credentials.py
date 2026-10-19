"""Disable default legacy admin credentials

Revision ID: 76786986deb0
Revises: cf4525e8f56c
Create Date: 2026-10-06 16:42:21.574177

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '76786986deb0'
down_revision: Union[str, Sequence[str], None] = 'cf4525e8f56c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Find the legacy_admin user and disable the account and invalidate the hash.
    # The known previous hash was:
    old_hash = "$2a$12$6/7/L1.rLp.7L.Yc/1.p8.Y6g8V9rV/7L6.r.X8/Y8g8V9rV/7L6"
    
    op.execute(
        f"UPDATE users SET hashed_password = '!disabled', is_active = false "
        f"WHERE username = 'legacy_admin' AND hashed_password = '{old_hash}'"
    )

def downgrade() -> None:
    """Downgrade schema."""
    pass
