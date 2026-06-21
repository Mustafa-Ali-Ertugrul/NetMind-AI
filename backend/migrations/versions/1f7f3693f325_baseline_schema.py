"""baseline schema

Revision ID: 1f7f3693f325
Revises:
Create Date: 2026-06-06 11:29:41.233356

"""
from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = '1f7f3693f325'
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
