"""add flow interval variance and ack count

Revision ID: b0e5f0c53d14
Revises: 1f7f3693f325
Create Date: 2026-06-06 11:30:03.601669

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b0e5f0c53d14"
down_revision: str | Sequence[str] | None = "1f7f3693f325"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add inter-packet interval metrics and ACK count to flows table."""
    op.add_column(
        "flows",
        sa.Column("inter_packet_interval_ms", sa.Float(), nullable=True),
    )
    op.add_column(
        "flows",
        sa.Column("inter_packet_interval_variance_ms", sa.Float(), nullable=True),
    )
    op.add_column(
        "flows",
        sa.Column("ack_count", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    """Remove the added columns."""
    op.drop_column("flows", "ack_count")
    op.drop_column("flows", "inter_packet_interval_variance_ms")
    op.drop_column("flows", "inter_packet_interval_ms")
