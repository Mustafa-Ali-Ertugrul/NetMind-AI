"""drop packets table

Revision ID: c1a2b3c4d5e6
Revises: bdfcd01cbf77
Create Date: 2026-06-07 21:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

# revision identifiers, used by Alembic.
revision: str = "c1a2b3c4d5e6"
down_revision: str | Sequence[str] | None = "bdfcd01cbf77"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Remove packet-level persistence; packet data remains parser-local."""
    op.execute("DROP TABLE IF EXISTS packets CASCADE")


def downgrade() -> None:
    """Recreate the legacy packet table for downgrade compatibility."""
    op.create_table(
        "packets",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("pcap_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("packet_number", sa.BigInteger(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("src_ip", pg.INET(), nullable=False),
        sa.Column("dst_ip", pg.INET(), nullable=False),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("length", sa.Integer(), nullable=False),
        sa.Column("ttl", sa.Integer(), nullable=True),
        sa.Column("tcp_flags", sa.String(length=16), nullable=True),
        sa.Column("info", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["pcap_id"], ["pcap_files.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_packets_pcap_id", "packets", ["pcap_id"], unique=False)
    op.create_index("idx_packets_ips", "packets", ["src_ip", "dst_ip"], unique=False)
    op.create_index("idx_packets_protocol", "packets", ["protocol"], unique=False)
