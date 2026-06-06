"""sprint10 live engine schema

Revision ID: bdfcd01cbf77
Revises: b0e5f0c53d14
Create Date: 2026-06-06 14:14:14.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

# revision identifiers, used by Alembic.
revision: str = "bdfcd01cbf77"
down_revision: Union[str, Sequence[str], None] = "b0e5f0c53d14"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # live_alerts
    op.create_table(
        "live_alerts",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("session_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("affected_entities", pg.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("evidence", pg.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("feature_snapshot", pg.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("timestamp_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("timestamp_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("raw_score", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_live_alerts")),
        sa.CheckConstraint(
            "status IN ('active','acknowledged','dismissed','resolved')",
            name="ck_live_alerts_status",
        ),
        sa.CheckConstraint(
            "severity IN ('critical','high','medium','low','informational')",
            name="ck_live_alerts_severity",
        ),
        sa.CheckConstraint(
            "confidence IN ('low','medium','high','critical')",
            name="ck_live_alerts_confidence",
        ),
    )
    op.create_index("idx_live_alerts_session_id", "live_alerts", ["session_id"], unique=False)
    op.create_index("idx_live_alerts_rule_id", "live_alerts", ["rule_id"], unique=False)
    op.create_index("idx_live_alerts_triggered_at", "live_alerts", ["triggered_at"], unique=False)
    op.create_index(
        "idx_live_alerts_severity_triggered",
        "live_alerts",
        ["severity", "triggered_at"],
        unique=False,
    )
    op.create_index("idx_live_alerts_status", "live_alerts", ["status"], unique=False)

    # alert_events
    op.create_table(
        "alert_events",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("alert_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("actor", sa.String(length=64), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["alert_id"], ["live_alerts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alert_events")),
        sa.CheckConstraint(
            "event_type IN ('created','acknowledged','dismissed','resolved','reopened')",
            name="ck_alert_events_type",
        ),
    )
    op.create_index("idx_alert_events_alert_id", "alert_events", ["alert_id"], unique=False)
    op.create_index("idx_alert_events_created", "alert_events", ["created_at"], unique=False)

    # rule_stats
    op.create_table(
        "rule_stats",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column("evaluations", sa.Integer(), nullable=False),
        sa.Column("hits", sa.Integer(), nullable=False),
        sa.Column("miss", sa.Integer(), nullable=False),
        sa.Column("avg_risk_score", sa.Float(), nullable=False),
        sa.Column("max_risk_score", sa.Float(), nullable=False),
        sa.Column("rolling_window_size", sa.Integer(), nullable=False),
        sa.Column("last_evaluation_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_rule_stats")),
    )
    op.create_index("idx_rule_stats_rule_id", "rule_stats", ["rule_id"], unique=False)
    op.create_index("idx_rule_stats_session_id", "rule_stats", ["session_id"], unique=False)
    op.create_index(
        "idx_rule_stats_last_eval_at", "rule_stats", ["last_evaluation_at"], unique=False
    )
    op.create_index(
        "idx_rule_stats_rule_updated", "rule_stats", ["rule_id", "updated_at"], unique=False
    )

    # rule_performance_history
    op.create_table(
        "rule_performance_history",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("bucket_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("bucket_duration_seconds", sa.Integer(), nullable=False),
        sa.Column("evaluations", sa.Integer(), nullable=False),
        sa.Column("hits", sa.Integer(), nullable=False),
        sa.Column("false_positive_count", sa.Integer(), nullable=False),
        sa.Column("avg_risk_score", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_rule_performance_history")),
    )
    op.create_index("idx_rph_rule_id", "rule_performance_history", ["rule_id"], unique=False)
    op.create_index(
        "idx_rph_bucket_start", "rule_performance_history", ["bucket_start"], unique=False
    )
    op.create_index(
        "idx_rph_rule_bucket", "rule_performance_history", ["rule_id", "bucket_start"], unique=False
    )

    # flow_samples
    op.create_table(
        "flow_samples",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("session_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("src_ip", pg.INET(), nullable=False),
        sa.Column("dst_ip", pg.INET(), nullable=False),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("bytes_total", sa.BigInteger(), nullable=False),
        sa.Column("packets_total", sa.Integer(), nullable=False),
        sa.Column("flow_metadata", pg.JSONB(astext_type=sa.Text()), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_flow_samples")),
    )
    op.create_index("idx_flow_samples_session_id", "flow_samples", ["session_id"], unique=False)
    op.create_index("idx_flow_samples_captured_at", "flow_samples", ["captured_at"], unique=False)
    op.create_index(
        "idx_flow_samples_session_time", "flow_samples", ["session_id", "captured_at"], unique=False
    )


def downgrade() -> None:
    op.drop_index("idx_flow_samples_session_time", table_name="flow_samples")
    op.drop_index("idx_flow_samples_captured_at", table_name="flow_samples")
    op.drop_index("idx_flow_samples_session_id", table_name="flow_samples")
    op.drop_table("flow_samples")

    op.drop_index("idx_rph_rule_bucket", table_name="rule_performance_history")
    op.drop_index("idx_rph_bucket_start", table_name="rule_performance_history")
    op.drop_index("idx_rph_rule_id", table_name="rule_performance_history")
    op.drop_table("rule_performance_history")

    op.drop_index("idx_rule_stats_rule_updated", table_name="rule_stats")
    op.drop_index("idx_rule_stats_last_eval_at", table_name="rule_stats")
    op.drop_index("idx_rule_stats_session_id", table_name="rule_stats")
    op.drop_index("idx_rule_stats_rule_id", table_name="rule_stats")
    op.drop_table("rule_stats")

    op.drop_index("idx_alert_events_created", table_name="alert_events")
    op.drop_index("idx_alert_events_alert_id", table_name="alert_events")
    op.drop_table("alert_events")

    op.drop_index("idx_live_alerts_status", table_name="live_alerts")
    op.drop_index("idx_live_alerts_severity_triggered", table_name="live_alerts")
    op.drop_index("idx_live_alerts_triggered_at", table_name="live_alerts")
    op.drop_index("idx_live_alerts_rule_id", table_name="live_alerts")
    op.drop_index("idx_live_alerts_session_id", table_name="live_alerts")
    op.drop_table("live_alerts")
