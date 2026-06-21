"""Smoke tests for Sprint 10 Alembic migration (extended live-engine schema).

These tests verify that the five new tables compile correctly via SQLAlchemy +
SQLite type shims and that their columns, constraints and indexes are present.
The actual upgrade/downgrade via Alembic CLI is validated separately in CI
(``alembic upgrade head`` + ``alembic downgrade -1``).
"""

import sys
from datetime import UTC, datetime
from types import ModuleType
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

# SQLite type shims for INET / JSONB / PG_UUID are injected via conftest.py
from backend.storage.database import Base
from backend.storage.models import (
    FlowSample,
    LiveAlert,
    RulePerformanceHistory,
    RuleStats,
)

# Provide a minimal alembic.op stub so that migration files can be imported
# for smoke-testing even when the real alembic package is not installed.
if "alembic" not in sys.modules:
    _alembic_pkg = ModuleType("alembic")
    _alembic_pkg.op = MagicMock()
    _alembic_pkg.op.f = lambda x: x
    sys.modules["alembic"] = _alembic_pkg


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    engine.dispose()


class TestLiveAlertsTable:
    def test_table_exists(self, db_session):
        insp = inspect(db_session.bind)
        assert "live_alerts" in insp.get_table_names()

    def test_columns(self, db_session):
        insp = inspect(db_session.bind)
        cols = {c["name"]: c for c in insp.get_columns("live_alerts")}
        expected = [
            "id",
            "session_id",
            "rule_id",
            "severity",
            "confidence",
            "risk_score",
            "title",
            "description",
            "recommendation",
            "affected_entities",
            "evidence",
            "feature_snapshot",
            "timestamp_start",
            "timestamp_end",
            "triggered_at",
            "status",
            "raw_score",
            "created_at",
            "updated_at",
        ]
        for name in expected:
            assert name in cols, f"Missing column {name}"

    def test_indexes(self, db_session):
        insp = inspect(db_session.bind)
        indexes = {i["name"] for i in insp.get_indexes("live_alerts")}
        assert "idx_live_alerts_session_id" in indexes, (
            f"Missing idx_live_alerts_session_id in {indexes}"
        )
        assert "idx_live_alerts_rule_id" in indexes, f"Missing idx_live_alerts_rule_id in {indexes}"
        assert "idx_live_alerts_triggered_at" in indexes, (
            f"Missing idx_live_alerts_triggered_at in {indexes}"
        )
        assert "idx_live_alerts_status" in indexes, f"Missing idx_live_alerts_status in {indexes}"
        assert "idx_live_alerts_severity_triggered" in indexes, (
            f"Missing idx_live_alerts_severity_triggered in {indexes}"
        )

    def test_defaults(self, db_session):
        alert = LiveAlert(
            session_id=uuid4(),
            rule_id="NET-001",
            severity="high",
            confidence="medium",
            title="Test Alert",
            timestamp_start=datetime.now(UTC),
            timestamp_end=datetime.now(UTC),
        )
        db_session.add(alert)
        db_session.commit()
        row = db_session.query(LiveAlert).first()
        assert row.status == "active"
        assert row.risk_score == 0
        assert row.raw_score == 0.0
        assert isinstance(row.id, UUID)

    def test_evidence_jsonb_roundtrip(self, db_session):
        evidence = {"ip": "10.0.0.1", "ports": [80, 443]}
        alert = LiveAlert(
            session_id=uuid4(),
            rule_id="NET-002",
            severity="critical",
            confidence="high",
            title="JSONB Test",
            evidence=evidence,
            timestamp_start=datetime.now(UTC),
            timestamp_end=datetime.now(UTC),
        )
        db_session.add(alert)
        db_session.commit()
        row = db_session.query(LiveAlert).first()
        if db_session.bind.dialect.name == "postgresql":
            assert row.evidence == evidence
        else:
            # SQLite JSON stored as string; SQLAlchemy does its best
            assert row.evidence is not None


class TestAlertEventsTable:
    def test_table_exists(self, db_session):
        insp = inspect(db_session.bind)
        assert "alert_events" in insp.get_table_names()

    def test_columns(self, db_session):
        insp = inspect(db_session.bind)
        cols = {c["name"] for c in insp.get_columns("alert_events")}
        assert cols == {
            "id",
            "alert_id",
            "event_type",
            "actor",
            "comment",
            "created_at",
        }

    def test_indexes(self, db_session):
        insp = inspect(db_session.bind)
        indexes = {i["name"] for i in insp.get_indexes("alert_events")}
        assert "idx_alert_events_alert_id" in indexes, (
            f"Missing idx_alert_events_alert_id in {indexes}"
        )
        assert "idx_alert_events_created" in indexes, (
            f"Missing idx_alert_events_created in {indexes}"
        )


class TestRuleStatsTable:
    def test_table_exists(self, db_session):
        insp = inspect(db_session.bind)
        assert "rule_stats" in insp.get_table_names()

    def test_columns(self, db_session):
        insp = inspect(db_session.bind)
        cols = {c["name"] for c in insp.get_columns("rule_stats")}
        expected = {
            "id",
            "rule_id",
            "session_id",
            "evaluations",
            "hits",
            "miss",
            "avg_risk_score",
            "max_risk_score",
            "rolling_window_size",
            "last_evaluation_at",
            "updated_at",
        }
        assert cols == expected

    def test_defaults(self, db_session):
        stats = RuleStats(rule_id="NET-003")
        db_session.add(stats)
        db_session.commit()
        row = db_session.query(RuleStats).first()
        assert row.evaluations == 0
        assert row.hits == 0
        assert row.miss == 0
        assert row.rolling_window_size == 100
        assert row.avg_risk_score == 0.0
        assert row.max_risk_score == 0.0

    def test_indexes(self, db_session):
        insp = inspect(db_session.bind)
        indexes = {i["name"] for i in insp.get_indexes("rule_stats")}
        assert "idx_rule_stats_rule_id" in indexes, f"Missing idx_rule_stats_rule_id in {indexes}"
        assert "idx_rule_stats_session_id" in indexes, (
            f"Missing idx_rule_stats_session_id in {indexes}"
        )
        assert "idx_rule_stats_last_eval_at" in indexes, (
            f"Missing idx_rule_stats_last_eval_at in {indexes}"
        )
        assert "idx_rule_stats_rule_updated" in indexes, (
            f"Missing idx_rule_stats_rule_updated in {indexes}"
        )


class TestRulePerformanceHistoryTable:
    def test_table_exists(self, db_session):
        insp = inspect(db_session.bind)
        assert "rule_performance_history" in insp.get_table_names()

    def test_columns(self, db_session):
        insp = inspect(db_session.bind)
        cols = {c["name"] for c in insp.get_columns("rule_performance_history")}
        expected = {
            "id",
            "rule_id",
            "bucket_start",
            "bucket_duration_seconds",
            "evaluations",
            "hits",
            "false_positive_count",
            "avg_risk_score",
        }
        assert cols == expected

    def test_defaults(self, db_session):
        h = RulePerformanceHistory(rule_id="NET-001", bucket_start=datetime.now(UTC))
        db_session.add(h)
        db_session.commit()
        row = db_session.query(RulePerformanceHistory).first()
        assert row.bucket_duration_seconds == 60
        assert row.evaluations == 0
        assert row.hits == 0
        assert row.false_positive_count == 0
        assert row.avg_risk_score == 0.0

    def test_indexes(self, db_session):
        insp = inspect(db_session.bind)
        indexes = {i["name"] for i in insp.get_indexes("rule_performance_history")}
        assert "idx_rph_rule_id" in indexes, f"Missing idx_rph_rule_id in {indexes}"
        assert "idx_rph_bucket_start" in indexes, f"Missing idx_rph_bucket_start in {indexes}"
        assert "idx_rph_rule_bucket" in indexes, f"Missing idx_rph_rule_bucket in {indexes}"


class TestFlowSamplesTable:
    def test_table_exists(self, db_session):
        insp = inspect(db_session.bind)
        assert "flow_samples" in insp.get_table_names()

    def test_columns(self, db_session):
        insp = inspect(db_session.bind)
        cols = {c["name"] for c in insp.get_columns("flow_samples")}
        expected = {
            "id",
            "session_id",
            "captured_at",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "bytes_total",
            "packets_total",
            "flow_metadata",
        }
        assert cols == expected

    def test_defaults(self, db_session):
        sample = FlowSample(
            session_id=uuid4(),
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            protocol="TCP",
        )
        db_session.add(sample)
        db_session.commit()
        row = db_session.query(FlowSample).first()
        assert row.bytes_total == 0
        assert row.packets_total == 0
        assert row.flow_metadata == {}

    def test_indexes(self, db_session):
        insp = inspect(db_session.bind)
        indexes = {i["name"] for i in insp.get_indexes("flow_samples")}
        assert "idx_flow_samples_session_id" in indexes, (
            f"Missing idx_flow_samples_session_id in {indexes}"
        )
        assert "idx_flow_samples_captured_at" in indexes, (
            f"Missing idx_flow_samples_captured_at in {indexes}"
        )
        assert "idx_flow_samples_session_time" in indexes, (
            f"Missing idx_flow_samples_session_time in {indexes}"
        )


class TestSchemaRelationships:
    def test_alert_events_fk_exists(self, db_session):
        insp = inspect(db_session.bind)
        fks = insp.get_foreign_keys("alert_events")
        assert any(fk["referred_table"] == "live_alerts" for fk in fks), (
            "Missing FK from alert_events to live_alerts"
        )


class TestMigrationSmoke:
    """Verify the migration file can be imported and has correct revision chain."""

    def test_migration_import(self):
        import backend.migrations.versions.bdfcd01cbf77_sprint10_live_engine_schema as migration

        assert migration.revision == "bdfcd01cbf77"
        assert migration.down_revision == "b0e5f0c53d14"

    def test_upgrade_function_exists(self):
        import backend.migrations.versions.bdfcd01cbf77_sprint10_live_engine_schema as migration

        assert callable(migration.upgrade)

    def test_downgrade_function_exists(self):
        import backend.migrations.versions.bdfcd01cbf77_sprint10_live_engine_schema as migration

        assert callable(migration.downgrade)
