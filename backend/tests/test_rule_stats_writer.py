"""Tests for RuleStatsWriter — per-rule evaluation statistics."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.storage.database import Base
from backend.storage.models import RuleStats
from backend.storage.rule_stats_writer import RuleStatsWriter


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


class TestRuleStatsWriter:
    def test_record_evaluation_inserts_new_rule(self, db_session):
        writer = RuleStatsWriter(db_session)
        result = writer.record_evaluation("NET-001", triggered=False)
        assert result.success is True
        assert result.count == 1

    def test_record_evaluation_existing_rule_updates(self, db_session):
        writer = RuleStatsWriter(db_session)
        writer.record_evaluation("NET-001", triggered=False)
        result = writer.record_evaluation("NET-001", triggered=True, risk_score=50.0)
        assert result.success is True
        rows = db_session.query(RuleStats).all()
        assert len(rows) == 1  # still one row

    def test_evaluations_counter_increments(self, db_session):
        writer = RuleStatsWriter(db_session)
        writer.record_evaluation("NET-001", triggered=False).count
        writer.record_evaluation("NET-001", triggered=False).count
        writer.record_evaluation("NET-001", triggered=False).count
        row = db_session.query(RuleStats).first()
        assert row.evaluations == 3

    def test_hits_counter_increments_on_trigger(self, db_session):
        writer = RuleStatsWriter(db_session)
        writer.record_evaluation("NET-001", triggered=True)
        writer.record_evaluation("NET-001", triggered=True)
        writer.record_evaluation("NET-001", triggered=False)
        row = db_session.query(RuleStats).first()
        assert row.hits == 2

    def test_miss_increments_when_not_triggered(self, db_session):
        writer = RuleStatsWriter(db_session)
        writer.record_evaluation("NET-001", triggered=False)
        writer.record_evaluation("NET-001", triggered=False)
        writer.record_evaluation("NET-001", triggered=True)
        row = db_session.query(RuleStats).first()
        assert row.miss == 2

    def test_max_risk_score_updates(self, db_session):
        writer = RuleStatsWriter(db_session)
        writer.record_evaluation("NET-001", triggered=True, risk_score=25.0)
        writer.record_evaluation("NET-001", triggered=True, risk_score=80.0)
        writer.record_evaluation("NET-001", triggered=True, risk_score=50.0)
        row = db_session.query(RuleStats).first()
        assert row.max_risk_score == 80.0

    def test_avg_risk_score_incremental_mean(self, db_session):
        writer = RuleStatsWriter(db_session)
        writer.record_evaluation("NET-001", triggered=True, risk_score=0.0)
        writer.record_evaluation("NET-001", triggered=True, risk_score=100.0)
        row = db_session.query(RuleStats).first()
        # After 2 evaluations: avg = 0 + (100 - 0) / 2 = 50.0
        assert row.avg_risk_score == 50.0

    def test_rolling_window_size_default_100(self, db_session):
        writer = RuleStatsWriter(db_session)
        writer.record_evaluation("NET-001", triggered=False)
        row = db_session.query(RuleStats).first()
        assert row.rolling_window_size == 100

    def test_upsert_no_duplicate_rows(self, db_session):
        writer = RuleStatsWriter(db_session)
        for _ in range(5):
            writer.record_evaluation("NET-001", triggered=True)
        rows = db_session.query(RuleStats).all()
        assert len(rows) == 1

    def test_session_id_stored(self, db_session):
        writer = RuleStatsWriter(db_session)
        sid = uuid4()
        writer.record_evaluation("NET-001", triggered=True, session_id=sid)
        row = db_session.query(RuleStats).first()
        assert row.session_id == sid

    def test_session_isolation(self, db_session):
        """Different session_ids produce separate rows."""
        writer = RuleStatsWriter(db_session)
        sid_a = uuid4()
        sid_b = uuid4()
        writer.record_evaluation("NET-001", triggered=True, session_id=sid_a)
        writer.record_evaluation("NET-001", triggered=True, session_id=sid_b)
        rows = db_session.query(RuleStats).all()
        assert len(rows) == 2

    def test_last_evaluation_at_updated(self, db_session):
        writer = RuleStatsWriter(db_session)
        writer.record_evaluation("NET-001", triggered=False)
        row = db_session.query(RuleStats).first()
        first_ts = row.last_evaluation_at
        # Make both naive for comparison (SQLite stores as naive)
        if first_ts.tzinfo is not None:
            first_ts = first_ts.replace(tzinfo=None)
        writer.record_evaluation("NET-001", triggered=False)
        db_session.refresh(row)
        second_ts = row.last_evaluation_at
        if second_ts.tzinfo is not None:
            second_ts = second_ts.replace(tzinfo=None)
        assert second_ts > first_ts, "last_evaluation_at should advance after repeated evaluations"

    def test_record_evaluations_batch(self, db_session):
        writer = RuleStatsWriter(db_session)
        sid = uuid4()
        evals = [
            ("NET-001", True, 80.0, sid),
            ("NET-002", False, 0.0, sid),
            ("NET-003", True, 50.0, sid),
        ]
        result = writer.record_evaluations(evals)
        assert result.success is True
        assert result.count == 3
        rows = db_session.query(RuleStats).all()
        assert len(rows) == 3

    def test_record_evaluations_empty(self, db_session):
        writer = RuleStatsWriter(db_session)
        result = writer.record_evaluations([])
        assert result.success is True
        assert result.count == 0

    def test_avg_risk_score_three_values(self, db_session):
        """Verify incremental mean over 3 evaluations: 0, 50, 100 → expect 50.0."""
        writer = RuleStatsWriter(db_session)
        writer.record_evaluation("NET-001", triggered=True, risk_score=0.0)
        writer.record_evaluation("NET-001", triggered=True, risk_score=50.0)
        writer.record_evaluation("NET-001", triggered=True, risk_score=100.0)
        row = db_session.query(RuleStats).first()
        assert row.avg_risk_score == 50.0
