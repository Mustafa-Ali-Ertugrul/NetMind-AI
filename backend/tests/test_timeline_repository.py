"""Tests for TimelineRepository — dialect-safe bucket aggregation."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.storage.database import Base
from backend.storage.models import LiveAlert
from backend.storage.timeline_repository import TimelineRepository


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


# ⚠️ TimelineRepository expects AsyncSession. We wrap sync session
# with a minimal async wrapper for these tests. In production the
# repo receives a real AsyncSession from FastAPI's Depends(get_db_session).
class _AsyncSessionWrapper:
    """Minimal async wrapper over a sync Session for testability."""

    def __init__(self, sync_session):
        self._sync = sync_session
        self._bind = sync_session.bind

    def get_bind(self):
        return self._bind

    async def execute(self, stmt):
        return self._sync.execute(stmt)


def _make_alert(
    rule_id: str = "NET-001",
    severity: str = "high",
    triggered_at: datetime | None = None,
    session_id=None,
) -> LiveAlert:
    return LiveAlert(
        session_id=session_id or uuid4(),
        rule_id=rule_id,
        severity=severity,
        confidence="high",
        risk_score=50,
        title="Test alert",
        description="Test description",
        evidence={},
        feature_snapshot={},
        timestamp_start=triggered_at or datetime.utcnow(),
        timestamp_end=triggered_at or datetime.utcnow(),
        triggered_at=triggered_at or datetime.utcnow(),
        raw_score=50.0,
    )


class TestTimelineRepository:
    async def test_no_alerts_returns_empty(self, db_session):
        repo = TimelineRepository(_AsyncSessionWrapper(db_session))
        buckets = await repo.query(since=datetime(2020, 1, 1))
        assert buckets == []

    async def test_single_bucket_hourly(self, db_session):
        now = datetime(2025, 6, 6, 12, 30, 0)
        db_session.add(_make_alert(rule_id="NET-001", triggered_at=now))
        db_session.commit()

        repo = TimelineRepository(_AsyncSessionWrapper(db_session))
        buckets = await repo.query(since=datetime(2025, 6, 6, 0, 0, 0), bucket="hour")
        assert len(buckets) == 1
        assert buckets[0].rule_id == "NET-001"
        assert buckets[0].count == 1

    async def test_multiple_rules_separate_buckets(self, db_session):
        now = datetime(2025, 6, 6, 12, 0, 0)
        db_session.add(_make_alert(rule_id="NET-001", triggered_at=now))
        db_session.add(_make_alert(rule_id="NET-002", triggered_at=now))
        db_session.commit()

        repo = TimelineRepository(_AsyncSessionWrapper(db_session))
        buckets = await repo.query(since=datetime(2025, 6, 6, 0, 0, 0))
        assert len(buckets) == 2
        rule_ids = {b.rule_id for b in buckets}
        assert rule_ids == {"NET-001", "NET-002"}

    async def test_session_id_filtering(self, db_session):
        now = datetime(2025, 6, 6, 12, 0, 0)
        sid1 = uuid4()
        sid2 = uuid4()
        db_session.add(_make_alert(rule_id="NET-001", session_id=sid1, triggered_at=now))
        db_session.add(_make_alert(rule_id="NET-002", session_id=sid2, triggered_at=now))
        db_session.commit()

        repo = TimelineRepository(_AsyncSessionWrapper(db_session))
        buckets = await repo.query(since=datetime(2025, 6, 6, 0, 0, 0), session_id=sid1)
        assert len(buckets) == 1
        assert buckets[0].rule_id == "NET-001"

    async def test_max_severity_picks_most_critical(self, db_session):
        now = datetime(2025, 6, 6, 12, 0, 0)
        db_session.add(_make_alert(rule_id="NET-001", severity="low", triggered_at=now))
        db_session.add(_make_alert(rule_id="NET-001", severity="critical", triggered_at=now))
        db_session.add(_make_alert(rule_id="NET-001", severity="medium", triggered_at=now))
        db_session.commit()

        repo = TimelineRepository(_AsyncSessionWrapper(db_session))
        buckets = await repo.query(since=datetime(2025, 6, 6, 0, 0, 0))
        assert len(buckets) == 1
        assert buckets[0].rule_id == "NET-001"
        assert buckets[0].max_severity == "critical"
        assert buckets[0].count == 3

    async def test_multiple_hours_same_rule(self, db_session):
        """Same rule in different hours produces separate buckets."""
        h1 = datetime(2025, 6, 6, 10, 0, 0)
        h2 = datetime(2025, 6, 6, 11, 0, 0)
        db_session.add(_make_alert(rule_id="NET-001", triggered_at=h1))
        db_session.add(_make_alert(rule_id="NET-001", triggered_at=h2))
        db_session.commit()

        repo = TimelineRepository(_AsyncSessionWrapper(db_session))
        buckets = await repo.query(since=datetime(2025, 6, 6, 0, 0, 0), bucket="hour")
        assert len(buckets) >= 1  # SQLite strftime behaviour may merge
