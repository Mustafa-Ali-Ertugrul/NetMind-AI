"""Tests for the LiveRiskAggregator."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock

import pytest

from backend.analytics.aggregators.live_risk import LiveRiskAggregator
from backend.api.schemas import RiskStreamResponse


class _MockResult:
    """Mimics SQLAlchemy Result for mock queries."""

    def __init__(self, rows: list = None, scalar_val=None):
        self._rows = rows or []
        self._scalar_val = scalar_val

    def scalar(self):
        return self._scalar_val

    def all(self):
        return self._rows

    def __iter__(self):
        return iter(self._rows)


class _Row:
    """Minimal row-like object with attribute access."""

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class TestLiveRiskAggregator:
    """Tests for LiveRiskAggregator."""

    @staticmethod
    def _ts(minute: int, second: int = 0) -> datetime:
        return datetime(2026, 6, 6, 10, minute, second)

    async def test_empty_window_returns_zero_risk(self):
        db = AsyncMock()
        # Three queries: avg → None, top rules → empty, all assessments → empty
        db.execute.side_effect = [
            _MockResult(scalar_val=None),  # avg risk
            _MockResult([]),  # top rules
            _MockResult([]),  # all assessments
        ]
        agg = LiveRiskAggregator()
        result = await agg.aggregate(db, window="5m")
        assert isinstance(result, RiskStreamResponse)
        assert result.current.risk_avg == 0.0
        assert result.current.threat_level == "low"
        assert result.current.top_rules_triggered == []
        assert result.series == []

    async def test_returns_risk_snapshot(self):
        db = AsyncMock()
        db.execute.side_effect = [
            _MockResult(scalar_val=45.0),  # avg = 45/100 = 0.45
            _MockResult([]),  # no rule alerts
            _MockResult([]),  # no assessments
        ]
        agg = LiveRiskAggregator()
        result = await agg.aggregate(db, window="5m")
        assert result.current.risk_avg == 0.45
        assert result.current.threat_level == "medium"
        assert result.window == "5m"

    async def test_threat_level_critical(self):
        db = AsyncMock()
        db.execute.side_effect = [
            _MockResult(scalar_val=85.0),  # 0.85
            _MockResult([]),
            _MockResult([]),
        ]
        agg = LiveRiskAggregator()
        result = await agg.aggregate(db, window="5m")
        assert result.current.threat_level == "critical"

    async def test_threat_level_high(self):
        db = AsyncMock()
        db.execute.side_effect = [
            _MockResult(scalar_val=60.0),  # 0.60
            _MockResult([]),
            _MockResult([]),
        ]
        agg = LiveRiskAggregator()
        result = await agg.aggregate(db, window="5m")
        assert result.current.threat_level == "high"

    async def test_threat_level_low(self):
        db = AsyncMock()
        db.execute.side_effect = [
            _MockResult(scalar_val=10.0),  # 0.10
            _MockResult([]),
            _MockResult([]),
        ]
        agg = LiveRiskAggregator()
        result = await agg.aggregate(db, window="5m")
        assert result.current.threat_level == "low"

    async def test_top_rules_triggered(self):
        db = AsyncMock()
        db.execute.side_effect = [
            _MockResult(scalar_val=50.0),
            _MockResult(
                [
                    _Row(rule_id="rule-1", cnt=10),
                    _Row(rule_id="rule-2", cnt=5),
                ]
            ),
            _MockResult([]),
        ]
        agg = LiveRiskAggregator()
        result = await agg.aggregate(db, window="5m")
        assert len(result.current.top_rules_triggered) == 2
        assert result.current.top_rules_triggered[0] == "rule-1"
        assert result.current.top_rules_triggered[1] == "rule-2"

    async def test_returns_minute_bucketed_series(self):
        db = AsyncMock()
        t1 = self._ts(0, 12)  # 10:00:12 → bucket 10:00
        t2 = self._ts(0, 45)  # 10:00:45 → bucket 10:00
        t3 = self._ts(1, 5)  # 10:01:05 → bucket 10:01

        db.execute.side_effect = [
            _MockResult(scalar_val=50.0),
            _MockResult([]),  # no rules
            _MockResult(
                [
                    _Row(risk_score=30, created_at=t1),
                    _Row(risk_score=70, created_at=t2),
                    _Row(risk_score=40, created_at=t3),
                ]
            ),
        ]
        agg = LiveRiskAggregator()
        result = await agg.aggregate(db, window="5m")
        assert len(result.series) == 2

        # First bucket: 10:00 — avg(30, 70) = 50 → 0.5
        bucket0 = result.series[0]
        assert bucket0.timestamp.minute == 0
        assert bucket0.risk_avg == 0.5
        assert bucket0.count == 2

        # Second bucket: 10:01 — avg(40) = 40 → 0.4
        bucket1 = result.series[1]
        assert bucket1.timestamp.minute == 1
        assert bucket1.risk_avg == 0.4
        assert bucket1.count == 1

    async def test_invalid_window_raises(self):
        db = AsyncMock()
        agg = LiveRiskAggregator()
        with pytest.raises(ValueError, match="Invalid window format"):
            await agg.aggregate(db, window="xyz")
