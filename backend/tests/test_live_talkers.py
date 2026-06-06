"""Tests for the LiveTalkerAggregator."""

from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from backend.analytics.aggregators.live_talkers import LiveTalkerAggregator
from backend.api.schemas import LiveTalkersResponse


class _MockResult:
    """Mimics SQLAlchemy Result.scalars().all() for mock queries."""

    def __init__(self, rows: list):
        self._rows = rows

    def scalar(self):
        return self._rows[0] if self._rows else None

    def all(self):
        return self._rows

    def __iter__(self):
        return iter(self._rows)


class _Row:
    """Minimal row-like object with attribute access."""

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class TestLiveTalkerAggregator:
    """Tests for LiveTalkerAggregator."""

    @staticmethod
    def _row(**kwargs):
        return type("Row", (), kwargs)()

    async def test_empty_window_returns_empty_talkers(self):
        db = AsyncMock()
        # Pcap ID subquery returns nothing
        db.execute.return_value = _MockResult([])
        agg = LiveTalkerAggregator()
        result = await agg.aggregate(db, window="5m", limit=10)
        assert isinstance(result, LiveTalkersResponse)
        assert result.talkers == []

    async def test_returns_src_and_dst_talkers(self):
        db = AsyncMock()

        pcap_id = uuid4()

        db.execute.side_effect = [
            _MockResult(  # src rows
                [
                    self._row(src_ip="10.0.0.1", bytes=1000, packets=10),
                    self._row(src_ip="10.0.0.2", bytes=500, packets=5),
                ]
            ),
            _MockResult(  # dst rows
                [
                    self._row(dst_ip="10.0.0.3", bytes=800, packets=8),
                ]
            ),
        ]

        agg = LiveTalkerAggregator()
        result = await agg.aggregate(db, window="5m", limit=10)

        assert len(result.talkers) == 3
        # Sorted by bytes descending
        assert result.talkers[0].ip == "10.0.0.1"
        assert result.talkers[0].direction == "src"
        assert result.talkers[0].bytes == 1000
        assert result.talkers[1].ip == "10.0.0.3"
        assert result.talkers[1].direction == "dst"
        assert result.talkers[2].ip == "10.0.0.2"
        assert result.talkers[2].direction == "src"

    async def test_deduplicates_ip_keeps_highest_bytes(self):
        db = AsyncMock()

        db.execute.side_effect = [
            _MockResult(
                [
                    self._row(src_ip="10.0.0.1", bytes=200, packets=2),
                ]
            ),
            _MockResult(
                [
                    self._row(dst_ip="10.0.0.1", bytes=1000, packets=10),
                ]
            ),
        ]

        agg = LiveTalkerAggregator()
        result = await agg.aggregate(db, window="5m", limit=10)

        # 10.0.0.1 appears as both src and dst — keep dst (higher bytes)
        assert len(result.talkers) == 1
        assert result.talkers[0].ip == "10.0.0.1"
        assert result.talkers[0].direction == "dst"
        assert result.talkers[0].bytes == 1000

    async def test_honours_limit(self):
        db = AsyncMock()

        db.execute.side_effect = [
            _MockResult(
                [self._row(src_ip=f"10.0.0.{i}", bytes=i * 100, packets=i) for i in range(1, 6)]
            ),
            _MockResult(
                [self._row(dst_ip=f"10.0.1.{i}", bytes=i * 200, packets=i) for i in range(1, 4)]
            ),
        ]

        agg = LiveTalkerAggregator()
        result = await agg.aggregate(db, window="5m", limit=3)

        assert len(result.talkers) <= 3

    async def test_invalid_window_raises(self):
        db = AsyncMock()
        agg = LiveTalkerAggregator()
        with pytest.raises(ValueError, match="Invalid window format"):
            await agg.aggregate(db, window="abc")
