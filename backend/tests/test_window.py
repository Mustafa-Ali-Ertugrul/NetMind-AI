"""Tests for live_engine.window.SlidingWindow."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from ipaddress import IPv4Address

import pytest

from backend.ingestion.event import FlowEvent
from backend.live_engine.window import SlidingWindow


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(**overrides: object) -> FlowEvent:
    """Create a FlowEvent with sensible defaults."""
    kwargs = {
        "src_ip": IPv4Address("192.168.1.1"),
        "dst_ip": IPv4Address("10.0.0.1"),
        "src_port": 12345,
        "dst_port": 80,
        "protocol": "TCP",
        "ts": datetime.utcnow(),
        "payload_bytes": 100,
        "packets": 1,
    }
    kwargs.update(overrides)
    return FlowEvent(**kwargs)  # type: ignore[arg-type]


class _SyncFlushAccumulator:
    """Callable that records the last event list passed to it."""

    def __init__(self) -> None:
        self.last_events: list[FlowEvent] = []

    def __call__(self, events: list[FlowEvent]) -> None:
        self.last_events = events


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_default_window_size_and_slide(self) -> None:
        window = SlidingWindow()
        assert window._window_size == 5.0
        assert window._slide == 1.0

    def test_invalid_window_size_raises(self) -> None:
        with pytest.raises(ValueError, match="window_size"):
            SlidingWindow(window_size=0)

    def test_invalid_slide_raises(self) -> None:
        with pytest.raises(ValueError, match="slide"):
            SlidingWindow(slide=0)

    def test_slide_exceeds_window_raises(self) -> None:
        with pytest.raises(ValueError, match="slide"):
            SlidingWindow(window_size=2.0, slide=3.0)


# ---------------------------------------------------------------------------
# Add / Get semantics
# ---------------------------------------------------------------------------


class TestAddGet:
    def test_add_event_appends_to_current_window(self) -> None:
        window = SlidingWindow()
        window.add_event(_make_event())
        assert window.size == 1
        assert window.total_received == 1

    def test_multiple_events_in_window(self) -> None:
        window = SlidingWindow()
        for _ in range(10):
            window.add_event(_make_event())
        assert window.size == 10
        assert window.total_received == 10

    def test_get_window_contains_events(self) -> None:
        window = SlidingWindow()
        e1 = _make_event()
        e2 = _make_event()
        window.add_event(e1)
        window.add_event(e2)
        events = window.get_window()
        assert len(events) == 2
        # get_window is a snapshot — events remain in buffer
        assert window.size == 2

    def test_empty_window(self) -> None:
        window = SlidingWindow()
        assert window.get_window() == []
        assert window.size == 0

    def test_get_window_is_snapshot_not_destructive(self) -> None:
        window = SlidingWindow()
        window.add_event(_make_event())
        _ = window.get_window()
        assert window.size == 1


# ---------------------------------------------------------------------------
# Time-based eviction
# ---------------------------------------------------------------------------


class TestEviction:
    def test_flush_old_removes_expired_buckets(self) -> None:
        """Events age out after window_size seconds pass."""
        window = SlidingWindow(window_size=0.1, slide=0.05)
        window.add_event(_make_event())
        assert window.size == 1

        time.sleep(0.15)
        expired = window.flush_old()
        assert len(expired) == 1
        assert window.size == 0

    def test_flush_old_keeps_recent_events(self) -> None:
        window = SlidingWindow(window_size=0.5, slide=0.1)
        window.add_event(_make_event())
        expired = window.flush_old()
        assert len(expired) == 0
        assert window.size == 1

    def test_slide_evicts_old_events(self) -> None:
        window = SlidingWindow(window_size=0.1, slide=0.05)
        window.add_event(_make_event())
        time.sleep(0.15)
        window.slide()
        assert window.size == 0
        assert window.total_flushed == 1


# ---------------------------------------------------------------------------
# Sliding correctness
# ---------------------------------------------------------------------------


class TestSliding:
    def test_slide_increments_total_flushed(self) -> None:
        window = SlidingWindow()
        window.slide()
        assert window.total_flushed == 1
        window.slide()
        assert window.total_flushed == 2

    def test_slide_increments_total_received(self) -> None:
        window = SlidingWindow()
        window.add_event(_make_event())
        window.add_event(_make_event())
        window.slide()
        assert window.total_received == 2

    def test_slide_invokes_sync_callback(self) -> None:
        acc = _SyncFlushAccumulator()
        window = SlidingWindow(on_flush=acc)
        e1 = _make_event()
        e2 = _make_event()
        window.add_event(e1)
        window.add_event(e2)
        window.slide()
        assert len(acc.last_events) == 2


# ---------------------------------------------------------------------------
# Memory bounds
# ---------------------------------------------------------------------------


class TestMemoryBounds:
    def test_max_window_events_cap(self) -> None:
        window = SlidingWindow(window_size=10.0, slide=1.0, max_window_events=5)
        for _ in range(10):
            window.add_event(_make_event())
        assert window.size <= 5

    def test_dropped_counter_increments_on_overflow(self) -> None:
        window = SlidingWindow(window_size=10.0, slide=1.0, max_window_events=5)
        for _ in range(10):
            window.add_event(_make_event())
        assert window.total_dropped > 0


# ---------------------------------------------------------------------------
# Async lifecycle
# ---------------------------------------------------------------------------


class TestAsyncLifecycle:
    @pytest.mark.asyncio
    async def test_async_start_stop(self) -> None:
        window = SlidingWindow()
        await window.start()
        assert window._task is not None and not window._task.done()
        await window.stop()
        assert window._task is None

    @pytest.mark.asyncio
    async def test_stop_without_start_is_noop(self) -> None:
        window = SlidingWindow()
        await window.stop()

    @pytest.mark.asyncio
    async def test_double_start_raises(self) -> None:
        window = SlidingWindow()
        await window.start()
        with pytest.raises(RuntimeError, match="already running"):
            await window.start()
        await window.stop()

    @pytest.mark.asyncio
    async def test_async_callback_receives_windowed_events(self) -> None:
        received: list[FlowEvent] = []

        async def async_flush(events: list[FlowEvent]) -> None:
            received.extend(events)

        window = SlidingWindow(
            window_size=0.5,
            slide=0.2,
            on_flush=async_flush,
        )
        await window.start()
        window.add_event(_make_event())
        window.add_event(_make_event())
        await asyncio.sleep(0.6)
        await window.stop()

        assert len(received) > 0


# ---------------------------------------------------------------------------
# Integration smoke
# ---------------------------------------------------------------------------


class TestIntegration:
    def test_window_feeds_streaming_engine(self) -> None:
        """Sync path: SlidingWindow + StreamingRuleEngine end-to-end."""
        from backend.live_engine.streaming_engine import StreamingRuleEngine

        engine = StreamingRuleEngine()
        acc = _SyncFlushAccumulator()

        def on_flush(events: list[FlowEvent]) -> None:
            acc(events)
            for e in events:
                engine.process_event(e)

        window = SlidingWindow(window_size=0.5, slide=0.1, on_flush=on_flush)

        for _ in range(10):
            window.add_event(_make_event())

        window.slide()
        findings, overall = engine.flush()

        assert len(acc.last_events) == 10
        assert isinstance(findings, list)
        assert overall is not None

    @pytest.mark.asyncio
    async def test_async_window_end_to_end(self) -> None:
        """Async path: start -> add events -> stop -> findings."""
        from backend.live_engine.streaming_engine import StreamingRuleEngine

        engine = StreamingRuleEngine()
        received: list[FlowEvent] = []

        async def on_flush(events: list[FlowEvent]) -> None:
            received.extend(events)

        window = SlidingWindow(
            window_size=0.5,
            slide=0.15,
            on_flush=on_flush,
        )

        await window.start()
        for _ in range(5):
            window.add_event(_make_event())
        await asyncio.sleep(0.6)
        await window.stop()

        assert len(received) > 0
        for e in received:
            engine.process_event(e)
        findings, overall = engine.flush()
        assert isinstance(findings, list)
