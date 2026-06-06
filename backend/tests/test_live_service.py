"""Tests for LiveEngineService — lifecycle, ingest, metrics."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from backend.ingestion.event import FlowEvent
from backend.live_engine.provider import GlobalEngineProvider
from backend.live_engine.service import LiveEngineService
from ipaddress import IPv4Address


def _make_event(
    src_ip: str = "10.0.0.5",
    dst_ip: str = "8.8.8.8",
    src_port: int = 51515,
    dst_port: int = 443,
    protocol: str = "TCP",
    **kwargs,
) -> FlowEvent:
    return FlowEvent(
        src_ip=IPv4Address(src_ip),
        dst_ip=IPv4Address(dst_ip),
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        **kwargs,
    )


class TestLiveEngineServiceLifecycle:
    """start(), stop(), double-start guards."""

    async def test_start_creates_consumer(self):
        svc = LiveEngineService()
        assert svc._consumer is None
        await svc.start()
        assert svc._consumer is not None
        await svc.stop()

    async def test_double_start_raises(self):
        svc = LiveEngineService()
        await svc.start()
        with pytest.raises(RuntimeError, match="already started"):
            await svc.start()
        await svc.stop()

    async def test_start_stop_is_idempotent(self):
        svc = LiveEngineService()
        await svc.start()
        await svc.stop()
        # second stop should not raise
        await svc.stop()


class TestLiveEngineServiceIngest:
    """ingest() enqueues events and returns correct outcomes."""

    async def test_ingest_generates_session_id_when_absent(self):
        svc = LiveEngineService()
        await svc.start()
        try:
            event = _make_event()
            outcome = await svc.ingest(event)
            assert outcome.queued is True
            assert isinstance(outcome.session_id, UUID)
            assert outcome.stream_qsize >= 0
        finally:
            await svc.stop()

    async def test_ingest_preserves_provided_session_id(self):
        svc = LiveEngineService()
        await svc.start()
        try:
            sid = uuid4()
            event = _make_event()
            outcome = await svc.ingest(event, session_id=sid)
            assert outcome.session_id == sid
        finally:
            await svc.stop()

    async def test_ingest_increments_event_count(self):
        svc = LiveEngineService()
        await svc.start()
        try:
            m1 = svc.metrics()
            for _ in range(5):
                await svc.ingest(_make_event())
            m2 = svc.metrics()
            assert m2.events_enqueued == m1.events_enqueued + 5
        finally:
            await svc.stop()


class TestLiveEngineServiceMetrics:
    """metrics() returns consistent counters."""

    async def test_metrics_initial_state(self):
        svc = LiveEngineService()
        await svc.start()
        try:
            m = svc.metrics()
            assert m.queue_size >= 0
            assert m.events_enqueued >= 0
            assert m.events_dropped >= 0
            assert m.alerts_generated >= 0
            assert m.active_sessions == 1
            assert m.uptime_seconds >= 0
        finally:
            await svc.stop()

    async def test_metrics_uptime_grows(self):
        svc = LiveEngineService()
        await svc.start()
        try:
            m1 = svc.metrics()
            m2 = svc.metrics()
            assert m2.uptime_seconds >= m1.uptime_seconds
        finally:
            await svc.stop()

    async def test_engine_provider_default(self):
        """Default provider is GlobalEngineProvider."""
        svc = LiveEngineService()
        assert isinstance(svc._provider, GlobalEngineProvider)
