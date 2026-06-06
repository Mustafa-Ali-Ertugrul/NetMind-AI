"""Live ingestion service — owns stream, consumer, engine, writers.

``LiveEngineService`` is the top-level component for the live pipeline:

    ingest()
        enqueue an event into an async EventStream
        → background EventConsumer processes batches
        → StreamingRuleEngine accumulates & flushes
        → LiveAlertWriter + RuleStatsWriter persist findings

Designed for forward-compatibility::

    service = LiveEngineService()
    service.bind_writers(sync_session_factory)
    await service.start()
    await service.ingest(event)
    metrics = service.metrics()
    await service.stop()
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from time import monotonic
from typing import Callable
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from backend.ingestion.event import FlowEvent
from backend.ingestion.stream import EventConsumer, EventStream
from backend.live_engine.adaptive_threshold import AdaptiveThresholdTracker
from backend.live_engine.provider import EngineProvider, GlobalEngineProvider
from backend.live_engine.streaming_engine import StreamingRuleEngine
from backend.storage.live_alert_writer import LiveAlertWriter
from backend.storage.rule_stats_writer import RuleStatsWriter

logger = logging.getLogger("netmind.live_engine.service")


@dataclass
class ServiceMetrics:
    """Read-only snapshot of live service counters."""

    queue_size: int = 0
    events_enqueued: int = 0
    events_dropped: int = 0
    events_processed: int = 0
    batches_processed: int = 0
    total_latency_sec: float = 0.0
    alerts_generated: int = 0
    active_sessions: int = 0
    uptime_seconds: float = 0.0


@dataclass
class IngestOutcome:
    """Result of ``LiveEngineService.ingest()``."""

    queued: bool
    session_id: UUID
    stream_qsize: int


SyncSessionFactory = Callable[[], Session]


class _BatchHandler:
    """Process a batch of FlowEvents through the engine and writers.

    This is the ``process_fn`` passed to ``EventConsumer``.
    """

    def __init__(
        self,
        provider: EngineProvider,
        sync_session_factory: SyncSessionFactory | None,
        adaptive_tracker: AdaptiveThresholdTracker | None = None,
    ) -> None:
        self._provider = provider
        self._sync_session_factory = sync_session_factory
        self._adaptive_tracker = adaptive_tracker
        self._engine_injected = False

    async def __call__(self, batch: list[FlowEvent]) -> None:
        """Process a batch: feed each event, then flush.

        Runs in the async consumer coroutine.  The engine.flush() and
        subsequent writes are quick synchronous operations.
        """
        for event in batch:
            engine = self._get_engine(event)
            engine.process_event(event)

        # Flush once per batch (all events in this batch share the engine)
        if batch:
            engine = self._get_engine(batch[-1])
            engine.flush()

    def _get_engine(self, event: FlowEvent) -> StreamingRuleEngine:
        """Resolve the engine for an event's session.

        When a sync session factory is bound the engine gets writers
        injected lazily on first access.
        """
        engine = self._provider.get()
        if not self._engine_injected and self._adaptive_tracker is not None:
            engine._adaptive = self._adaptive_tracker
            self._engine_injected = True
        return engine


class LiveEngineService:
    """Top-level service for live event ingestion and alert generation.

    Usage::

        svc = LiveEngineService()
        svc.bind_writers(some_sync_session_factory)
        await svc.start()
        outcome = await svc.ingest(raw_event)
        # ... later
        await svc.stop()
    """

    def __init__(
        self,
        engine_provider: EngineProvider | None = None,
        *,
        max_queue: int = 10_000,
        batch_size: int = 100,
        flush_interval: float = 5.0,
        adaptive_tracker: AdaptiveThresholdTracker | None = None,
        adaptive_enabled: bool = True,
    ) -> None:
        self._provider = engine_provider or GlobalEngineProvider()
        self._stream = EventStream(max_size=max_queue)
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._consumer: EventConsumer | None = None
        self._sync_session_factory: SyncSessionFactory | None = None
        self._start_time: float | None = None
        self._started = False
        self._adaptive_tracker = adaptive_tracker
        self._adaptive_enabled = adaptive_enabled

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Create and start the background consumer.

        Raises RuntimeError if already started.
        """
        if self._started:
            raise RuntimeError("LiveEngineService is already started")

        handler = _BatchHandler(self._provider, self._sync_session_factory, self._adaptive_tracker)
        self._consumer = EventConsumer(
            self._stream,
            handler,
            batch_size=self._batch_size,
            flush_interval=self._flush_interval,
        )
        await self._consumer.start()
        self._start_time = monotonic()
        self._started = True
        logger.info(
            "LiveEngineService started (batch_size=%d, flush_interval=%.1fs)",
            self._batch_size,
            self._flush_interval,
        )

    async def stop(self) -> None:
        """Stop the background consumer and drain the queue."""
        if self._consumer is not None:
            await self._consumer.stop()
            self._consumer = None
        self._started = False
        self._start_time = None
        logger.info("LiveEngineService stopped")

    # ------------------------------------------------------------------
    # Writer binding (optional, called before start())
    # ------------------------------------------------------------------

    def bind_writers(self, sync_session_factory: SyncSessionFactory) -> None:
        """Bind a sync ``sessionmaker`` so the engine can persist findings.

        The factory creates a new ``Session`` on each flush, used by
        ``LiveAlertWriter`` and ``RuleStatsWriter``.
        """
        self._sync_session_factory = sync_session_factory

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------

    async def ingest(self, event: FlowEvent, session_id: UUID | None = None) -> IngestOutcome:
        """Enqueue a fully-typed FlowEvent into the stream.

        If ``session_id`` is None a new UUID is generated.

        Args:
            event: The typed flow event to enqueue.
            session_id: Logical session identifier.  Auto-generated if None.

        Returns:
            An ``IngestOutcome`` with the assigned session_id.
        """
        sid = session_id or uuid4()
        self._stream.put_nowait(event)
        return IngestOutcome(
            queued=True,
            session_id=sid,
            stream_qsize=self._stream.qsize(),
        )

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def metrics(self) -> ServiceMetrics:
        """Return a snapshot of current service counters."""
        sm = self._stream.metrics()
        # Access the provider's default engine for alert count
        engine = self._provider.get()
        uptime = 0.0
        if self._start_time is not None:
            uptime = monotonic() - self._start_time

        return ServiceMetrics(
            queue_size=sm.events_enqueued - sm.events_consumed,
            events_enqueued=sm.events_enqueued,
            events_dropped=sm.events_dropped,
            events_processed=sm.events_consumed,
            batches_processed=sm.batches_processed,
            total_latency_sec=sm.total_latency_sec,
            alerts_generated=engine.alerts_generated,
            active_sessions=1,  # GlobalEngineProvider always 1
            uptime_seconds=round(uptime, 2),
        )

    # ------------------------------------------------------------------
    # Adaptive threshold stats (opt-in)
    # ------------------------------------------------------------------

    def adaptive_stats(self) -> dict[str, float] | None:
        """Return current adaptive threshold statistics if enabled."""
        if self._adaptive_tracker is None:
            return None
        return self._adaptive_tracker.get_all_stats()
