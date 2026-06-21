"""Bounded async event-streaming infrastructure.

``EventStream`` wraps an ``asyncio.Queue`` with backpressure
(refusing events when the queue is full).  ``EventConsumer`` runs
as a background asyncio task, draining the queue and passing
batched events to a user-supplied coroutine.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from time import monotonic
from typing import Any

from backend.ingestion.event import FlowEvent

logger = logging.getLogger("netmind.ingestion.stream")


@dataclass
class StreamMetrics:
    """Runtime counters for an EventStream."""

    events_enqueued: int = 0
    events_dropped: int = 0
    events_consumed: int = 0
    batches_processed: int = 0
    last_batch_at: float = 0.0
    total_latency_sec: float = 0.0


class EventStream:
    """Bounded asyncio queue for FlowEvent ingestion.

    When ``max_size`` is reached, ``put()`` logs a warning and drops
    the event — preventing OOM under spike load.  Consumers call
    ``get()`` to await the next event.
    """

    def __init__(self, max_size: int = 10_000) -> None:
        self._queue: asyncio.Queue[FlowEvent] = asyncio.Queue(maxsize=max_size)
        self._metrics = StreamMetrics()

    # ------------------------------------------------------------------
    # Producer API
    # ------------------------------------------------------------------

    async def put(self, event: FlowEvent) -> None:
        """Enqueue an event; drop silently if queue is full."""
        try:
            self._queue.put_nowait(event)
            self._metrics.events_enqueued += 1
        except asyncio.QueueFull:
            self._metrics.events_dropped += 1
            logger.warning(
                "EventStream overflow (dropped event from %s → %s)",
                event.src_ip,
                event.dst_ip,
            )

    def put_nowait(self, event: FlowEvent) -> None:
        """Synchronous put for use outside async contexts.

        Also drops silently on overflow.
        """
        try:
            self._queue.put_nowait(event)
            self._metrics.events_enqueued += 1
        except asyncio.QueueFull:
            self._metrics.events_dropped += 1
            logger.warning(
                "EventStream overflow (dropped event from %s → %s)",
                event.src_ip,
                event.dst_ip,
            )

    # ------------------------------------------------------------------
    # Consumer API
    # ------------------------------------------------------------------

    async def get(self) -> FlowEvent:
        """Await and return the next event from the queue."""
        event = await self._queue.get()
        self._metrics.events_consumed += 1
        return event

    def empty(self) -> bool:
        return self._queue.empty()

    def qsize(self) -> int:
        return self._queue.qsize()

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def metrics(self) -> StreamMetrics:
        """Return a snapshot of current counters."""
        return StreamMetrics(
            events_enqueued=self._metrics.events_enqueued,
            events_dropped=self._metrics.events_dropped,
            events_consumed=self._metrics.events_consumed,
            batches_processed=self._metrics.batches_processed,
            last_batch_at=self._metrics.last_batch_at,
            total_latency_sec=self._metrics.total_latency_sec,
        )

    # ------------------------------------------------------------------
    # Lifecycle (for graceful shutdown)
    # ------------------------------------------------------------------

    async def drain(self) -> list[FlowEvent]:
        """Drain remaining events without blocking.  Used during shutdown."""
        remaining: list[FlowEvent] = []
        while not self._queue.empty():
            try:
                remaining.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return remaining


class EventConsumer:
    """Background task that drains EventStream and processes batches.

    Typical use::

        stream = EventStream()
        consumer = EventConsumer(stream, process_fn, batch_size=100, flush_interval=5.0)
        asyncio.create_task(consumer.start())
        # … later …
        await consumer.stop()
    """

    def __init__(
        self,
        stream: EventStream,
        process_fn: Callable[[list[FlowEvent]], Awaitable[None]],
        *,
        batch_size: int = 100,
        flush_interval: float = 5.0,
    ) -> None:
        self._stream = stream
        self._process_fn = process_fn
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._task: asyncio.Task[Any] | None = None
        self._stop_event = asyncio.Event()

    async def start(self) -> None:
        """Launch the background consumer task.

        Raises RuntimeError if called twice without a preceding ``stop()``.
        """
        if self._task is not None and not self._task.done():
            raise RuntimeError("EventConsumer is already running")
        self._stop_event.clear()
        self._task = asyncio.create_task(self._consume(), name="EventConsumer")
        logger.info(
            "EventConsumer started (batch_size=%d flush_interval=%.1fs)",
            self._batch_size,
            self._flush_interval,
        )

    async def stop(self) -> None:
        """Signal the consumer to stop, await completion, then drain queue."""
        if self._task is None:
            return
        self._stop_event.set()
        logger.info("EventConsumer stop requested")
        try:
            await asyncio.wait_for(self._task, timeout=10.0)
        except TimeoutError:
            logger.warning("EventConsumer did not stop within timeout; cancelling")
            self._task.cancel()
        self._task = None

    async def _consume(self) -> None:
        batch: list[FlowEvent] = []
        last_flush = monotonic()

        while not self._stop_event.is_set():
            timeout = max(0.0, self._flush_interval - (monotonic() - last_flush))

            try:
                event = await asyncio.wait_for(self._stream.get(), timeout=timeout)
                batch.append(event)
            except TimeoutError:
                pass  # flush on interval

            # Flush if batch full or interval expired
            if len(batch) >= self._batch_size or monotonic() - last_flush >= self._flush_interval:
                if batch:
                    await self._flush_batch(batch)
                    batch = []
                    last_flush = monotonic()

        # Drain final batch before exit
        remaining = await self._stream.drain()
        if remaining:
            batch.extend(remaining)
        if batch:
            await self._flush_batch(batch)
        logger.info("EventConsumer stopped")

    async def _flush_batch(self, batch: list[FlowEvent]) -> None:
        t0 = monotonic()
        try:
            await self._process_fn(batch)
        except Exception:  # pragma: no cover
            logger.exception("process_fn raised an exception on batch of %d events", len(batch))
            # Consumer keeps running so one bad batch doesn't kill the stream
        latency = monotonic() - t0
        self._stream._metrics.batches_processed += 1
        self._stream._metrics.last_batch_at = monotonic()
        self._stream._metrics.total_latency_sec += latency
        logger.debug("Batch flushed: %d events in %.3fs", len(batch), latency)
