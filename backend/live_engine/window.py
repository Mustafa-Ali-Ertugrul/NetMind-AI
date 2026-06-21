"""Time-windowed event buffer with auto-flush for streaming pipeline.

``SlidingWindow`` sits between ``EventStream`` and
``StreamingRuleEngine``, maintaining a sliding window of recent
``FlowEvent`` objects.  On every *slide* tick the window advances:
expired events are evicted and the remaining windowed events are
passed to a user-supplied callback (typically a wrapper around
``StreamingRuleEngine.process_event``).

Usage (sync / test mode)::

    engine = StreamingRuleEngine()
    window = SlidingWindow(on_flush=lambda evts: [engine.process_event(e) for e in evts])
    window.add_event(event1)
    window.slide()

Usage (async production mode)::

    window = SlidingWindow(on_flush=my_async_fn)
    await window.start()
    await window.aadd_event(event1)
    # ...
    await window.stop()

Memory is bounded by **max_window_events** — when the cap is exceeded
oldest buckets are dropped (FIFO).  No engine or rule logic lives here;
this is exclusively a time-slicing layer.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from time import monotonic
from typing import Any

from backend.ingestion.event import FlowEvent

logger = logging.getLogger("netmind.live_engine.window")


@dataclass
class _Bucket:
    """A single time-aligned bucket holding events for one slide interval."""

    start_ts: float
    events: list[FlowEvent] = field(default_factory=list)


class SlidingWindow:
    """Time-windowed event buffer with periodic flush.

    Parameters
    ----------
    window_size : float
        Width of the active window in seconds (default 5.0).
    slide : float
        Interval between ticks in seconds (default 1.0).
    on_flush : Callable[[list[FlowEvent]], Any] | None
        Callback invoked on each tick with the events currently in
        the window.  Accepts both sync and async callables.
    max_window_events : int
        Hard cap on total buffered events (default 50_000).  When
        exceeded the oldest bucket(s) are dropped (FIFO).
    """

    def __init__(
        self,
        window_size: float = 5.0,
        slide: float = 1.0,
        on_flush: Callable[[list[FlowEvent]], Any] | None = None,
        max_window_events: int = 50_000,
    ) -> None:
        if window_size <= 0:
            raise ValueError("window_size must be > 0")
        if slide <= 0:
            raise ValueError("slide must be > 0")
        if slide > window_size:
            raise ValueError("slide must be <= window_size")

        self._window_size = window_size
        self._slide = slide
        self._on_flush = on_flush
        self._max_window_events = max_window_events

        self._buckets: deque[_Bucket] = deque()
        self._total_received = 0
        self._total_flushed = 0
        self._total_dropped = 0

        # Async lifecycle
        self._task: asyncio.Task[Any] | None = None
        self._stop_event = asyncio.Event()

    # ------------------------------------------------------------------
    # Properties / metrics
    # ------------------------------------------------------------------

    @property
    def size(self) -> int:
        """Total events currently buffered across all buckets."""
        return sum(len(b.events) for b in self._buckets)

    @property
    def total_received(self) -> int:
        return self._total_received

    @property
    def total_flushed(self) -> int:
        """Number of ``slide()`` ticks executed."""
        return self._total_flushed

    @property
    def total_dropped(self) -> int:
        """Number of events dropped due to ``max_window_events`` cap."""
        return self._total_dropped

    # ------------------------------------------------------------------
    # Producer API
    # ------------------------------------------------------------------

    def add_event(self, event: FlowEvent) -> None:
        """Add a FlowEvent to the current time bucket.

        If the total buffer exceeds **max_window_events** the oldest
        events are silently dropped (FIFO).  This method is safe to
        call from synchronous contexts (HTTP handlers, queue drains).
        """
        self._total_received += 1
        self._ensure_bucket(monotonic()).events.append(event)
        self._enforce_cap()

    async def aadd_event(self, event: FlowEvent) -> None:
        """Async variant of ``add_event``."""
        self.add_event(event)

    # ------------------------------------------------------------------
    # Consumer API
    # ------------------------------------------------------------------

    def get_window(self, now: float | None = None) -> list[FlowEvent]:
        """Return all events within ``[now - window_size, now]``.

        This is a snapshot — events remain in the buffer until
        ``flush_old()`` or ``slide()`` removes them.
        """
        cutoff = (now if now is not None else monotonic()) - self._window_size
        result: list[FlowEvent] = []
        for bucket in self._buckets:
            if bucket.start_ts >= cutoff:
                result.extend(bucket.events)
        return result

    def flush_old(self, now: float | None = None) -> list[FlowEvent]:
        """Remove and return events from buckets outside the window.

        Buckets with ``start_ts < now - window_size`` are evicted.
        """
        cutoff = (now if now is not None else monotonic()) - self._window_size
        expired: list[FlowEvent] = []
        while self._buckets and self._buckets[0].start_ts < cutoff:
            expired.extend(self._buckets.popleft().events)
        return expired

    def slide(self, now: float | None = None) -> None:
        """Advance the window by one tick.

        Steps:
        1. Evict expired buckets via ``flush_old()``.
        2. Collect remaining windowed events.
        3. Invoke ``on_flush`` with those events (sync callbacks only;
           async callbacks are handled by the background ``_run`` task).
        """
        self._total_flushed += 1
        self.flush_old(now or monotonic())
        window_events = self.get_window(now)
        if window_events and self._on_flush is not None:
            if asyncio.iscoroutinefunction(self._on_flush):
                logger.warning(
                    "slide() called with async on_flush — "
                    "callback will not be awaited; use start() for async"
                )
            else:
                self._on_flush(window_events)

    # ------------------------------------------------------------------
    # Async lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Launch a background task that ticks every ``slide`` seconds."""
        if self._task is not None and not self._task.done():
            raise RuntimeError("SlidingWindow is already running")
        self._stop_event.clear()
        self._task = asyncio.create_task(self._run(), name="SlidingWindow")
        logger.info(
            "SlidingWindow started (window=%.1fs slide=%.1fs max_events=%d)",
            self._window_size,
            self._slide,
            self._max_window_events,
        )

    async def stop(self) -> None:
        """Signal graceful shutdown, await background task, then final flush."""
        if self._task is None:
            return
        self._stop_event.set()
        try:
            await asyncio.wait_for(self._task, timeout=5.0)
        except TimeoutError:
            logger.warning("SlidingWindow task did not stop within timeout; cancelling")
            self._task.cancel()
        self._task = None

        # Final flush of remaining events
        await self._flush_remaining()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run(self) -> None:
        """Background tick loop."""
        while not self._stop_event.is_set():
            await asyncio.sleep(self._slide)
            await self._tick(monotonic())

    async def _tick(self, now: float) -> None:
        """One tick: flush old, collect window, invoke callback (async-safe)."""
        self.flush_old(now)
        window_events = self.get_window(now)
        if window_events and self._on_flush is not None:
            if asyncio.iscoroutinefunction(self._on_flush):
                await self._on_flush(window_events)
            else:
                self._on_flush(window_events)

    async def _flush_remaining(self) -> None:
        """Drain and callback with any events still in the buffer."""
        now = monotonic()
        self.flush_old(now)
        remaining = self.get_window(now)
        if remaining and self._on_flush is not None:
            if asyncio.iscoroutinefunction(self._on_flush):
                await self._on_flush(remaining)
            else:
                self._on_flush(remaining)

    def _ensure_bucket(self, now: float) -> _Bucket:
        """Return (or create) the time-aligned bucket for *now*."""
        start_ts = (now // self._slide) * self._slide
        if self._buckets and self._buckets[-1].start_ts == start_ts:
            return self._buckets[-1]
        bucket = _Bucket(start_ts=start_ts)
        self._buckets.append(bucket)
        return bucket

    def _enforce_cap(self) -> None:
        """Drop oldest bucket(s) if total buffered exceeds max."""
        while self.size > self._max_window_events and self._buckets:
            dropped = self._buckets.popleft()
            self._total_dropped += len(dropped.events)
            logger.warning(
                "SlidingWindow cap reached; dropped %d events from bucket @ %.3f",
                len(dropped.events),
                dropped.start_ts,
            )
