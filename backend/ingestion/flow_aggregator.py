"""Streaming flow aggregator: FlowEvent → FlowRecord.

Mirrors ``feature_extractor.flow_builder._FlowAccumulator`` and
``FlowBuilder`` but operates on ``FlowEvent`` objects rather than
``ParsedPacket``.

Key differences from batch FlowBuilder:

- Accepts ``FlowEvent`` instead of ``ParsedPacket``.
- Flags are string-based (``"SYN"``, ``"RST"``) rather than hex.
- Each ``FlowEvent`` may represent >1 packet (``event.packets``).
- Provides ``flush_older_than(seconds)`` for expiry-based eviction
  used by the SlidingWindow micro-batcher.
"""

from __future__ import annotations

import logging
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from time import monotonic

from backend.contracts.features import FlowRecord
from backend.ingestion.event import FlowEvent

logger = logging.getLogger("netmind.ingestion.flow_aggregator")


def _stream_flow_key(event: FlowEvent) -> tuple:
    """Canonical bidirectional 5-tuple key for a FlowEvent.

    Sorts the (ip, port) pairs so src/dst are order-independent.
    ICMP (port = 0) works because both ports are zero.
    """
    a = (event.src_ip, event.src_port)
    b = (event.dst_ip, event.dst_port)
    left, right = sorted([a, b], key=lambda pair: (str(pair[0]), pair[1]))
    return (left[0], left[1], right[0], right[1], event.protocol)


class _StreamingFlowAccumulator:
    """Mutable per-flow state accumulated across FlowEvents."""

    __slots__ = (
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "packets_total",
        "bytes_total",
        "src_bytes",
        "dst_bytes",
        "syn_count",
        "rst_count",
        "ack_count",
        "start_time",
        "end_time",
        "_last_timestamp",
        "_interval_mean",
        "_interval_m2",
        "_interval_count",
        "_created_at_monotonic",
        "_initial_src_ip",
        "_initial_src_port",
    )

    def __init__(self, event: FlowEvent) -> None:
        self.src_ip = event.src_ip
        self.dst_ip = event.dst_ip
        self.src_port = event.src_port
        self.dst_port = event.dst_port or 0
        self.protocol = event.protocol
        self.packets_total = event.packets
        self.bytes_total = event.payload_bytes
        self.src_bytes = event.payload_bytes
        self.dst_bytes = 0
        self.syn_count = 0
        self.rst_count = 0
        self.ack_count = 0
        self._update_flags(event)

        ts = event.ts or datetime.utcnow()
        self.start_time = ts
        self.end_time = ts
        self._last_timestamp = ts
        self._interval_mean = 0.0
        self._interval_m2 = 0.0
        self._interval_count = 0
        self._created_at_monotonic = monotonic()

        # Remember initial direction so we know which bytes are src→dst
        self._initial_src_ip = event.src_ip
        self._initial_src_port = event.src_port

    # ------------------------------------------------------------------
    # Accumulation
    # ------------------------------------------------------------------

    def add_event(self, event: FlowEvent) -> None:
        """Accumulate one more FlowEvent into this flow."""
        self.packets_total += event.packets
        payload = event.payload_bytes
        self.bytes_total += payload

        # Determine direction using original source IP/port
        if event.src_ip == self._initial_src_ip and event.src_port == self._initial_src_port:
            self.src_bytes += payload
        else:
            self.dst_bytes += payload

        ts = event.ts or datetime.utcnow()
        if ts < self.start_time:
            self.start_time = ts
        if ts > self.end_time:
            self.end_time = ts
        if self._last_timestamp:
            interval_ms = (ts - self._last_timestamp).total_seconds() * 1000.0
            self._interval_count += 1
            delta = interval_ms - self._interval_mean
            self._interval_mean += delta / self._interval_count
            delta2 = interval_ms - self._interval_mean
            self._interval_m2 += delta * delta2
        self._last_timestamp = ts

        self._update_flags(event)

    def _update_flags(self, event: FlowEvent) -> None:
        if event.syn_flag():
            self.syn_count += event.packets
        if event.rst_flag():
            self.rst_count += event.packets
        if event.ack_flag():
            self.ack_count += event.packets

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def duration_ms(self) -> float:
        delta = (self.end_time - self.start_time).total_seconds()
        return delta * 1000.0

    @property
    def age_seconds(self) -> float:
        return monotonic() - self._created_at_monotonic

    # ------------------------------------------------------------------
    # Conversion
    # ------------------------------------------------------------------

    def to_flow_record(self) -> FlowRecord:
        if self._interval_count > 0:
            inter_avg = self._interval_mean
            inter_var = (
                self._interval_m2 / (self._interval_count - 1) if self._interval_count > 1 else 0.0
            )
        else:
            inter_avg = (
                self.duration_ms / (self.packets_total - 1) if self.packets_total > 1 else 0.0
            )
            inter_var = 0.0
        return FlowRecord(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
            packets_total=self.packets_total,
            bytes_total=self.bytes_total,
            duration_ms=self.duration_ms,
            start_time=self.start_time,
            end_time=self.end_time,
            src_bytes=self.src_bytes,
            dst_bytes=self.dst_bytes,
            syn_count=self.syn_count,
            rst_count=self.rst_count,
            ack_count=self.ack_count,
            inter_packet_interval_ms=round(inter_avg, 4),
            inter_packet_interval_variance_ms=round(inter_var, 4),
        )


class StreamingFlowAggregator:
    """Accumulates FlowEvents into bidirectional FlowRecords.

    Usage::

        aggregator = StreamingFlowAggregator()
        for event in events:
            aggregator.add_event(event)
        records = aggregator.flush()
    """

    def __init__(self) -> None:
        self._flows: dict[tuple, _StreamingFlowAccumulator] = {}

    def add_event(self, event: FlowEvent) -> None:
        """Accumulate a FlowEvent."""
        key = _stream_flow_key(event)
        acc = self._flows.get(key)
        if acc is None:
            self._flows[key] = _StreamingFlowAccumulator(event)
        else:
            acc.add_event(event)

    def flush(self) -> list[FlowRecord]:
        """Return all accumulated FlowRecords and clear internal state."""
        records = [acc.to_flow_record() for acc in self._flows.values()]
        records.sort(key=lambda r: r.start_time)
        self._flows.clear()
        return records

    def flush_older_than(self, seconds: float) -> list[FlowRecord]:
        """Return FlowRecords for flows that have not received an event
        in the last ``seconds`` seconds, then remove them.

        Used by SlidingWindow to age out stale flows while keeping
        active ones in the current window.
        """
        old_keys = [k for k, acc in self._flows.items() if acc.age_seconds >= seconds]
        records = [self._flows[k].to_flow_record() for k in old_keys]
        records.sort(key=lambda r: r.start_time)
        for k in old_keys:
            del self._flows[k]
        return records

    def active_flow_count(self) -> int:
        return len(self._flows)
