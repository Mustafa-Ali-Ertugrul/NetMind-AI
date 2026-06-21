"""Tests for ingestion.event and ingestion.stream."""

from __future__ import annotations

import asyncio
from datetime import datetime

import pytest

from backend.ingestion.event import FlowEvent, RawEvent
from backend.ingestion.stream import EventConsumer, EventStream


class TestRawEvent:
    """Tests for RawEvent validation and normalization."""

    def test_valid_raw_event(self) -> None:
        raw = RawEvent(
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=1234,
            dst_port=80,
            protocol="TCP",
        )
        assert raw.src_ip == "192.168.1.1"
        assert raw.dst_ip == "10.0.0.1"
        assert raw.src_port == 1234
        assert raw.dst_port == 80
        assert raw.protocol == "TCP"
        assert raw.payload_bytes == 0
        assert raw.packets == 1

    def test_invalid_ip(self) -> None:
        with pytest.raises(ValueError):
            RawEvent(src_ip="not_an_ip", dst_ip="10.0.0.1", src_port=1, dst_port=1, protocol="TCP")

    def test_empty_ip(self) -> None:
        with pytest.raises(ValueError):
            RawEvent(src_ip="", dst_ip="10.0.0.1", src_port=1, dst_port=1, protocol="TCP")

    def test_protocol_normalised(self) -> None:
        raw = RawEvent(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=1, protocol="udp")
        assert raw.protocol == "UDP"

    def test_raw_event_with_flags(self) -> None:
        raw = RawEvent(
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            src_port=1,
            dst_port=1,
            protocol="TCP",
            flags="SYN+ACK",
        )
        assert raw.flags == "SYN+ACK"

    def test_extra_fields_ignored(self) -> None:
        raw = RawEvent(
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            src_port=1,
            dst_port=1,
            protocol="TCP",
            unknown_collector_field="whatever",
        )
        assert raw.src_ip == "1.1.1.1"


class TestFlowEvent:
    """Tests for FlowEvent (parsed, typed version)."""

    def test_from_raw_event(self) -> None:
        raw = RawEvent(
            src_ip="192.168.1.1",
            dst_ip="2001:db8::1",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            bytes=1500,
            packets=3,
            flags="SYN",
        )
        flow = raw.to_flow_event()
        assert flow.src_ip == __import__("ipaddress").IPv4Address("192.168.1.1")
        assert flow.dst_ip == __import__("ipaddress").IPv6Address("2001:db8::1")
        assert flow.src_port == 54321
        assert flow.dst_port == 443
        assert flow.protocol == "TCP"
        assert flow.payload_bytes == 1500
        assert flow.packets == 3
        assert flow.syn_flag() is True
        assert flow.ack_flag() is False


class TestEventStream:
    """Tests for bounded async event queue."""

    @pytest.mark.asyncio
    async def test_put_and_get(self) -> None:
        stream = EventStream(max_size=10)
        event = FlowEvent(
            ts=datetime.utcnow(),
            src_ip=__import__("ipaddress").IPv4Address("1.1.1.1"),
            dst_ip=__import__("ipaddress").IPv4Address("2.2.2.2"),
            src_port=1,
            dst_port=2,
            protocol="TCP",
        )
        await stream.put(event)
        out = await stream.get()
        assert out.src_ip == event.src_ip
        metrics = stream.metrics()
        assert metrics.events_enqueued == 1
        assert metrics.events_consumed == 1
        assert metrics.events_dropped == 0

    @pytest.mark.asyncio
    async def test_drop_on_overflow(self) -> None:
        stream = EventStream(max_size=2)
        for i in range(5):
            event = FlowEvent(
                ts=datetime.utcnow(),
                src_ip=__import__("ipaddress").IPv4Address("1.1.1.1"),
                dst_ip=__import__("ipaddress").IPv4Address("2.2.2.2"),
                src_port=i,
                dst_port=80,
                protocol="TCP",
            )
            await stream.put(event)
        metrics = stream.metrics()
        assert metrics.events_enqueued == 2
        assert metrics.events_dropped == 3

    @pytest.mark.asyncio
    async def test_put_nowait(self) -> None:
        stream = EventStream(max_size=3)
        event = FlowEvent(
            ts=datetime.utcnow(),
            src_ip=__import__("ipaddress").IPv4Address("1.1.1.1"),
            dst_ip=__import__("ipaddress").IPv4Address("2.2.2.2"),
            src_port=1,
            dst_port=2,
            protocol="UDP",
        )
        stream.put_nowait(event)
        assert stream.qsize() == 1
        out = await stream.get()
        assert out.protocol == "UDP"

    @pytest.mark.asyncio
    async def test_drain(self) -> None:
        stream = EventStream(max_size=10)
        for i in range(3):
            event = FlowEvent(
                ts=datetime.utcnow(),
                src_ip=__import__("ipaddress").IPv4Address("1.1.1.1"),
                dst_ip=__import__("ipaddress").IPv4Address("2.2.2.2"),
                src_port=i,
                dst_port=80,
                protocol="TCP",
            )
            await stream.put(event)
        remaining = await stream.drain()
        assert len(remaining) == 3
        assert stream.empty()


class TestEventConsumer:
    """Tests for background batch consumer."""

    @pytest.mark.asyncio
    async def test_single_batch(self) -> None:
        received: list[list[FlowEvent]] = []

        async def capture(batch: list[FlowEvent]) -> None:
            received.append(batch)

        stream = EventStream(max_size=100)
        consumer = EventConsumer(stream, capture, batch_size=5, flush_interval=10.0)
        await consumer.start()

        for i in range(5):
            event = FlowEvent(
                ts=datetime.utcnow(),
                src_ip=__import__("ipaddress").IPv4Address("1.1.1.1"),
                dst_ip=__import__("ipaddress").IPv4Address("2.2.2.2"),
                src_port=i,
                dst_port=80,
                protocol="TCP",
            )
            await stream.put(event)

        await asyncio.sleep(0.1)  # let consumer flush
        await consumer.stop()

        assert len(received) == 1
        assert len(received[0]) == 5
        assert stream.metrics().batches_processed == 1

    @pytest.mark.asyncio
    async def test_interval_flush(self) -> None:
        received: list[list[FlowEvent]] = []

        async def capture(batch: list[FlowEvent]) -> None:
            received.append(batch)

        stream = EventStream(max_size=100)
        consumer = EventConsumer(stream, capture, batch_size=100, flush_interval=0.2)
        await consumer.start()

        event = FlowEvent(
            ts=datetime.utcnow(),
            src_ip=__import__("ipaddress").IPv4Address("1.1.1.1"),
            dst_ip=__import__("ipaddress").IPv4Address("2.2.2.2"),
            src_port=1,
            dst_port=80,
            protocol="TCP",
        )
        await stream.put(event)

        await asyncio.sleep(0.5)  # wait for interval flush
        await consumer.stop()

        assert len(received) == 1
        assert len(received[0]) == 1

    @pytest.mark.asyncio
    async def test_process_fn_exception_survives(self) -> None:
        async def boom(batch: list[FlowEvent]) -> None:
            raise RuntimeError("boom")

        stream = EventStream(max_size=100)
        consumer = EventConsumer(stream, boom, batch_size=2, flush_interval=10.0)
        await consumer.start()

        for i in range(4):
            event = FlowEvent(
                ts=datetime.utcnow(),
                src_ip=__import__("ipaddress").IPv4Address("1.1.1.1"),
                dst_ip=__import__("ipaddress").IPv4Address("2.2.2.2"),
                src_port=i,
                dst_port=80,
                protocol="TCP",
            )
            await stream.put(event)

        await asyncio.sleep(0.1)
        await consumer.stop()

        # Consumer should not crash — both batches processed despite exceptions
        assert stream.metrics().batches_processed == 2

    @pytest.mark.asyncio
    async def test_double_start_raises(self) -> None:
        async def dummy(batch: list[FlowEvent]) -> None:
            pass

        stream = EventStream(max_size=10)
        consumer = EventConsumer(stream, dummy, batch_size=5, flush_interval=10.0)
        await consumer.start()
        with pytest.raises(RuntimeError):
            await consumer.start()
        await consumer.stop()

    @pytest.mark.asyncio
    async def test_stop_without_start(self) -> None:
        async def dummy(batch: list[FlowEvent]) -> None:
            pass

        stream = EventStream(max_size=10)
        consumer = EventConsumer(stream, dummy, batch_size=5, flush_interval=10.0)
        # should not raise
        await consumer.stop()
