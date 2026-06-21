"""Tests for ingestion.flow_aggregator."""

from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from backend.ingestion.event import FlowEvent
from backend.ingestion.flow_aggregator import StreamingFlowAggregator, _stream_flow_key


def _make_event(
    *,
    src_ip: str = "192.168.1.1",
    dst_ip: str = "10.0.0.1",
    src_port: int = 12345,
    dst_port: int = 80,
    protocol: str = "TCP",
    payload_bytes: int = 100,
    packets: int = 1,
    flags: str | None = None,
    ts: datetime | None = None,
) -> FlowEvent:
    return FlowEvent(
        ts=ts or datetime.utcnow(),
        src_ip=IPv4Address(src_ip),
        dst_ip=IPv4Address(dst_ip),
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        payload_bytes=payload_bytes,
        packets=packets,
        flags=flags,
    )


class TestStreamFlowKey:
    """Tests for bidirectional flow key generation."""

    def test_bidirectional_sorting(self) -> None:
        a = _make_event(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80)
        b = _make_event(src_ip="2.2.2.2", dst_ip="1.1.1.1", src_port=80, dst_port=1000)
        assert _stream_flow_key(a) == _stream_flow_key(b)

    def test_same_direction_same_key(self) -> None:
        a = _make_event(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80)
        b = _make_event(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80)
        assert _stream_flow_key(a) == _stream_flow_key(b)

    def test_different_flow_different_key(self) -> None:
        a = _make_event(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80)
        b = _make_event(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=443)
        assert _stream_flow_key(a) != _stream_flow_key(b)

    def test_icmp_no_ports(self) -> None:
        a = _make_event(protocol="ICMP", src_port=0, dst_port=0)
        b = _make_event(protocol="ICMP", src_port=0, dst_port=0)
        assert _stream_flow_key(a) == _stream_flow_key(b)


class TestStreamingFlowAggregator:
    """Tests for StreamingFlowAggregator."""

    def test_single_event(self) -> None:
        agg = StreamingFlowAggregator()
        event = _make_event()
        agg.add_event(event)
        records = agg.flush()
        assert len(records) == 1
        r = records[0]
        assert r.packets_total == 1
        assert r.bytes_total == 100
        assert r.syn_count == 0

    def test_multiple_events_same_flow(self) -> None:
        agg = StreamingFlowAggregator()
        for i in range(5):
            event = _make_event(payload_bytes=100 + i, packets=1)
            agg.add_event(event)
        records = agg.flush()
        assert len(records) == 1
        r = records[0]
        assert r.packets_total == 5
        assert r.bytes_total == 100 + 101 + 102 + 103 + 104

    def test_bidirectional_bytes(self) -> None:
        agg = StreamingFlowAggregator()
        # src→dst
        agg.add_event(
            _make_event(
                src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, payload_bytes=100
            )
        )
        # dst→src (reverse)
        agg.add_event(
            _make_event(
                src_ip="2.2.2.2", dst_ip="1.1.1.1", src_port=80, dst_port=1000, payload_bytes=50
            )
        )
        records = agg.flush()
        assert len(records) == 1
        r = records[0]
        assert r.bytes_total == 150
        assert r.src_bytes == 100
        assert r.dst_bytes == 50

    def test_syn_count(self) -> None:
        agg = StreamingFlowAggregator()
        agg.add_event(_make_event(flags="SYN", packets=3))
        agg.add_event(_make_event(flags="SYN+ACK", packets=1))
        agg.add_event(_make_event(flags="ACK", packets=1))
        records = agg.flush()
        assert len(records) == 1
        r = records[0]
        assert r.syn_count == 4  # SYN(3) + SYN+ACK(1)  (both have SYN flag)
        assert r.ack_count == 2  # SYN+ACK(1) + ACK(1)

    def test_rst_count(self) -> None:
        agg = StreamingFlowAggregator()
        agg.add_event(_make_event(flags="RST", packets=1))
        records = agg.flush()
        assert records[0].rst_count == 1

    def test_flush_then_empty(self) -> None:
        agg = StreamingFlowAggregator()
        agg.add_event(_make_event())
        agg.flush()
        assert agg.active_flow_count() == 0

    def test_flush_older_than(self) -> None:
        agg = StreamingFlowAggregator()
        # Add event, then immediately try to flush older than 0.01s
        # Should NOT be flushed because it was just added
        agg.add_event(_make_event())
        old = agg.flush_older_than(0.01)
        assert len(old) == 0  # too recent

        # Now add another event and wait a tiny bit
        import time

        time.sleep(0.05)
        old = agg.flush_older_than(0.01)
        assert len(old) == 1

    def test_multiple_flows(self) -> None:
        agg = StreamingFlowAggregator()
        agg.add_event(_make_event(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1111, dst_port=80))
        agg.add_event(_make_event(src_ip="3.3.3.3", dst_ip="4.4.4.4", src_port=2222, dst_port=443))
        records = agg.flush()
        assert len(records) == 2
        assert {r.src_ip for r in records} == {IPv4Address("1.1.1.1"), IPv4Address("3.3.3.3")}

    def test_ipv6_addresses(self) -> None:
        agg = StreamingFlowAggregator()
        event = FlowEvent(
            ts=datetime.utcnow(),
            src_ip=IPv6Address("::1"),
            dst_ip=IPv6Address("::2"),
            src_port=1234,
            dst_port=80,
            protocol="TCP",
            payload_bytes=200,
            packets=1,
        )
        agg.add_event(event)
        records = agg.flush()
        assert len(records) == 1
        assert isinstance(records[0].src_ip, IPv6Address)

    def test_multi_packet_event(self) -> None:
        agg = StreamingFlowAggregator()
        event = _make_event(packets=10, payload_bytes=1000)
        agg.add_event(event)
        records = agg.flush()
        assert records[0].packets_total == 10
        assert records[0].bytes_total == 1000
