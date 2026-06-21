"""Tests for TrafficBaselineComputer."""

from datetime import UTC, datetime

import pytest

from backend.contracts.enums import Protocol
from backend.feature_extractor.traffic_baseline import TrafficBaselineComputer

from .fixtures import make_parsed_packet


class TestTrafficBaselineComputer:
    """Tests for baseline and deviation computation."""

    def test_empty_packets(self):
        """Should handle empty packet list gracefully."""
        tbc = TrafficBaselineComputer()
        baseline = tbc.compute_baseline([], [])
        assert baseline.total_packets == 0
        assert baseline.total_bytes == 0
        assert baseline.duration_seconds > 0  # defaulted to 1.0
        assert baseline.expected_bytes_per_second == 0.0

    def test_single_packet_baseline(self):
        """A single packet produces a baseline with one packet."""
        pkt = make_parsed_packet(length=100)
        tbc = TrafficBaselineComputer()
        baseline = tbc.compute_baseline([pkt], [])
        assert baseline.total_packets == 1
        assert baseline.total_bytes == 100
        # duration will be 1.0 (default)
        assert baseline.duration_seconds >= 1.0

    def test_multi_packet_baseline(self):
        """Multiple packets with timestamps produce correct baseline."""
        pkts = [
            make_parsed_packet(
                packet_number=1,
                length=100,
                timestamp="2024-01-01T00:00:00+00:00",
            ),
            make_parsed_packet(
                packet_number=2,
                length=200,
                timestamp="2024-01-01T00:00:02+00:00",
            ),
        ]
        tbc = TrafficBaselineComputer()
        baseline = tbc.compute_baseline(pkts, [])
        assert baseline.total_packets == 2
        assert baseline.total_bytes == 300
        assert baseline.duration_seconds == 2.0
        assert baseline.expected_bytes_per_second == 150.0
        assert baseline.expected_packets_per_second == 1.0

    def test_unique_ip_counts(self):
        """Should correctly count unique source/destination IPs."""
        pkts = [
            make_parsed_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2"),
            make_parsed_packet(src_ip="10.0.0.1", dst_ip="10.0.0.3"),
            make_parsed_packet(src_ip="10.0.0.4", dst_ip="10.0.0.2"),
        ]
        tbc = TrafficBaselineComputer()
        baseline = tbc.compute_baseline(pkts, [])
        assert baseline.unique_src_ips == 2
        assert baseline.unique_dst_ips == 2

    def test_protocol_percentages(self):
        """Protocol percentages should sum to 100%."""
        pkts = [
            make_parsed_packet(protocol=Protocol.TCP),
            make_parsed_packet(protocol=Protocol.TCP),
            make_parsed_packet(protocol=Protocol.UDP, src_port=1000, dst_port=53),
        ]
        tbc = TrafficBaselineComputer()
        baseline = tbc.compute_baseline(pkts, [])
        pcts = baseline.protocol_percentages
        assert "TCP" in pcts
        assert "UDP" in pcts
        total = sum(pcts.values())
        assert total == pytest.approx(100.0, rel=0.1)

    def test_empty_deviations(self):
        """Empty flow list should produce empty deviation list."""
        tbc = TrafficBaselineComputer()
        base = tbc.compute_baseline([make_parsed_packet()], [])
        devs = tbc.compute_deviations([], base)
        assert devs == []

    def test_single_flow_deviation(self):
        """Single flow should produce a deviation record."""
        pkt = make_parsed_packet(length=500, timestamp="2024-01-01T00:00:00+00:00")
        tbc = TrafficBaselineComputer()

        # Build a fake flow with src_bytes > dst_bytes (upload dominated)
        from backend.contracts.features import FlowRecord

        flow = FlowRecord(
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            src_port=pkt.src_port or 0,
            dst_port=pkt.dst_port or 0,
            protocol="TCP",
            packets_total=1,
            bytes_total=500,
            duration_ms=1000.0,
            start_time=datetime(2024, 1, 1, tzinfo=UTC),
            end_time=datetime(2024, 1, 1, 0, 0, 1, tzinfo=UTC),
            src_bytes=500,
            dst_bytes=0,
        )

        base = tbc.compute_baseline([pkt], [flow])
        devs = tbc.compute_deviations([flow], base)
        assert len(devs) == 1
        assert devs[0].is_upload_dominated is True
        assert devs[0].bytes_per_second > 0
