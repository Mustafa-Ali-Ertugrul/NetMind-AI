"""Tests for flow_writer module."""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import IPv4Address
from unittest.mock import MagicMock, call
from uuid import UUID, uuid4

import pytest

from backend.contracts.features import AggregatedFeatures, FlowRecord, TrafficBaseline
from backend.storage.flow_writer import write_flows_from_features
from backend.storage.models import Flow

TEST_PCAP = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")


def _make_flow_record(**kwargs) -> FlowRecord:
    defaults = dict(
        src_ip=IPv4Address("10.0.0.1"),
        dst_ip=IPv4Address("10.0.0.2"),
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        packets_total=10,
        bytes_total=1000,
        duration_ms=500.0,
        start_time=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        src_bytes=600,
        dst_bytes=400,
        syn_count=1,
        rst_count=0,
        ack_count=8,
        inter_packet_interval_ms=55.5,
        inter_packet_interval_variance_ms=12.3,
    )
    defaults.update(kwargs)
    return FlowRecord(**defaults)


class TestFlowWriter:
    """Tests for write_flows_from_features."""

    def test_empty_flows(self):
        """Should return 0 when no flows exist."""
        db = MagicMock()
        baseline = TrafficBaseline(
            expected_bytes_per_second=0.0,
            expected_packets_per_second=0.0,
            total_bytes=0,
            total_packets=0,
            duration_seconds=0.0,
            unique_src_ips=0,
            unique_dst_ips=0,
            protocol_percentages={},
        )
        features = AggregatedFeatures(
            pcap_id=TEST_PCAP,
            capture_duration_seconds=0.0,
            time_window_start=datetime.now(timezone.utc),
            time_window_end=datetime.now(timezone.utc),
            traffic_baseline=baseline,
            flows=[],
            extractor_version="test",
            extraction_duration_ms=0,
        )
        assert write_flows_from_features(db, pcap_id=TEST_PCAP, features=features) == 0
        db.add_all.assert_not_called()

    def test_single_flow(self):
        """Should insert one Flow row per FlowRecord."""
        db = MagicMock()
        record = _make_flow_record()
        baseline = TrafficBaseline(
            expected_bytes_per_second=100.0,
            expected_packets_per_second=10.0,
            total_bytes=1000,
            total_packets=10,
            duration_seconds=1.0,
            unique_src_ips=1,
            unique_dst_ips=1,
            protocol_percentages={"TCP": 100.0},
        )
        features = AggregatedFeatures(
            pcap_id=TEST_PCAP,
            capture_duration_seconds=1.0,
            time_window_start=datetime.now(timezone.utc),
            time_window_end=datetime.now(timezone.utc),
            traffic_baseline=baseline,
            flows=[record],
            extractor_version="test",
            extraction_duration_ms=0,
        )
        assert write_flows_from_features(db, pcap_id=TEST_PCAP, features=features) == 1
        db.add_all.assert_called_once()
        added = db.add_all.call_args[0][0]
        assert len(added) == 1
        assert isinstance(added[0], Flow)
        assert added[0].pcap_id == TEST_PCAP
        assert added[0].src_ip == IPv4Address("10.0.0.1")
        assert added[0].bytes_sent == 600
        assert added[0].packets_count == 10
        assert added[0].inter_packet_interval_ms == 55.5
        assert added[0].inter_packet_interval_variance_ms == 12.3
        assert added[0].ack_count == 8

    def test_batching(self):
        """Should batch inserts when flow count exceeds batch_size."""
        db = MagicMock()
        flows = [_make_flow_record(src_port=i) for i in range(2500)]
        baseline = TrafficBaseline(
            expected_bytes_per_second=100.0,
            expected_packets_per_second=10.0,
            total_bytes=2500000,
            total_packets=25000,
            duration_seconds=1.0,
            unique_src_ips=1,
            unique_dst_ips=1,
            protocol_percentages={"TCP": 100.0},
        )
        features = AggregatedFeatures(
            pcap_id=TEST_PCAP,
            capture_duration_seconds=1.0,
            time_window_start=datetime.now(timezone.utc),
            time_window_end=datetime.now(timezone.utc),
            traffic_baseline=baseline,
            flows=flows,
            extractor_version="test",
            extraction_duration_ms=0,
        )
        assert (
            write_flows_from_features(db, pcap_id=TEST_PCAP, features=features, batch_size=1000)
            == 2500
        )
        assert db.add_all.call_count == 3
        batches = [c[0][0] for c in db.add_all.call_args_list]
        assert len(batches[0]) == 1000
        assert len(batches[1]) == 1000
        assert len(batches[2]) == 500

    def test_port_zero_mapped_to_none(self):
        """FlowRecord with port 0 should map to None in DB."""
        db = MagicMock()
        record = _make_flow_record(src_port=0, dst_port=0)
        baseline = TrafficBaseline(
            expected_bytes_per_second=100.0,
            expected_packets_per_second=10.0,
            total_bytes=1000,
            total_packets=10,
            duration_seconds=1.0,
            unique_src_ips=1,
            unique_dst_ips=1,
            protocol_percentages={"TCP": 100.0},
        )
        features = AggregatedFeatures(
            pcap_id=TEST_PCAP,
            capture_duration_seconds=1.0,
            time_window_start=datetime.now(timezone.utc),
            time_window_end=datetime.now(timezone.utc),
            traffic_baseline=baseline,
            flows=[record],
            extractor_version="test",
            extraction_duration_ms=0,
        )
        write_flows_from_features(db, pcap_id=TEST_PCAP, features=features)
        added = db.add_all.call_args[0][0]
        assert added[0].src_port is None
        assert added[0].dst_port is None
