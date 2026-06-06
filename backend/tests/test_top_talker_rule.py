"""Tests for NET-008 Top Talker Detection Rule."""

from datetime import datetime, timezone
from ipaddress import IPv4Address

from backend.contracts.features import AggregatedFeatures, FlowRecord
from backend.rule_engine.rules.top_talker_rule import TopTalkerRule

RULE = TopTalkerRule()


def _make_flow(bytes_total: int, packets: int = 10) -> FlowRecord:
    return FlowRecord(
        src_ip=IPv4Address("10.0.0.1"),
        dst_ip=IPv4Address("10.0.0.2"),
        src_port=12345,
        dst_port=80,
        protocol="tcp",
        packets_total=packets,
        bytes_total=bytes_total,
        duration_ms=1000,
        start_time=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2025, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        src_bytes=bytes_total // 2,
        dst_bytes=bytes_total // 2,
        syn_count=0,
        rst_count=0,
        inter_packet_interval_ms=0.0,
        inter_packet_interval_variance_ms=0.0,
        ack_count=0,
    )


def _make_features(flows: list[FlowRecord], total_bytes: int) -> AggregatedFeatures:
    return AggregatedFeatures(
        pcap_id="00000000-0000-0000-0000-000000000000",
        capture_duration_seconds=1.0,
        time_window_start=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        time_window_end=datetime(2025, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        traffic_baseline={
            "expected_bytes_per_second": 1000.0,
            "expected_packets_per_second": 10.0,
            "total_bytes": total_bytes,
            "total_packets": 10,
            "duration_seconds": 1.0,
            "unique_src_ips": 1,
            "unique_dst_ips": 1,
            "protocol_percentages": {"tcp": 100.0},
        },
        flows=flows,
        connection_profiles=[],
        traffic_deviations=[],
        dns_profiles=[],
        ftp_flows=[],
        smtp_flows=[],
        http_method_counts={},
        http_status_counts={},
        http_top_uris=[],
        http_user_agents=[],
        extractor_version="1.0.0",
        extraction_duration_ms=0,
    )


def test_no_trigger_small_share():
    result = RULE._evaluate(_make_features([_make_flow(100)], total_bytes=1000))
    assert result == []


def test_trigger_high_share():
    result = RULE._evaluate(
        _make_features([_make_flow(6_000_000, packets=1000)], total_bytes=10_000_000)
    )
    assert len(result) == 1
    f = result[0]
    assert f.rule_id == "NET-008"
    assert any(e.key == "traffic_share" for e in f.evidences)
    assert f.risk_score > 0


def test_trigger_large_bytes():
    result = RULE._evaluate(_make_features([_make_flow(2_000_000)], total_bytes=3_000_000))
    assert len(result) == 1
    f = result[0]
    assert any(e.key == "total_bytes" for e in f.evidences)


def test_trigger_both_indicators():
    result = RULE._evaluate(
        _make_features([_make_flow(5_000_000, packets=5000)], total_bytes=8_000_000)
    )
    assert len(result) == 1
    f = result[0]
    assert len(f.evidences) >= 2
    assert f.risk_score >= 60


def test_multiple_flows():
    flows = [
        _make_flow(100),
        _make_flow(6_000_000, packets=1000),
    ]
    result = RULE._evaluate(_make_features(flows, total_bytes=10_000_000))
    assert len(result) == 1


def test_feature_snapshot():
    result = RULE._evaluate(_make_features([_make_flow(6_000_000)], total_bytes=10_000_000))
    assert len(result) == 1
    assert "traffic_share" in result[0].feature_snapshot
