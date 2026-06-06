"""Tests for NET-009 Beaconing Detection Rule."""

from datetime import datetime, timezone
from ipaddress import IPv4Address

from backend.contracts.features import AggregatedFeatures, FlowRecord
from backend.rule_engine.rules.beaconing_rule import BeaconingRule

RULE = BeaconingRule()


def _make_beacon_flow(
    pkt_count: int = 30,
    interval_ms: float = 1000.0,
    variance_ms: float = 100.0,
    bytes_total: int = 3000,
    duration_ms: float = 30000.0,
) -> FlowRecord:
    return FlowRecord(
        src_ip=IPv4Address("10.0.0.1"),
        dst_ip=IPv4Address("10.0.0.2"),
        src_port=54321,
        dst_port=443,
        protocol="tcp",
        packets_total=pkt_count,
        bytes_total=bytes_total,
        duration_ms=duration_ms,
        start_time=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2025, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
        src_bytes=bytes_total // 2,
        dst_bytes=bytes_total // 2,
        syn_count=0,
        rst_count=0,
        inter_packet_interval_ms=interval_ms,
        inter_packet_interval_variance_ms=variance_ms,
        ack_count=0,
    )


def _make_features(flows: list[FlowRecord]) -> AggregatedFeatures:
    return AggregatedFeatures(
        pcap_id="00000000-0000-0000-0000-000000000000",
        capture_duration_seconds=1.0,
        time_window_start=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        time_window_end=datetime(2025, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
        traffic_baseline={
            "expected_bytes_per_second": 1000.0,
            "expected_packets_per_second": 10.0,
            "total_bytes": 3000,
            "total_packets": 30,
            "duration_seconds": 30.0,
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


def test_no_trigger_high_variance():
    # cv = sqrt(90000)/1000 = 300/1000 = 0.3 --> blocked (>= SUSPECT threshold)
    result = RULE._evaluate(_make_features([_make_beacon_flow(variance_ms=90000.0)]))
    assert result == []


def test_no_trigger_low_pkt_count():
    result = RULE._evaluate(_make_features([_make_beacon_flow(pkt_count=5)]))
    assert result == []


def test_no_trigger_large_size():
    result = RULE._evaluate(_make_features([_make_beacon_flow(bytes_total=10000)]))
    assert result == []


def test_trigger_all_indicators():
    result = RULE._evaluate(_make_features([_make_beacon_flow()]))
    assert len(result) == 1
    f = result[0]
    assert f.rule_id == "NET-009"
    assert len(f.evidences) == 3
    assert f.risk_score >= 60


def test_trigger_cv_only():
    # Low CV, large size (but all other checks are AND)
    # Large size should block
    result = RULE._evaluate(_make_features([_make_beacon_flow(bytes_total=10000)]))
    assert result == []


def test_feature_snapshot():
    result = RULE._evaluate(_make_features([_make_beacon_flow()]))
    assert len(result) == 1
    snap = result[0].feature_snapshot
    assert "cv" in snap
    assert "avg_size" in snap
    assert "pkt_count" in snap


def test_affected_entities():
    result = RULE._evaluate(_make_features([_make_beacon_flow()]))
    assert len(result) == 1
    assert "10.0.0.1" in result[0].affected_entities
    assert "10.0.0.2" in result[0].affected_entities
