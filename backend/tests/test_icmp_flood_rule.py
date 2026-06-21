"""Tests for NET-007 ICMP Flood Detection Rule."""

from datetime import UTC, datetime
from ipaddress import IPv4Address

from backend.contracts.features import AggregatedFeatures, FlowRecord
from backend.rule_engine.rules.icmp_flood_rule import ICMPFloodRule

RULE = ICMPFloodRule()


def _make_icmp_flow(pkt_count: int, duration_ms: float = 1000) -> FlowRecord:
    return FlowRecord(
        src_ip=IPv4Address("10.0.0.1"),
        dst_ip=IPv4Address("10.0.0.2"),
        src_port=0,
        dst_port=0,
        protocol="icmp",
        packets_total=pkt_count,
        bytes_total=pkt_count * 80,
        duration_ms=duration_ms,
        start_time=datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC),
        end_time=datetime(2025, 1, 1, 0, 0, 1, tzinfo=UTC),
        src_bytes=pkt_count * 40,
        dst_bytes=pkt_count * 40,
        syn_count=0,
        rst_count=0,
        inter_packet_interval_ms=0.0,
        inter_packet_interval_variance_ms=0.0,
        ack_count=0,
    )


def _make_features(flows: list[FlowRecord]) -> AggregatedFeatures:
    return AggregatedFeatures(
        pcap_id="00000000-0000-0000-0000-000000000000",
        capture_duration_seconds=1.0,
        time_window_start=datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC),
        time_window_end=datetime(2025, 1, 1, 0, 0, 1, tzinfo=UTC),
        traffic_baseline={
            "expected_bytes_per_second": 1000.0,
            "expected_packets_per_second": 10.0,
            "total_bytes": 1000,
            "total_packets": 10,
            "duration_seconds": 1.0,
            "unique_src_ips": 1,
            "unique_dst_ips": 1,
            "protocol_percentages": {"icmp": 100.0},
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


def test_no_trigger_below_threshold():
    result = RULE._evaluate(_make_features([_make_icmp_flow(pkt_count=3)]))
    assert result == []


def test_trigger_high_pps():
    result = RULE._evaluate(_make_features([_make_icmp_flow(pkt_count=200, duration_ms=1000)]))
    assert len(result) == 1
    f = result[0]
    assert f.rule_id == "NET-007"
    assert any(e.key == "icmp_pps" for e in f.evidences)
    assert f.risk_score > 0


def test_trigger_high_total_pkts():
    result = RULE._evaluate(_make_features([_make_icmp_flow(pkt_count=150)]))
    assert len(result) == 1
    f = result[0]
    assert any(e.key == "icmp_total_pkts" for e in f.evidences)


def test_trigger_both_indicators():
    result = RULE._evaluate(_make_features([_make_icmp_flow(pkt_count=250, duration_ms=500)]))
    assert len(result) == 1
    f = result[0]
    assert len(f.evidences) == 2
    assert f.risk_score >= 60


def test_no_trigger_for_tcp():
    tcp_flow = FlowRecord(
        src_ip=IPv4Address("10.0.0.1"),
        dst_ip=IPv4Address("10.0.0.2"),
        src_port=12345,
        dst_port=80,
        protocol="tcp",
        packets_total=250,
        bytes_total=20000,
        duration_ms=500,
        start_time=datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC),
        end_time=datetime(2025, 1, 1, 0, 0, 1, tzinfo=UTC),
        src_bytes=10000,
        dst_bytes=10000,
        syn_count=0,
        rst_count=0,
        inter_packet_interval_ms=0.0,
        inter_packet_interval_variance_ms=0.0,
        ack_count=0,
    )
    result = RULE._evaluate(_make_features([tcp_flow]))
    assert result == []


def test_feature_snapshot():
    result = RULE._evaluate(_make_features([_make_icmp_flow(pkt_count=200)]))
    assert len(result) == 1
    assert "total_pkts" in result[0].feature_snapshot
    assert "pps" in result[0].feature_snapshot


def test_affected_entities():
    result = RULE._evaluate(_make_features([_make_icmp_flow(pkt_count=200)]))
    assert len(result) == 1
    assert "10.0.0.1" in result[0].affected_entities
    assert "10.0.0.2" in result[0].affected_entities
