"""Tests for NET-011 Large Outbound Transfer Detection Rule."""

from datetime import datetime, timezone
from ipaddress import IPv4Address

from backend.contracts.features import AggregatedFeatures, FlowRecord
from backend.rule_engine.rules.large_outbound_rule import LargeOutboundRule

RULE = LargeOutboundRule()

# RFC1918 internal IP
_INTERNAL_IP = IPv4Address("10.0.0.1")
# Public external IP
_EXTERNAL_IP = IPv4Address("8.8.8.8")


def _make_outbound_flow(
    bytes_total: int = 100_000_000,
    src_bytes: int | None = None,
    duration_ms: float = 60_000.0,
    dst_port: int = 443,
    protocol: str = "tcp",
    dst_ip=_EXTERNAL_IP,
) -> FlowRecord:
    if src_bytes is None:
        src_bytes = bytes_total - 10_000_000  # mostly upload by default
    return FlowRecord(
        src_ip=_INTERNAL_IP,
        dst_ip=dst_ip,
        src_port=54321,
        dst_port=dst_port,
        protocol=protocol,
        packets_total=bytes_total // 1460,
        bytes_total=bytes_total,
        duration_ms=duration_ms,
        start_time=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2025, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
        src_bytes=src_bytes,
        dst_bytes=bytes_total - src_bytes,
        syn_count=0,
        rst_count=0,
        inter_packet_interval_ms=500.0,
        inter_packet_interval_variance_ms=0.0,
        ack_count=0,
    )


def _make_features(flows: list[FlowRecord]) -> AggregatedFeatures:
    return AggregatedFeatures(
        pcap_id="00000000-0000-0000-0000-000000000000",
        capture_duration_seconds=1.0,
        time_window_start=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        time_window_end=datetime(2025, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
        traffic_baseline={
            "expected_bytes_per_second": 1000.0,
            "expected_packets_per_second": 10.0,
            "total_bytes": 3000,
            "total_packets": 30,
            "duration_seconds": 60.0,
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


def test_no_trigger_small_transfer():
    flow = _make_outbound_flow(bytes_total=1_000_000)
    result = RULE._evaluate(_make_features([flow]))
    assert result == []


def test_no_trigger_short_duration():
    flow = _make_outbound_flow(duration_ms=100.0)
    result = RULE._evaluate(_make_features([flow]))
    assert result == []


def test_no_trigger_rfc1918_destination():
    flow = _make_outbound_flow(dst_ip=IPv4Address("192.168.1.1"))
    result = RULE._evaluate(_make_features([flow]))
    assert result == []


def test_trigger_large_outbound_upload():
    flow = _make_outbound_flow()
    result = RULE._evaluate(_make_features([flow]))
    assert len(result) == 1
    f = result[0]
    assert f.rule_id == "NET-011"
    assert "outbound" in f.title.lower()
    assert len(f.evidences) >= 2


def test_trigger_large_outbound_download():
    # Download-dominated (low src_bytes ratio)
    flow = _make_outbound_flow(src_bytes=1_000_000)
    result = RULE._evaluate(_make_features([flow]))
    assert len(result) == 1
    f = result[0]
    assert f.rule_id == "NET-011"


def test_trigger_non_web_port():
    flow = _make_outbound_flow(dst_port=22)
    result = RULE._evaluate(_make_features([flow]))
    assert len(result) == 1
