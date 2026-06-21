"""Tests for NET-006 HTTP Anomaly Detection Rule."""

from datetime import UTC, datetime

from backend.contracts.features import AggregatedFeatures, FlowRecord
from backend.rule_engine.rules.http_anomaly_rule import HTTPAnomalyRule

RULE = HTTPAnomalyRule()


def _make_features(
    http_status_counts: dict,
    http_user_agents: list[str],
    http_top_uris: list,
    flows: list[FlowRecord] | None = None,
) -> AggregatedFeatures:
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
            "protocol_percentages": {"tcp": 100.0},
        },
        flows=flows or [],
        connection_profiles=[],
        traffic_deviations=[],
        dns_profiles=[],
        ftp_flows=[],
        smtp_flows=[],
        http_method_counts={},
        http_status_counts=http_status_counts,
        http_top_uris=http_top_uris,
        http_user_agents=http_user_agents,
        extractor_version="1.0.0",
        extraction_duration_ms=0,
    )


def test_no_trigger_empty_uris():
    result = RULE._evaluate(_make_features({}, [], []))
    assert result == []


def test_trigger_error_ratio():
    result = RULE._evaluate(_make_features({200: 10, 404: 5, 500: 5}, ["Mozilla/5.0"], [("/", 20)]))
    assert len(result) == 1
    f = result[0]
    assert f.rule_id == "NET-006"
    assert any(e.key == "http_error_ratio" for e in f.evidences)


def test_trigger_suspicious_ua():
    result = RULE._evaluate(_make_features({200: 20}, ["nmap/7.92"], [("/", 20)]))
    assert len(result) == 1
    f = result[0]
    assert any(e.key == "suspicious_ua_count" for e in f.evidences)


def test_trigger_single_uri_share():
    result = RULE._evaluate(
        _make_features({200: 20}, ["Mozilla/5.0"], [("/api/login", 14), ("/", 6)])
    )
    assert len(result) == 1
    f = result[0]
    assert any(e.key == "single_uri_share" for e in f.evidences)


def test_trigger_all_indicators():
    result = RULE._evaluate(
        _make_features(
            {200: 10, 404: 5, 500: 5},
            ["nmap/7.92", "Mozilla/5.0"],
            [("/api/login", 14), ("/", 6)],
        )
    )
    assert len(result) == 1
    f = result[0]
    assert len(f.evidences) == 3
    assert f.risk_score >= 60


def test_no_trigger_below_thresholds():
    result = RULE._evaluate(
        _make_features(
            {200: 18, 404: 1, 500: 1},  # error_ratio = 2/20 = 0.1 < 0.5
            ["Mozilla/5.0"],
            [("/", 10), ("/api", 10)],  # share = 0.5 < 0.7
        )
    )
    assert result == []


def test_feature_snapshot():
    result = RULE._evaluate(_make_features({200: 10, 404: 5, 500: 5}, ["Mozilla/5.0"], [("/", 20)]))
    assert len(result) == 1
    assert "error_ratio" in result[0].feature_snapshot
