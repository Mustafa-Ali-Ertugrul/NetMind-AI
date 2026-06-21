"""Tests for NET-010 Cleartext Credentials Detection Rule."""

from datetime import UTC, datetime

from backend.contracts.features import AggregatedFeatures, FTPFlow, SMTPFlow
from backend.rule_engine.rules.cleartext_credentials_rule import CleartextCredentialsRule

RULE = CleartextCredentialsRule()


def _make_features(
    ftp_flows: list[FTPFlow] | None = None,
    smtp_flows: list[SMTPFlow] | None = None,
    http_top_uris: list[tuple[str, int]] | None = None,
) -> AggregatedFeatures:
    return AggregatedFeatures(
        pcap_id="00000000-0000-0000-0000-000000000000",
        capture_duration_seconds=1.0,
        time_window_start=datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC),
        time_window_end=datetime(2025, 1, 1, 0, 0, 30, tzinfo=UTC),
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
        flows=[],
        connection_profiles=[],
        traffic_deviations=[],
        dns_profiles=[],
        ftp_flows=ftp_flows or [],
        smtp_flows=smtp_flows or [],
        http_method_counts={},
        http_status_counts={},
        http_top_uris=http_top_uris or [],
        http_user_agents=[],
        extractor_version="1.0.0",
        extraction_duration_ms=0,
    )


def test_no_trigger_clean():
    result = RULE._evaluate(_make_features())
    assert result == []


def test_trigger_ftp_cleartext():
    ftp = FTPFlow(
        src_ip="10.0.0.1",
        failed_auth_count=0,
        success_auth_count=1,
        total_commands=5,
        failed_auth_ratio=0.0,
    )
    result = RULE._evaluate(_make_features(ftp_flows=[ftp]))
    assert len(result) == 1
    f = result[0]
    assert f.rule_id == "NET-010"
    assert "cleartext" in f.title.lower()
    assert len(f.evidences) >= 1


def test_trigger_smtp_cleartext():
    smtp = SMTPFlow(
        src_ip="10.0.0.1",
        message_count=0,
        unique_recipients=0,
        failed_auth_count=2,
        total_connections=3,
    )
    result = RULE._evaluate(_make_features(smtp_flows=[smtp]))
    assert len(result) == 1
    f = result[0]
    assert f.rule_id == "NET-010"


def test_trigger_http_login_uri():
    uris = [("/login.php", 3), ("/signin", 1)]
    result = RULE._evaluate(_make_features(http_top_uris=uris))
    assert len(result) == 1
    f = result[0]
    assert f.rule_id == "NET-010"


def test_no_trigger_http_safe_uri():
    uris = [("/index.html", 10), ("/images/logo.png", 5)]
    result = RULE._evaluate(_make_features(http_top_uris=uris))
    assert result == []


def test_trigger_multiple_sources():
    ftp = FTPFlow(
        src_ip="10.0.0.1",
        failed_auth_count=0,
        success_auth_count=1,
        total_commands=5,
        failed_auth_ratio=0.0,
    )
    smtp = SMTPFlow(
        src_ip="10.0.0.2",
        message_count=0,
        unique_recipients=0,
        failed_auth_count=2,
        total_connections=3,
    )
    uris = [("/auth/token", 1)]
    result = RULE._evaluate(_make_features(ftp_flows=[ftp], smtp_flows=[smtp], http_top_uris=uris))
    assert len(result) == 1
    f = result[0]
    assert len(f.evidences) >= 3
