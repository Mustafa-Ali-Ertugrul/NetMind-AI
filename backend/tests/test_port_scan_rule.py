"""Tests for PortScanRule."""

from datetime import UTC, datetime
from ipaddress import IPv4Address
from uuid import uuid4

from backend.contracts.enums import Severity
from backend.contracts.features import AggregatedFeatures, ConnectionProfile, TrafficBaseline
from backend.rule_engine.rules import PortScanRule


def _make_baseline() -> TrafficBaseline:
    return TrafficBaseline(
        expected_bytes_per_second=1_000,
        expected_packets_per_second=100,
        total_bytes=10_000,
        total_packets=1_000,
        duration_seconds=10.0,
        unique_src_ips=1,
        unique_dst_ips=5,
        protocol_percentages={"TCP": 100.0},
    )


def _make_features(
    profiles: list[ConnectionProfile] | None = None,
) -> AggregatedFeatures:
    now = datetime.now(UTC)
    return AggregatedFeatures(
        pcap_id=uuid4(),
        capture_duration_seconds=10.0,
        time_window_start=now,
        time_window_end=now,
        traffic_baseline=_make_baseline(),
        connection_profiles=profiles or [],
        extractor_version="1.0.0",
        extraction_duration_ms=0,
    )


class TestPortScanRule:
    """PortScanRule evaluation."""

    def test_no_profiles_no_findings(self):
        rule = PortScanRule()
        features = _make_features()
        findings = rule.evaluate(features)
        assert findings == []

    def test_non_suspect_profile_no_finding(self):
        profile = ConnectionProfile(
            src_ip=IPv4Address("10.0.0.1"),
            unique_dst_ips=2,
            unique_dst_ports=5,
            total_connections=10,
            failed_connections=0,
            success_connections=10,
            total_bytes_sent=1000,
            total_packets_sent=10,
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
            distinct_protocols=["TCP"],
            port_scan_suspect=False,
        )
        features = _make_features([profile])
        rule = PortScanRule()
        findings = rule.evaluate(features)
        assert findings == []

    def test_suspect_profile_creates_finding(self):
        profile = ConnectionProfile(
            src_ip=IPv4Address("10.0.0.1"),
            unique_dst_ips=1,
            unique_dst_ports=25,
            total_connections=50,
            failed_connections=40,
            success_connections=10,
            total_bytes_sent=5000,
            total_packets_sent=50,
            first_seen=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
            last_seen=datetime(2024, 1, 1, 0, 0, 10, tzinfo=UTC),
            distinct_protocols=["TCP"],
            failed_connection_ratio=0.8,
            port_scan_suspect=True,
            unique_dst_ports_per_host=25,
            connections_per_minute=300.0,
        )
        features = _make_features([profile])
        rule = PortScanRule()
        findings = rule.evaluate(features)
        assert len(findings) == 1

        f = findings[0]
        assert f.rule_id == "NET-001"
        assert f.rule_name == "Port Scan Detection"
        assert f.risk_score > 0
        assert f.severity >= Severity.MEDIUM
        assert "10.0.0.1" in f.title
        assert "10.0.0.1" in f.affected_entities
        assert len(f.evidences) >= 5
        assert f.recommendation != ""
        assert f.feature_snapshot["port_scan_suspect"] == 1.0

    def test_severity_scales_with_ports(self):
        """More ports → higher severity."""
        base_kw = dict(
            src_ip=IPv4Address("10.0.0.1"),
            unique_dst_ips=1,
            total_connections=100,
            failed_connections=90,
            success_connections=10,
            total_bytes_sent=5000,
            total_packets_sent=100,
            first_seen=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
            last_seen=datetime(2024, 1, 1, 0, 0, 10, tzinfo=UTC),
            distinct_protocols=["TCP"],
            failed_connection_ratio=0.9,
            port_scan_suspect=True,
        )
        rule = PortScanRule()

        # CRITICAL: >= 100 ports + high cpm
        high = ConnectionProfile(
            unique_dst_ports=120,
            unique_dst_ports_per_host=120,
            connections_per_minute=600.0,
            **base_kw,
        )
        f_high = rule.evaluate(_make_features([high]))
        assert f_high[0].severity == Severity.CRITICAL

        # MEDIUM: >= 30 ports, lower cpm
        mid = ConnectionProfile(
            unique_dst_ports=35,
            unique_dst_ports_per_host=35,
            connections_per_minute=60.0,
            **base_kw,
        )
        f_mid = rule.evaluate(_make_features([mid]))
        assert f_mid[0].severity == Severity.MEDIUM

    def test_multiple_suspect_profiles(self):
        """Multiple suspect IPs produce multiple findings."""
        rule = PortScanRule()
        base = dict(
            unique_dst_ips=1,
            total_connections=30,
            failed_connections=25,
            success_connections=5,
            total_bytes_sent=2000,
            total_packets_sent=30,
            first_seen=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
            last_seen=datetime(2024, 1, 1, 0, 0, 5, tzinfo=UTC),
            distinct_protocols=["TCP"],
            failed_connection_ratio=0.83,
            port_scan_suspect=True,
            connections_per_minute=360.0,
        )
        p1 = ConnectionProfile(
            src_ip=IPv4Address("10.0.0.1"),
            unique_dst_ports=40,
            unique_dst_ports_per_host=40,
            **base,
        )
        p2 = ConnectionProfile(
            src_ip=IPv4Address("10.0.0.2"),
            unique_dst_ports=55,
            unique_dst_ports_per_host=55,
            **base,
        )
        features = _make_features([p1, p2])
        findings = rule.evaluate(features)
        assert len(findings) == 2
        assert findings[0].affected_entities != findings[1].affected_entities

    def test_evidence_contains_key_values(self):
        """Evidence objects have correct keys and types."""
        profile = ConnectionProfile(
            src_ip=IPv4Address("10.0.0.1"),
            unique_dst_ips=2,
            unique_dst_ports=30,
            total_connections=40,
            failed_connections=30,
            success_connections=10,
            total_bytes_sent=4000,
            total_packets_sent=40,
            first_seen=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
            last_seen=datetime(2024, 1, 1, 0, 0, 5, tzinfo=UTC),
            distinct_protocols=["TCP"],
            failed_connection_ratio=0.75,
            port_scan_suspect=True,
            unique_dst_ports_per_host=15,
            connections_per_minute=480.0,
        )
        rule = PortScanRule()
        findings = rule.evaluate(_make_features([profile]))
        assert len(findings) == 1
        keys = {e.key for e in findings[0].evidences}
        assert "unique_dst_ports" in keys
        assert "failed_connection_ratio" in keys
        assert "connections_per_minute" in keys

    def test_raw_score_boundaries(self):
        """raw_score should be between 0 and 1."""
        profile = ConnectionProfile(
            src_ip=IPv4Address("10.0.0.1"),
            unique_dst_ips=1,
            unique_dst_ports=50,
            total_connections=100,
            failed_connections=95,
            success_connections=5,
            total_bytes_sent=5000,
            total_packets_sent=100,
            first_seen=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
            last_seen=datetime(2024, 1, 1, 0, 0, 10, tzinfo=UTC),
            distinct_protocols=["TCP"],
            failed_connection_ratio=0.95,
            port_scan_suspect=True,
            unique_dst_ports_per_host=50,
            connections_per_minute=600.0,
        )
        rule = PortScanRule()
        findings = rule.evaluate(_make_features([profile]))
        assert 0.0 <= findings[0].raw_score <= 1.0
