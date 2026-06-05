"""Tests for FTPBruteForceRule."""

from datetime import datetime, timezone
from uuid import uuid4

from ipaddress import IPv4Address

from backend.contracts.enums import Severity
from backend.contracts.features import AggregatedFeatures, FTPFlow, TrafficBaseline
from backend.rule_engine.rules import FTPBruteForceRule


def _make_baseline() -> TrafficBaseline:
    return TrafficBaseline(
        expected_bytes_per_second=1_000,
        expected_packets_per_second=100,
        total_bytes=10_000,
        total_packets=1_000,
        duration_seconds=10.0,
        unique_src_ips=1,
        unique_dst_ips=1,
        protocol_percentages={"TCP": 100.0},
    )


def _make_features(
    ftp_flows: list[FTPFlow] | None = None,
) -> AggregatedFeatures:
    now = datetime.now(timezone.utc)
    return AggregatedFeatures(
        pcap_id=uuid4(),
        capture_duration_seconds=10.0,
        time_window_start=now,
        time_window_end=now,
        traffic_baseline=_make_baseline(),
        ftp_flows=ftp_flows or [],
        extractor_version="1.0.0",
        extraction_duration_ms=0,
    )


class TestFTPBruteForceRule:
    """FTPBruteForceRule evaluation."""

    def test_empty_flows_no_findings(self):
        rule = FTPBruteForceRule()
        features = _make_features()
        findings = rule.evaluate(features)
        assert findings == []

    def test_normal_ftp_no_finding(self):
        """Legit FTP with no failures should not trigger."""
        flow = FTPFlow(
            src_ip=IPv4Address("10.0.0.1"),
            failed_auth_count=0,
            success_auth_count=1,
            total_commands=5,
            auth_rate_per_second=0.1,
            failed_auth_ratio=0.0,
        )
        features = _make_features([flow])
        rule = FTPBruteForceRule()
        findings = rule.evaluate(features)
        assert findings == []

    def test_few_failures_no_finding(self):
        """Fewer than FTP_FAILED_AUTH_COUNT_MIN failures should not trigger."""
        flow = FTPFlow(
            src_ip=IPv4Address("10.0.0.1"),
            failed_auth_count=2,
            success_auth_count=1,
            total_commands=6,
            auth_rate_per_second=1.0,
            failed_auth_ratio=0.67,
        )
        features = _make_features([flow])
        rule = FTPBruteForceRule()
        findings = rule.evaluate(features)
        assert findings == []

    def test_high_failure_ratio_triggers(self):
        """High failure ratio + enough attempts should trigger."""
        flow = FTPFlow(
            src_ip=IPv4Address("10.0.0.1"),
            failed_auth_count=20,
            success_auth_count=1,
            total_commands=25,
            auth_rate_per_second=2.0,
            failed_auth_ratio=0.95,
        )
        features = _make_features([flow])
        rule = FTPBruteForceRule()
        findings = rule.evaluate(features)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "NET-003"
        assert f.rule_name == "FTP Brute Force Detection"
        assert f.severity >= Severity.MEDIUM
        assert "10.0.0.1" in f.title
        assert "10.0.0.1" in f.affected_entities

    def test_very_high_rate_gives_critical(self):
        """Very high auth rate produces CRITICAL severity."""
        flow = FTPFlow(
            src_ip=IPv4Address("10.0.0.2"),
            failed_auth_count=50,
            success_auth_count=0,
            total_commands=55,
            auth_rate_per_second=5.0,
            failed_auth_ratio=1.0,
        )
        features = _make_features([flow])
        rule = FTPBruteForceRule()
        findings = rule.evaluate(features)
        assert len(findings) == 1
        assert findings[0].severity >= Severity.HIGH

    def test_multiple_flows(self):
        """Multiple brute force sources produce multiple findings."""
        flow_a = FTPFlow(
            src_ip=IPv4Address("10.0.0.1"),
            failed_auth_count=10,
            success_auth_count=0,
            total_commands=12,
            auth_rate_per_second=1.0,
            failed_auth_ratio=1.0,
        )
        flow_b = FTPFlow(
            src_ip=IPv4Address("10.0.0.2"),
            failed_auth_count=15,
            success_auth_count=1,
            total_commands=20,
            auth_rate_per_second=1.5,
            failed_auth_ratio=0.94,
        )
        features = _make_features([flow_a, flow_b])
        rule = FTPBruteForceRule()
        findings = rule.evaluate(features)
        assert len(findings) == 2
        assert findings[0].affected_entities != findings[1].affected_entities

    def test_evidence_keys(self):
        """Evidence contains the expected keys."""
        flow = FTPFlow(
            src_ip=IPv4Address("10.0.0.1"),
            failed_auth_count=25,
            success_auth_count=1,
            total_commands=30,
            auth_rate_per_second=2.5,
            failed_auth_ratio=0.96,
        )
        rule = FTPBruteForceRule()
        findings = rule.evaluate(_make_features([flow]))
        assert len(findings) == 1
        keys = {e.key for e in findings[0].evidences}
        assert "failed_auth_ratio" in keys
        assert "failed_auth_count" in keys
        assert "auth_rate_per_second" in keys
        assert "success_auth_count" in keys

    def test_feature_snapshot_fields(self):
        """feature_snapshot contains the right fields."""
        flow = FTPFlow(
            src_ip=IPv4Address("10.0.0.1"),
            failed_auth_count=10,
            success_auth_count=2,
            total_commands=15,
            auth_rate_per_second=1.0,
            failed_auth_ratio=0.83,
        )
        rule = FTPBruteForceRule()
        findings = rule.evaluate(_make_features([flow]))
        snap = findings[0].feature_snapshot
        assert "failed_auth_ratio" in snap
        assert "failed_auth_count" in snap
        assert "auth_rate_per_second" in snap
        assert "success_auth_count" in snap

    def test_none_auth_rate_handled(self):
        """None auth_rate_per_second should not crash."""
        flow = FTPFlow(
            src_ip=IPv4Address("10.0.0.1"),
            failed_auth_count=5,
            success_auth_count=0,
            total_commands=8,
            auth_rate_per_second=None,
            failed_auth_ratio=1.0,
        )
        rule = FTPBruteForceRule()
        findings = rule.evaluate(_make_features([flow]))
        assert len(findings) == 1
