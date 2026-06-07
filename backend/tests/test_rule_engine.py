"""Tests for RuleEngine orchestrator and OverallRiskScore."""

from datetime import datetime, timezone
from uuid import uuid4

from ipaddress import IPv4Address

from backend.contracts.enums import RiskLabel, Severity
from backend.contracts.features import (
    AggregatedFeatures,
    ConnectionProfile,
    DNSProfile,
    FTPFlow,
    FlowRecord,
    SMTPFlow,
    TrafficBaseline,
)
from backend.rule_engine import RuleEngine
from backend.rule_engine.registry import RuleRegistry


def _make_baseline() -> TrafficBaseline:
    return TrafficBaseline(
        expected_bytes_per_second=1_000,
        expected_packets_per_second=100,
        total_bytes=10_000,
        total_packets=1_000,
        duration_seconds=10.0,
        unique_src_ips=2,
        unique_dst_ips=3,
        protocol_percentages={"TCP": 80.0, "UDP": 20.0},
    )


def _make_empty_features() -> AggregatedFeatures:
    now = datetime.now(timezone.utc)
    return AggregatedFeatures(
        pcap_id=uuid4(),
        capture_duration_seconds=10.0,
        time_window_start=now,
        time_window_end=now,
        traffic_baseline=_make_baseline(),
        extractor_version="1.0.0",
        extraction_duration_ms=0,
    )


def _make_attack_features() -> AggregatedFeatures:
    """Build a feature set that triggers the full built-in demo rule set."""
    now = datetime.now(timezone.utc)
    pcap_id = uuid4()

    return AggregatedFeatures(
        pcap_id=pcap_id,
        capture_duration_seconds=30.0,
        time_window_start=now,
        time_window_end=now,
        traffic_baseline=_make_baseline(),
        connection_profiles=[
            ConnectionProfile(
                src_ip=IPv4Address("10.0.0.1"),
                unique_dst_ips=1,
                unique_dst_ports=50,
                total_connections=100,
                failed_connections=90,
                success_connections=10,
                total_bytes_sent=5000,
                total_packets_sent=100,
                first_seen=now,
                last_seen=now,
                distinct_protocols=["TCP"],
                failed_connection_ratio=0.9,
                port_scan_suspect=True,
                unique_dst_ports_per_host=50,
                connections_per_minute=300.0,
            ),
        ],
        dns_profiles=[
            DNSProfile(
                qname="tunnel.evil.com",
                query_count=200,
                unique_qtypes=["TXT", "A"],
                subdomain_entropy=5.8,
                avg_query_size_bytes=150.0,
                response_success_rate=0.85,
                ttl_values=[60],
                src_ips=["10.0.0.2"],
                base64_ratio=0.9,
                unique_subdomain_count=80,
                query_frequency_per_ip={"10.0.0.2": 20.0},
                query_frequency_per_domain=80.0,
            ),
        ],
        flows=[
            FlowRecord(
                src_ip=IPv4Address("10.0.0.5"),
                dst_ip=IPv4Address("10.0.0.6"),
                src_port=4444,
                dst_port=443,
                protocol="TCP",
                packets_total=1000,
                bytes_total=8_000_000,
                duration_ms=30_000,
                start_time=now,
                end_time=now,
                src_bytes=7_000_000,
                dst_bytes=1_000_000,
            )
        ],
        ftp_flows=[
            FTPFlow(
                src_ip=IPv4Address("10.0.0.3"),
                failed_auth_count=30,
                success_auth_count=0,
                total_commands=35,
                auth_rate_per_second=3.0,
                failed_auth_ratio=1.0,
            ),
        ],
        smtp_flows=[
            SMTPFlow(
                src_ip=IPv4Address("10.0.0.4"),
                message_count=100,
                unique_recipients=150,
                failed_auth_count=5,
                total_connections=20,
            ),
        ],
        extractor_version="1.0.0",
        extraction_duration_ms=0,
    )


class TestRuleEngine:
    """RuleEngine integration tests."""

    def test_empty_features_no_findings(self):
        """No attack features → empty findings, zero risk."""
        engine = RuleEngine()
        findings, overall = engine.analyze(_make_empty_features())
        assert findings == []
        assert overall.total_findings == 0
        assert overall.max_score == 0
        assert overall.weighted_score == 0
        assert overall.severity_label == RiskLabel.INFORMATIONAL
        assert overall.failed_rules == []

    def test_default_rules_fire_on_attack(self):
        """Attack features should trigger multiple built-in showcase rules."""
        engine = RuleEngine()
        features = _make_attack_features()
        findings, overall = engine.analyze(features)
        assert len(findings) >= 5

        rule_ids = {f.rule_id for f in findings}
        assert "NET-001" in rule_ids  # PortScan
        assert "NET-002" in rule_ids  # DNSTunneling
        assert "NET-003" in rule_ids  # FTPBruteForce
        assert "NET-004" in rule_ids  # SMTPAbuse
        assert "NET-008" in rule_ids  # TopTalker

    def test_overall_risk_scored(self):
        """OverallRiskScore should be populated with attack features."""
        engine = RuleEngine()
        features = _make_attack_features()
        findings, overall = engine.analyze(features)
        assert overall.total_findings == len(findings)
        assert overall.max_score > 0
        assert overall.weighted_score > 0
        assert overall.severity_label in (
            RiskLabel.HIGH,
            RiskLabel.CRITICAL,
            RiskLabel.MEDIUM,
            RiskLabel.LOW,
        )
        assert overall.findings_by_severity != {}
        assert len(overall.top_finding_ids) > 0
        assert all(isinstance(fid, uuid4().__class__) for fid in overall.top_finding_ids)
        assert overall.failed_rules == []

    def test_top_findings_sorted_by_risk(self):
        """Top findings should be in descending risk_score order."""
        engine = RuleEngine()
        features = _make_attack_features()
        findings, overall = engine.analyze(features)
        # Verify the top finding IDs match the highest scoring findings
        sorted_findings = sorted(findings, key=lambda f: f.risk_score, reverse=True)
        top_ids = [f.id for f in sorted_findings[:5]]
        assert overall.top_finding_ids == top_ids

    def test_severity_breakdown_counts(self):
        """findings_by_severity counts should sum to total."""
        engine = RuleEngine()
        features = _make_attack_features()
        findings, overall = engine.analyze(features)
        total_from_dict = sum(overall.findings_by_severity.values())
        assert total_from_dict == overall.total_findings

    def test_pcap_id_preserved(self):
        """All findings should share the same pcap_id as input."""
        engine = RuleEngine()
        features = _make_attack_features()
        findings, _ = engine.analyze(features)
        assert all(f.pcap_id == features.pcap_id for f in findings)

    def test_all_findings_have_required_fields(self):
        """Every finding must have non-empty required fields."""
        engine = RuleEngine()
        features = _make_attack_features()
        findings, _ = engine.analyze(features)
        for f in findings:
            assert f.title != ""
            assert f.description != ""
            assert f.recommendation != ""
            assert f.rule_id != ""
            assert f.rule_name != ""
            assert f.rule_version == "1.0.0"
            assert f.risk_score >= 0
            assert f.raw_score >= 0.0

    def test_custom_registry(self):
        """Custom registry with only one rule should work."""
        from backend.rule_engine.rules import PortScanRule

        reg = RuleRegistry()
        reg.register(PortScanRule())
        engine = RuleEngine(registry=reg)

        features = _make_attack_features()
        findings, overall = engine.analyze(features)
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids == {"NET-001"}

    def test_registry_property(self):
        """RuleEngine exposes its registry."""
        engine = RuleEngine()
        assert engine.registry is not None
        assert len(engine.registry) == 11
