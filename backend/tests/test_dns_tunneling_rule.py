"""Tests for DNSTunnelingRule."""

from datetime import UTC, datetime
from uuid import uuid4

from backend.contracts.enums import Severity
from backend.contracts.features import AggregatedFeatures, DNSProfile, TrafficBaseline
from backend.rule_engine.rules import DNSTunnelingRule


def _make_baseline() -> TrafficBaseline:
    return TrafficBaseline(
        expected_bytes_per_second=1_000,
        expected_packets_per_second=100,
        total_bytes=10_000,
        total_packets=1_000,
        duration_seconds=10.0,
        unique_src_ips=1,
        unique_dst_ips=1,
        protocol_percentages={"TCP": 50.0, "UDP": 50.0},
    )


def _make_features(
    dns_profiles: list[DNSProfile] | None = None,
) -> AggregatedFeatures:
    now = datetime.now(UTC)
    return AggregatedFeatures(
        pcap_id=uuid4(),
        capture_duration_seconds=10.0,
        time_window_start=now,
        time_window_end=now,
        traffic_baseline=_make_baseline(),
        dns_profiles=dns_profiles or [],
        extractor_version="1.0.0",
        extraction_duration_ms=0,
    )


class TestDNSTunnelingRule:
    """DNSTunnelingRule evaluation."""

    def test_empty_profiles_no_findings(self):
        rule = DNSTunnelingRule()
        features = _make_features()
        findings = rule.evaluate(features)
        assert findings == []

    def test_benign_profile_no_finding(self):
        """A normal DNS profile should not trigger."""
        profile = DNSProfile(
            qname="example.com",
            query_count=5,
            unique_qtypes=["A"],
            subdomain_entropy=1.5,
            avg_query_size_bytes=40.0,
            response_success_rate=1.0,
            ttl_values=[300],
            src_ips=["10.0.0.1"],
            base64_ratio=0.0,
            unique_subdomain_count=0,
        )
        features = _make_features([profile])
        rule = DNSTunnelingRule()
        findings = rule.evaluate(features)
        assert findings == []

    def test_high_base64_ratio_triggers(self):
        """High base64_ratio alone with support from other indicators."""
        profile = DNSProfile(
            qname="tunnel.example.com",
            query_count=200,
            unique_qtypes=["TXT"],
            subdomain_entropy=5.5,
            avg_query_size_bytes=120.0,
            response_success_rate=0.9,
            ttl_values=[60],
            src_ips=["10.0.0.1"],
            base64_ratio=0.85,
            unique_subdomain_count=60,
            query_frequency_per_ip={"10.0.0.1": 20.0},
            query_frequency_per_domain=60.0,
        )
        features = _make_features([profile])
        rule = DNSTunnelingRule()
        findings = rule.evaluate(features)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "NET-002"
        assert f.severity >= Severity.MEDIUM
        assert "tunnel.example.com" in f.title
        assert "tunnel.example.com" in f.affected_entities

    def test_high_entropy_and_subdomains_triggers(self):
        """High entropy + many subdomains should trigger even without base64."""
        profile = DNSProfile(
            qname="dga.example.net",
            query_count=100,
            unique_qtypes=["A"],
            subdomain_entropy=6.2,
            avg_query_size_bytes=80.0,
            response_success_rate=0.95,
            ttl_values=[300],
            src_ips=["10.0.0.2"],
            base64_ratio=0.15,
            unique_subdomain_count=50,
            query_frequency_per_ip={"10.0.0.2": 10.0},
            query_frequency_per_domain=40.0,
        )
        features = _make_features([profile])
        rule = DNSTunnelingRule()
        findings = rule.evaluate(features)
        assert len(findings) == 1
        assert findings[0].severity >= Severity.MEDIUM

    def test_two_weak_indicators_not_enough(self):
        """Only one weak indicator should not fire."""
        profile = DNSProfile(
            qname="normal.example.com",
            query_count=50,
            unique_qtypes=["A"],
            subdomain_entropy=2.0,
            avg_query_size_bytes=45.0,
            response_success_rate=1.0,
            ttl_values=[3600],
            src_ips=["10.0.0.1"],
            base64_ratio=0.0,
            unique_subdomain_count=5,
            query_frequency_per_ip={"10.0.0.1": 8.0},
            query_frequency_per_domain=10.0,
        )
        features = _make_features([profile])
        rule = DNSTunnelingRule()
        findings = rule.evaluate(features)
        assert findings == []

    def test_multiple_suspect_profiles(self):
        """Multiple suspicious domains produce multiple findings."""
        rule = DNSTunnelingRule()
        profile_a = DNSProfile(
            qname="evil1.com",
            query_count=200,
            unique_qtypes=["TXT", "A"],
            subdomain_entropy=5.8,
            avg_query_size_bytes=130.0,
            response_success_rate=0.85,
            ttl_values=[60],
            src_ips=["10.0.0.1"],
            base64_ratio=0.9,
            unique_subdomain_count=80,
            query_frequency_per_ip={"10.0.0.1": 25.0},
            query_frequency_per_domain=80.0,
        )
        profile_b = DNSProfile(
            qname="evil2.com",
            query_count=150,
            unique_qtypes=["TXT"],
            subdomain_entropy=5.5,
            avg_query_size_bytes=100.0,
            response_success_rate=0.9,
            ttl_values=[120],
            src_ips=["10.0.0.2"],
            base64_ratio=0.75,
            unique_subdomain_count=45,
            query_frequency_per_ip={"10.0.0.2": 15.0},
            query_frequency_per_domain=50.0,
        )
        features = _make_features([profile_a, profile_b])
        findings = rule.evaluate(features)
        assert len(findings) == 2
        assert findings[0].affected_entities[0] != findings[1].affected_entities[0]

    def test_confidence_high_with_many_indicators(self):
        """All 5 indicators firing should give HIGH confidence."""
        profile = DNSProfile(
            qname="exfil.evil.com",
            query_count=500,
            unique_qtypes=["TXT", "A", "AAAA"],
            subdomain_entropy=6.5,
            avg_query_size_bytes=200.0,
            response_success_rate=0.8,
            ttl_values=[1, 5, 10],
            src_ips=["10.0.0.1"],
            base64_ratio=0.95,
            unique_subdomain_count=120,
            query_frequency_per_ip={"10.0.0.1": 50.0},
            query_frequency_per_domain=200.0,
        )
        features = _make_features([profile])
        rule = DNSTunnelingRule()
        findings = rule.evaluate(features)
        assert len(findings) == 1
        from backend.contracts.enums import Confidence

        assert findings[0].confidence == Confidence.HIGH

    def test_evidence_fields_present(self):
        """Evidence contains expected keys for DNS tunneling."""
        profile = DNSProfile(
            qname="tunnel.test.com",
            query_count=300,
            unique_qtypes=["TXT"],
            subdomain_entropy=5.0,
            avg_query_size_bytes=150.0,
            response_success_rate=0.9,
            ttl_values=[60],
            src_ips=["10.0.0.1"],
            base64_ratio=0.65,
            unique_subdomain_count=40,
            query_frequency_per_ip={"10.0.0.1": 12.0},
            query_frequency_per_domain=35.0,
        )
        rule = DNSTunnelingRule()
        findings = rule.evaluate(_make_features([profile]))
        assert len(findings) == 1
        keys = {e.key for e in findings[0].evidences}
        assert "base64_ratio" in keys
        assert "unique_subdomain_count" in keys
        assert "subdomain_entropy" in keys
        assert "query_frequency_per_domain" in keys
