"""Tests for SMTPAbuseRule."""

from datetime import datetime, timezone
from uuid import uuid4

from ipaddress import IPv4Address

from backend.contracts.enums import Severity
from backend.contracts.features import AggregatedFeatures, SMTPFlow, TrafficBaseline
from backend.rule_engine.rules import SMTPAbuseRule


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
    smtp_flows: list[SMTPFlow] | None = None,
) -> AggregatedFeatures:
    now = datetime.now(timezone.utc)
    return AggregatedFeatures(
        pcap_id=uuid4(),
        capture_duration_seconds=10.0,
        time_window_start=now,
        time_window_end=now,
        traffic_baseline=_make_baseline(),
        smtp_flows=smtp_flows or [],
        extractor_version="1.0.0",
        extraction_duration_ms=0,
    )


class TestSMTPAbuseRule:
    """SMTPAbuseRule evaluation."""

    def test_empty_flows_no_findings(self):
        rule = SMTPAbuseRule()
        features = _make_features()
        findings = rule.evaluate(features)
        assert findings == []

    def test_normal_smtp_no_finding(self):
        """Legitimate low-volume SMTP should not trigger."""
        flow = SMTPFlow(
            src_ip=IPv4Address("10.0.0.1"),
            message_count=1,
            unique_recipients=1,
            failed_auth_count=0,
            total_connections=1,
            avg_message_size_bytes=500.0,
        )
        features = _make_features([flow])
        rule = SMTPAbuseRule()
        findings = rule.evaluate(features)
        assert findings == []

    def test_many_recipients_triggers(self):
        """High unique recipients should trigger spam finding."""
        flow = SMTPFlow(
            src_ip=IPv4Address("10.0.0.1"),
            message_count=50,
            unique_recipients=60,
            failed_auth_count=0,
            total_connections=5,
            avg_message_size_bytes=2000.0,
        )
        features = _make_features([flow])
        rule = SMTPAbuseRule()
        findings = rule.evaluate(features)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "NET-004"
        assert f.rule_name == "SMTP Abuse Detection"
        assert f.severity >= Severity.MEDIUM
        assert "10.0.0.1" in f.title

    def test_failed_auth_plus_recipients_triggers(self):
        """Failed auth + many recipients = credential stuffing + spam."""
        flow = SMTPFlow(
            src_ip=IPv4Address("10.0.0.1"),
            message_count=10,
            unique_recipients=15,
            failed_auth_count=5,
            total_connections=20,
            avg_message_size_bytes=1000.0,
        )
        rule = SMTPAbuseRule()
        findings = rule.evaluate(_make_features([flow]))
        assert len(findings) == 1

    def test_many_messages_triggers(self):
        """High message_count alone with enough recipients."""
        flow = SMTPFlow(
            src_ip=IPv4Address("10.0.0.1"),
            message_count=30,
            unique_recipients=8,
            failed_auth_count=0,
            total_connections=3,
        )
        rule = SMTPAbuseRule()
        findings = rule.evaluate(_make_features([flow]))
        assert len(findings) == 1

    def test_multiple_abusive_sources(self):
        """Multiple suspicious flows produce multiple findings."""
        flow_a = SMTPFlow(
            src_ip=IPv4Address("10.0.0.1"),
            message_count=100,
            unique_recipients=120,
            failed_auth_count=0,
            total_connections=10,
        )
        flow_b = SMTPFlow(
            src_ip=IPv4Address("10.0.0.2"),
            message_count=5,
            unique_recipients=3,
            failed_auth_count=10,
            total_connections=15,
        )
        rule = SMTPAbuseRule()
        findings = rule.evaluate(_make_features([flow_a, flow_b]))
        assert len(findings) == 2

    def test_severity_scales(self):
        """More extreme abuse gets higher severity."""
        rule = SMTPAbuseRule()

        # Mild abuse
        mild = SMTPFlow(
            src_ip=IPv4Address("10.0.0.1"),
            message_count=5,
            unique_recipients=12,
            failed_auth_count=0,
            total_connections=2,
        )
        f_mild = rule.evaluate(_make_features([mild]))
        assert len(f_mild) == 1
        mild_sev = f_mild[0].severity

        # Severe abuse
        severe = SMTPFlow(
            src_ip=IPv4Address("10.0.0.2"),
            message_count=500,
            unique_recipients=600,
            failed_auth_count=0,
            total_connections=50,
        )
        f_sev = rule.evaluate(_make_features([severe]))
        assert len(f_sev) == 1
        assert f_sev[0].severity.value >= mild_sev.value

    def test_evidence_keys(self):
        """Evidence contains expected keys."""
        flow = SMTPFlow(
            src_ip=IPv4Address("10.0.0.1"),
            message_count=20,
            unique_recipients=25,
            failed_auth_count=3,
            total_connections=5,
        )
        rule = SMTPAbuseRule()
        findings = rule.evaluate(_make_features([flow]))
        assert len(findings) == 1
        keys = {e.key for e in findings[0].evidences}
        assert "unique_recipients" in keys
        assert "message_count" in keys
        assert "failed_auth_count" in keys
        assert "total_connections" in keys
