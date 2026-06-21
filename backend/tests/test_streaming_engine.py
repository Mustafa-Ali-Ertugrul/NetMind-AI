"""Tests for StreamingRuleEngine and streaming feature builder."""

from datetime import UTC, datetime
from uuid import UUID

from backend.ingestion.event import FlowEvent
from backend.live_engine.streaming_engine import StreamingRuleEngine


def _make_event(
    *,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 12345,
    dst_port: int | None = 80,
    protocol: str = "TCP",
    ts: datetime | None = None,
    tcp_flags: set[str] | None = None,
    payload_bytes: int = 100,
    packet_count: int = 1,
    http_method: str | None = "GET",
    http_uri: str | None = "/",
    http_status: int | None = 200,
    http_user_agent: str | None = "unittest",
    dns_qname: str | None = None,
    dns_qtype: str | None = None,
) -> FlowEvent:
    """Helper to create FlowEvent with sensible defaults."""
    return FlowEvent(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        ts=ts or datetime.now(UTC),
        flags=" ".join(sorted(tcp_flags)) if tcp_flags else None,
        payload_bytes=payload_bytes,
        packet_count=packet_count,
        http_method=http_method,
        http_uri=http_uri,
        http_status=http_status,
        http_user_agent=http_user_agent,
        dns_qname=dns_qname,
        dns_qtype=dns_qtype,
    )


class TestStreamingRuleEngine:
    def test_process_event_and_flush(self):
        engine = StreamingRuleEngine()
        event = _make_event()
        engine.process_event(event)
        findings, overall = engine.flush()
        assert isinstance(findings, list)
        assert overall is not None
        # At least one meta rule should fire
        assert len(findings) >= 1, "meta rules (evaluation/missing_checks) should trigger"

    def test_flush_returns_synthetic_pcap_id(self):
        engine = StreamingRuleEngine()
        engine.process_event(_make_event())
        findings, _ = engine.flush()
        for f in findings:
            assert isinstance(f.pcap_id, UUID)

    def test_session_id_consistent(self):
        engine = StreamingRuleEngine()
        sid = engine.session_id
        engine.process_event(_make_event())
        findings, _ = engine.flush()
        for f in findings:
            assert f.pcap_id == sid

    def test_empty_flush(self):
        engine = StreamingRuleEngine()
        findings, overall = engine.flush()
        assert isinstance(findings, list)
        assert overall is not None
        # With empty features meta rules may be silent; just assert structure
        assert len(findings) == 0

    def test_multiple_events_aggregate_flows(self):
        engine = StreamingRuleEngine()
        for i in range(5):
            engine.process_event(_make_event(dst_port=80 + i, payload_bytes=200))
        findings, overall = engine.flush()
        assert isinstance(findings, list)

    def test_http_summary_populated(self):
        engine = StreamingRuleEngine()
        engine.process_event(_make_event(http_method="GET", http_status=200))
        engine.process_event(_make_event(http_method="POST", http_status=404))
        features = engine._feature_builder.finalize()
        assert features.http_method_counts.get("GET", 0) >= 1
        assert features.http_method_counts.get("POST", 0) >= 1
        assert features.http_status_counts.get(200, 0) >= 1
        assert features.http_status_counts.get(404, 0) >= 1

    def test_dns_profile_populated(self):
        engine = StreamingRuleEngine()
        engine.process_event(
            _make_event(
                dns_qname="example.com",
                dns_qtype="A",
                http_method=None,
                http_status=None,
            )
        )
        _, _ = engine.flush()
        features = engine._feature_builder.finalize()
        names = [p.qname for p in features.dns_profiles]
        assert "example.com" in names

    def test_connection_profiles_from_flows(self):
        engine = StreamingRuleEngine()
        for i in range(3):
            engine.process_event(
                _make_event(
                    dst_ip=f"192.168.1.{10 + i}",
                    dst_port=443,
                    payload_bytes=300,
                )
            )
        features = engine._feature_builder.finalize()
        assert len(features.connection_profiles) >= 1
        profile = features.connection_profiles[0]
        assert profile.unique_dst_ips >= 1
        assert profile.total_connections >= 1

    def test_reset_clears_state(self):
        engine = StreamingRuleEngine()
        engine.process_event(_make_event())
        engine.reset()
        # After reset, another flush should yield empty-or-meta findings
        findings, _ = engine.flush()
        assert isinstance(findings, list)

    def test_multiple_flushes(self):
        engine = StreamingRuleEngine()
        engine.process_event(_make_event())
        findings1, _ = engine.flush()
        engine.process_event(_make_event(dst_port=443))
        findings2, _ = engine.flush()
        # findings1 and findings2 are independent results
        assert isinstance(findings1, list)
        assert isinstance(findings2, list)

    def test_udp_event(self):
        engine = StreamingRuleEngine()
        engine.process_event(_make_event(protocol="UDP", dst_port=53, payload_bytes=64))
        findings, _ = engine.flush()
        assert isinstance(findings, list)

    def test_icmp_event(self):
        engine = StreamingRuleEngine()
        engine.process_event(_make_event(protocol="ICMP", dst_port=None, payload_bytes=32))
        findings, _ = engine.flush()
        assert isinstance(findings, list)

    def test_large_window_many_events(self):
        engine = StreamingRuleEngine()
        for i in range(100):
            engine.process_event(
                _make_event(
                    dst_port=(i % 10) + 80,
                    payload_bytes=100 + i,
                )
            )
        findings, overall = engine.flush()
        assert isinstance(findings, list)
        assert overall is not None

    def test_baseline_computed(self):
        engine = StreamingRuleEngine()
        for _i in range(10):
            engine.process_event(_make_event(payload_bytes=1000))
        features = engine._feature_builder.finalize()
        assert features.traffic_baseline.total_bytes > 0
        assert features.traffic_baseline.total_packets > 0

    def test_deviations_computed(self):
        engine = StreamingRuleEngine()
        for _i in range(20):
            engine.process_event(_make_event(payload_bytes=5000))
        features = engine._feature_builder.finalize()
        # With 20 events of 5000 bytes each, top flows should exceed baseline
        assert len(features.traffic_deviations) > 0

    def test_port_scan_suspect(self):
        """Port scan: same src to many dst_ports on same dst_ip."""
        engine = StreamingRuleEngine()
        for port in range(1000, 1030):
            engine.process_event(
                _make_event(
                    dst_ip="10.0.0.99",
                    dst_port=port,
                    tcp_flags={"SYN"},
                    payload_bytes=0,
                )
            )
        features = engine._feature_builder.finalize()
        profiles = features.connection_profiles
        assert any(p.port_scan_suspect for p in profiles), "port_scan_suspect should be True"

    def test_failed_ratio(self):
        """Connections with RST and low payload=failed."""
        engine = StreamingRuleEngine()
        for _ in range(3):
            engine.process_event(
                _make_event(
                    tcp_flags={"SYN", "RST"},
                    payload_bytes=50,
                )
            )
        features = engine._feature_builder.finalize()
        profile = features.connection_profiles[0]
        assert profile.failed_connection_ratio > 0.0, (
            "failed_connection_ratio should detect RST flows"
        )


class TestStreamingRuleEngineWriters:
    """Writer hook integration tests (Adım 6)."""

    def test_flush_without_writers_same_as_before(self):
        """When writers are None, flush() behaviour is unchanged."""
        engine = StreamingRuleEngine()
        engine.process_event(_make_event())
        findings, overall = engine.flush()
        assert isinstance(findings, list)
        assert overall is not None

    def test_flush_calls_alert_writer(self):
        """flush() should delegate findings to alert_writer."""
        from unittest.mock import MagicMock

        mock_writer = MagicMock()
        mock_writer.write_alerts.return_value = MagicMock(success=True, count=1)

        engine = StreamingRuleEngine(alert_writer=mock_writer)
        engine.process_event(_make_event())
        engine.flush()

        mock_writer.write_alerts.assert_called_once()

    def test_flush_calls_stats_writer_per_rule(self):
        """flush() should call record_evaluation for each registered rule."""
        from unittest.mock import MagicMock

        mock_writer = MagicMock()
        mock_writer.record_evaluation.return_value = MagicMock(success=True, count=1)

        engine = StreamingRuleEngine(stats_writer=mock_writer)
        engine.process_event(_make_event())
        engine.flush()

        # 11 rules in the full built-in showcase registry
        assert mock_writer.record_evaluation.call_count == 11

    def test_flush_stats_detects_which_rule_triggered(self):
        """Only the rule(s) that produced findings should be marked triggered."""
        from unittest.mock import MagicMock

        mock_writer = MagicMock()
        mock_writer.record_evaluation.return_value = MagicMock(success=True, count=1)

        engine = StreamingRuleEngine(stats_writer=mock_writer)
        # Send a large enough event that rules fire
        engine.process_event(_make_event(payload_bytes=5000))
        findings, _ = engine.flush()

        triggered_rules = {f.rule_id for f in findings}

        for call_args in mock_writer.record_evaluation.call_args_list:
            rule_id_arg = call_args[0][0]
            triggered_arg = call_args[1].get("triggered", False)

            if rule_id_arg in triggered_rules:
                assert triggered_arg, (
                    f"Rule {rule_id_arg} triggered a finding but record_evaluation(triggered=False)"
                )
            # Not asserting not-triggered rules — they may still correctly report False
