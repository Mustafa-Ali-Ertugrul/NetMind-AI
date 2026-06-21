"""End-to-end tests for the FeatureExtractor orchestrator."""

from uuid import UUID

from backend.contracts.enums import Protocol
from backend.contracts.parser_output import ParsedProtocols
from backend.feature_extractor import FeatureExtractor, extract_features

from .fixtures import (
    make_parsed_dns,
    make_parsed_ftp,
    make_parsed_http,
    make_parsed_packet,
    make_parsed_smtp,
)

TEST_PCAP = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
PARSER_VERSION = "2.0.0"


def _make_empty_parsed() -> ParsedProtocols:
    return ParsedProtocols(
        pcap_id=TEST_PCAP,
        packets=[],
        parser_version=PARSER_VERSION,
        parse_duration_ms=0,
    )


class TestFeatureExtractor:
    """End-to-end tests for FeatureExtractor."""

    def test_empty_parsed(self):
        """Empty parsed protocols should produce valid AggregatedFeatures."""
        parsed = _make_empty_parsed()
        extractor = FeatureExtractor()
        features = extractor.extract(parsed)
        assert features.pcap_id == TEST_PCAP
        assert features.traffic_baseline.total_packets == 0
        assert features.flows == []
        assert features.connection_profiles == []
        assert features.dns_profiles == []
        assert features.extractor_version == "1.0.0"
        assert features.extraction_duration_ms >= 0

    def test_extract_features_convenience(self):
        """The convenience function should work identically."""
        parsed = _make_empty_parsed()
        features = extract_features(parsed)
        assert features.pcap_id == TEST_PCAP

    def test_single_tcp_flow(self):
        """A single TCP packet produces one flow and one connection profile."""
        pkt = make_parsed_packet(pcap_id=TEST_PCAP)
        parsed = ParsedProtocols(
            pcap_id=TEST_PCAP,
            packets=[pkt],
            parser_version=PARSER_VERSION,
            parse_duration_ms=0,
        )
        features = FeatureExtractor().extract(parsed)
        assert len(features.flows) == 1
        assert len(features.connection_profiles) == 1
        assert features.connection_profiles[0].src_ip == pkt.src_ip
        assert features.traffic_baseline.total_packets == 1

    def test_full_protocol_coverage(self):
        """All parsed protocol types should be reflected in output."""
        parsed = ParsedProtocols(
            pcap_id=TEST_PCAP,
            packets=[
                make_parsed_packet(
                    pcap_id=TEST_PCAP,
                    packet_number=1,
                    src_ip="10.0.0.1",
                    dst_ip="10.0.0.2",
                    dst_port=80,
                    timestamp="2024-01-01T00:00:00+00:00",
                ),
                make_parsed_packet(
                    pcap_id=TEST_PCAP,
                    packet_number=2,
                    src_ip="10.0.0.2",
                    dst_ip="10.0.0.1",
                    src_port=80,
                    dst_port=12345,
                    timestamp="2024-01-01T00:00:01+00:00",
                ),
            ],
            dns_queries=[
                make_parsed_dns(qname="example.com", qtype="A"),
                make_parsed_dns(qname="test.org", qtype="MX"),
            ],
            http_requests=[
                make_parsed_http(method="GET", uri="/", status_code=200),
                make_parsed_http(method="POST", uri="/login", status_code=401),
            ],
            ftp_sessions=[
                make_parsed_ftp(command="USER", argument="test"),
            ],
            smtp_messages=[
                make_parsed_smtp(command="MAIL", argument="FROM:<a@b.com>"),
            ],
            parser_version=PARSER_VERSION,
            parse_duration_ms=0,
        )
        features = FeatureExtractor().extract(parsed)
        # Flows
        assert len(features.flows) == 1  # bidirectional merge
        # Connection profiles (10.0.0.1 and 10.0.0.2)
        assert len(features.connection_profiles) == 2
        # DNS
        assert len(features.dns_profiles) == 2
        # HTTP
        assert sum(features.http_method_counts.values()) == 2
        # FTP
        assert len(features.ftp_flows) == 1
        # SMTP
        assert len(features.smtp_flows) == 1
        # Baseline
        assert features.traffic_baseline.total_packets == 2
        assert features.capture_duration_seconds > 0
        # Version
        assert features.extractor_version == "1.0.0"

    def test_version_and_timing(self):
        """Version string and extraction duration should be set."""
        parsed = _make_empty_parsed()
        features = FeatureExtractor().extract(parsed)
        assert features.extractor_version == "1.0.0"
        assert isinstance(features.extraction_duration_ms, int)
        assert features.extraction_duration_ms >= 0

    def test_multi_source_ips(self):
        """Multiple source IPs produce multiple connection profiles."""
        parsed = ParsedProtocols(
            pcap_id=TEST_PCAP,
            packets=[
                make_parsed_packet(pcap_id=TEST_PCAP, src_ip="10.0.0.1"),
                make_parsed_packet(pcap_id=TEST_PCAP, src_ip="10.0.0.2"),
            ],
            parser_version=PARSER_VERSION,
            parse_duration_ms=0,
        )
        features = FeatureExtractor().extract(parsed)
        assert len(features.connection_profiles) == 2

    def test_varied_protocols_in_packets(self):
        """TCP, UDP, and ICMP should all appear in traffic baseline."""
        parsed = ParsedProtocols(
            pcap_id=TEST_PCAP,
            packets=[
                make_parsed_packet(pcap_id=TEST_PCAP, protocol=Protocol.TCP, dst_port=80),
                make_parsed_packet(
                    pcap_id=TEST_PCAP,
                    protocol=Protocol.UDP,
                    src_port=1000,
                    dst_port=53,
                ),
                make_parsed_packet(
                    pcap_id=TEST_PCAP,
                    protocol=Protocol.ICMP,
                    src_port=None,
                    dst_port=None,
                ),
            ],
            parser_version=PARSER_VERSION,
            parse_duration_ms=0,
        )
        features = FeatureExtractor().extract(parsed)
        pcts = features.traffic_baseline.protocol_percentages
        assert "TCP" in pcts
        assert "UDP" in pcts
        assert "ICMP" in pcts
