"""Tests for the ProtocolParser coordinator."""

from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import pytest

from backend.contracts.parser_output import ParsedProtocols
from backend.protocol_parser import ProtocolParser, TsharkError, parse_pcap

from .fixtures import (
    DNS_QUERY_PACKET,
    FTP_COMMAND_PACKET,
    HTTP_REQUEST_PACKET,
    ICMP_PACKET,
    SMTP_COMMAND_PACKET,
    TCP_PACKET,
    UDP_PACKET,
)

TEST_PCAP_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
FAKE_TSHARK = "/usr/bin/tshark"


class TestProtocolParserCoordinator:
    """Tests for the ProtocolParser class."""

    def test_init_defaults(self):
        """Should initialize with default settings."""
        parser = ProtocolParser(tshark_path=FAKE_TSHARK)
        assert parser.display_filter is None

    def test_init_with_display_filter(self):
        """Should accept display filter."""
        parser = ProtocolParser(tshark_path=FAKE_TSHARK, display_filter="dns")
        assert parser.display_filter == "dns"

    def test_parse_pcap_file_not_found(self, tmp_path):
        """Should raise FileNotFoundError for nonexistent file."""
        parser = ProtocolParser(tshark_path=FAKE_TSHARK)
        nonexistent = tmp_path / "nonexistent" / "file.pcap"
        with pytest.raises(FileNotFoundError):
            parser.parse_pcap(str(nonexistent), TEST_PCAP_ID)


class TestParsePcapConvenience:
    """Tests for the parse_pcap convenience function."""

    def test_file_not_found(self, tmp_path):
        """Should raise FileNotFoundError for nonexistent file."""
        nonexistent = tmp_path / "nonexistent" / "file.pcap"
        with pytest.raises(FileNotFoundError):
            parse_pcap(str(nonexistent), TEST_PCAP_ID, tshark_path=FAKE_TSHARK)


class TestProtocolParserStreaming:
    """Tests for ProtocolParser with mocked tshark output."""

    @pytest.fixture
    def mock_pcap_path(self, tmp_path: Path) -> Path:
        """Create a temporary valid PCAP file."""
        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_text("fake-pcap-data")
        return pcap_file

    @pytest.fixture
    def parser(self) -> ProtocolParser:
        return ProtocolParser(tshark_path=FAKE_TSHARK)

    def test_single_dns_packet(self, parser, mock_pcap_path):
        """Should parse a single DNS packet correctly."""
        mock_packets = [DNS_QUERY_PACKET]

        with patch.object(parser, "_stream_packets", return_value=iter(mock_packets)):
            result = parser.parse_pcap(mock_pcap_path, TEST_PCAP_ID)

        assert isinstance(result, ParsedProtocols)
        assert result.pcap_id == UUID(TEST_PCAP_ID)
        assert len(result.packets) == 1  # DNS uses UDP, so one ParsedPacket
        assert len(result.dns_queries) == 1
        assert result.dns_queries[0].qname == "example.com"
        assert result.parser_version is not None
        assert result.parse_duration_ms >= 0

    def test_multiple_protocols(self, parser, mock_pcap_path):
        """Should parse multiple packets with different protocols."""
        mock_packets = [
            TCP_PACKET,
            UDP_PACKET,
            ICMP_PACKET,
            DNS_QUERY_PACKET,
            HTTP_REQUEST_PACKET,
            FTP_COMMAND_PACKET,
            SMTP_COMMAND_PACKET,
        ]

        with patch.object(parser, "_stream_packets", return_value=iter(mock_packets)):
            result = parser.parse_pcap(mock_pcap_path, TEST_PCAP_ID)

        assert isinstance(result, ParsedProtocols)
        # All 7 packets have TCP/UDP/ICMP layers → 7 ParsedPacket entries
        assert len(result.packets) == 7
        assert len(result.dns_queries) == 1
        assert len(result.http_requests) == 1
        assert len(result.ftp_sessions) == 1
        assert len(result.smtp_messages) == 1

    def test_empty_pcap(self, parser, mock_pcap_path):
        """Should handle empty PCAP files."""
        with patch.object(parser, "_stream_packets", return_value=iter([])):
            result = parser.parse_pcap(mock_pcap_path, TEST_PCAP_ID)

        assert isinstance(result, ParsedProtocols)
        assert len(result.packets) == 0
        assert len(result.dns_queries) == 0
        assert len(result.http_requests) == 0
        assert len(result.ftp_sessions) == 0
        assert len(result.smtp_messages) == 0
        assert result.parse_duration_ms >= 0

    def test_tshark_error_propagation(self, parser, mock_pcap_path):
        """Should propagate TsharkError from the wrapper."""

        def _raise_error():
            raise TsharkError("tshark not found")

        with patch.object(parser, "_stream_packets", side_effect=TsharkError("tshark not found")):
            with pytest.raises(TsharkError):
                parser.parse_pcap(mock_pcap_path, TEST_PCAP_ID)

    def test_pcap_id_string_or_uuid(self, parser, mock_pcap_path):
        """Should accept both string and UUID pcap_id."""
        mock_packets = [TCP_PACKET]

        with patch.object(parser, "_stream_packets", return_value=iter(mock_packets)):
            result_str = parser.parse_pcap(mock_pcap_path, TEST_PCAP_ID)
            result_uuid = parser.parse_pcap(mock_pcap_path, UUID(TEST_PCAP_ID))

        assert result_str.pcap_id == UUID(TEST_PCAP_ID)
        assert result_uuid.pcap_id == UUID(TEST_PCAP_ID)

    def test_malformed_packet_in_stream(self, parser, mock_pcap_path):
        """Should skip malformed packets without crashing."""
        mock_packets = [
            {"_source": {"layers": None}},  # Malformed
            TCP_PACKET,
            {},  # Empty
            UDP_PACKET,
        ]

        with patch.object(parser, "_stream_packets", return_value=iter(mock_packets)):
            result = parser.parse_pcap(mock_pcap_path, TEST_PCAP_ID)

        # Should not crash, should parse valid packets
        assert isinstance(result, ParsedProtocols)
        assert len(result.packets) == 2  # TCP + UDP

    def test_version_string(self, parser, mock_pcap_path):
        """Should include parser version in output."""
        mock_packets = [TCP_PACKET]

        with patch.object(parser, "_stream_packets", return_value=iter(mock_packets)):
            result = parser.parse_pcap(mock_pcap_path, TEST_PCAP_ID)

        assert result.parser_version == "2.0.0"
