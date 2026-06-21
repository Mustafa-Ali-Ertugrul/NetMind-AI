"""Tests for individual protocol parsers."""

from ipaddress import IPv4Address
from uuid import UUID

from backend.contracts.enums import Protocol
from backend.contracts.parser_output import (
    ParsedDNS,
    ParsedFTP,
    ParsedHTTP,
    ParsedPacket,
    ParsedSMTP,
)
from backend.protocol_parser.parsers.dns import parse_dns_packet
from backend.protocol_parser.parsers.ftp import parse_ftp_packet
from backend.protocol_parser.parsers.http import parse_http_packet
from backend.protocol_parser.parsers.icmp import parse_icmp_packet
from backend.protocol_parser.parsers.smtp import parse_smtp_packet
from backend.protocol_parser.parsers.tcp import parse_tcp_packet
from backend.protocol_parser.parsers.udp import parse_udp_packet

from .fixtures import (
    DNS_QUERY_PACKET,
    DNS_RESPONSE_PACKET,
    FTP_COMMAND_PACKET,
    FTP_RESPONSE_PACKET,
    HTTP_REQUEST_PACKET,
    HTTP_RESPONSE_PACKET,
    ICMP_PACKET,
    ICMP_RESPONSE_PACKET,
    SMTP_COMMAND_PACKET,
    SMTP_RESPONSE_PACKET,
    TCP_PACKET,
    UDP_PACKET,
    make_expected_timestamp,
)

TEST_PCAP_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"


class TestDNSParser:
    """Tests for the DNS packet parser."""

    def test_parse_dns_query(self):
        result = parse_dns_packet(DNS_QUERY_PACKET, TEST_PCAP_ID)
        assert result is not None
        assert isinstance(result, ParsedDNS)
        assert result.pcap_id == UUID(TEST_PCAP_ID)
        assert result.qname == "example.com"
        assert result.qtype == "A"
        assert result.response_code == "0"
        assert "93.184.216.34" in result.answers
        assert result.src_ip == IPv4Address("192.168.1.100")
        assert result.dst_ip == IPv4Address("8.8.8.8")
        expected_ts = make_expected_timestamp("1700000000.123456")
        assert result.timestamp == expected_ts

    def test_parse_dns_response(self):
        result = parse_dns_packet(DNS_RESPONSE_PACKET, TEST_PCAP_ID)
        assert result is not None
        assert result.qname == "example.com"
        assert result.src_ip == IPv4Address("8.8.8.8")
        assert result.dst_ip == IPv4Address("192.168.1.100")

    def test_parse_non_dns_packet(self):
        """Should return None for non-DNS packets."""
        result = parse_dns_packet(TCP_PACKET, TEST_PCAP_ID)
        assert result is None

    def test_parse_empty_data(self):
        result = parse_dns_packet({}, TEST_PCAP_ID)
        assert result is None


class TestHTTPParser:
    """Tests for the HTTP packet parser."""

    def test_parse_http_request(self):
        result = parse_http_packet(HTTP_REQUEST_PACKET, TEST_PCAP_ID)
        assert result is not None
        assert isinstance(result, ParsedHTTP)
        assert result.method == "GET"
        assert result.host == "example.com"
        assert result.uri == "/index.html"
        assert result.user_agent == "TestAgent/1.0"
        assert result.status_code is None  # Request, not response
        assert result.src_ip == IPv4Address("192.168.1.100")
        assert result.dst_ip == IPv4Address("93.184.216.34")

    def test_parse_http_response(self):
        result = parse_http_packet(HTTP_RESPONSE_PACKET, TEST_PCAP_ID)
        assert result is not None
        assert result.status_code == 200
        assert result.content_type == "text/html"
        assert result.method == ""  # No method in response

    def test_parse_non_http_packet(self):
        result = parse_http_packet(UDP_PACKET, TEST_PCAP_ID)
        assert result is None

    def test_parse_empty_data(self):
        result = parse_http_packet({}, TEST_PCAP_ID)
        assert result is None


class TestFTPParser:
    """Tests for the FTP packet parser."""

    def test_parse_ftp_command(self):
        result = parse_ftp_packet(FTP_COMMAND_PACKET, TEST_PCAP_ID)
        assert result is not None
        assert isinstance(result, ParsedFTP)
        assert result.command == "USER"
        assert result.argument == "anonymous"
        assert result.response_code is None
        assert result.src_ip == IPv4Address("192.168.1.100")
        assert result.dst_ip == IPv4Address("10.0.0.1")

    def test_parse_ftp_response(self):
        result = parse_ftp_packet(FTP_RESPONSE_PACKET, TEST_PCAP_ID)
        assert result is not None
        assert result.response_code == 230
        assert result.response_message == "Login successful"
        assert result.command == ""

    def test_parse_non_ftp_packet(self):
        result = parse_ftp_packet(DNS_QUERY_PACKET, TEST_PCAP_ID)
        assert result is None

    def test_parse_empty_data(self):
        result = parse_ftp_packet({}, TEST_PCAP_ID)
        assert result is None


class TestSMTPParser:
    """Tests for the SMTP packet parser."""

    def test_parse_smtp_command(self):
        result = parse_smtp_packet(SMTP_COMMAND_PACKET, TEST_PCAP_ID)
        assert result is not None
        assert isinstance(result, ParsedSMTP)
        assert result.command == "MAIL"
        assert result.argument == "FROM:<test@example.com>"
        assert result.mail_from == "test@example.com"
        assert result.src_ip == IPv4Address("192.168.1.100")
        assert result.dst_ip == IPv4Address("10.0.0.2")

    def test_parse_smtp_response(self):
        result = parse_smtp_packet(SMTP_RESPONSE_PACKET, TEST_PCAP_ID)
        assert result is not None
        assert result.response_code == 250
        assert result.command == ""

    def test_parse_non_smtp_packet(self):
        result = parse_smtp_packet(TCP_PACKET, TEST_PCAP_ID)
        assert result is None

    def test_parse_empty_data(self):
        result = parse_smtp_packet({}, TEST_PCAP_ID)
        assert result is None


class TestTCPParser:
    """Tests for the TCP packet parser."""

    def test_parse_tcp_packet(self):
        result = parse_tcp_packet(TCP_PACKET, TEST_PCAP_ID)
        assert result is not None
        assert isinstance(result, ParsedPacket)
        assert result.protocol == Protocol.TCP
        assert result.packet_number == 40
        assert result.src_ip == IPv4Address("10.0.0.1")
        assert result.dst_ip == IPv4Address("10.0.0.2")
        assert result.src_port == 12345
        assert result.dst_port == 443
        assert result.length == 200
        assert "ACK" in (result.info or "")

    def test_parse_non_tcp_packet(self):
        result = parse_tcp_packet(UDP_PACKET, TEST_PCAP_ID)
        assert result is None

    def test_parse_empty_data(self):
        result = parse_tcp_packet({}, TEST_PCAP_ID)
        assert result is None


class TestUDPParser:
    """Tests for the UDP packet parser."""

    def test_parse_udp_packet(self):
        result = parse_udp_packet(UDP_PACKET, TEST_PCAP_ID)
        assert result is not None
        assert isinstance(result, ParsedPacket)
        assert result.protocol == Protocol.UDP
        assert result.packet_number == 50
        assert result.src_ip == IPv4Address("10.0.0.1")
        assert result.dst_ip == IPv4Address("10.0.0.2")
        assert result.src_port == 12345
        assert result.dst_port == 53
        assert result.length == 100

    def test_parse_non_udp_packet(self):
        result = parse_udp_packet(TCP_PACKET, TEST_PCAP_ID)
        assert result is None

    def test_parse_empty_data(self):
        result = parse_udp_packet({}, TEST_PCAP_ID)
        assert result is None


class TestICMPParser:
    """Tests for the ICMP packet parser."""

    def test_parse_icmp_echo_request(self):
        result = parse_icmp_packet(ICMP_PACKET, TEST_PCAP_ID)
        assert result is not None
        assert isinstance(result, ParsedPacket)
        assert result.protocol == Protocol.ICMP
        assert result.packet_number == 60
        assert result.src_ip == IPv4Address("192.168.1.100")
        assert result.dst_ip == IPv4Address("8.8.8.8")
        assert result.src_port is None
        assert result.dst_port is None
        assert "ping" in (result.info or "").lower()

    def test_parse_icmp_echo_reply(self):
        result = parse_icmp_packet(ICMP_RESPONSE_PACKET, TEST_PCAP_ID)
        assert result is not None
        assert result.protocol == Protocol.ICMP
        assert result.src_ip == IPv4Address("8.8.8.8")
        assert result.dst_ip == IPv4Address("192.168.1.100")

    def test_parse_non_icmp_packet(self):
        result = parse_icmp_packet(TCP_PACKET, TEST_PCAP_ID)
        assert result is None

    def test_parse_empty_data(self):
        result = parse_icmp_packet({}, TEST_PCAP_ID)
        assert result is None


class TestMalformedInputs:
    """Tests for graceful handling of malformed packet data."""

    def test_none_layers(self):
        packet = {"_source": {"layers": None}}
        assert parse_dns_packet(packet, TEST_PCAP_ID) is None
        assert parse_tcp_packet(packet, TEST_PCAP_ID) is None

    def test_missing_ip(self):
        packet = {
            "_source": {
                "layers": {
                    "frame": {"frame.number": "1", "frame.time_epoch": "1.0", "frame.len": "10"},
                    "tcp": {"tcp.srcport": "80", "tcp.dstport": "443"},
                }
            }
        }
        result = parse_tcp_packet(packet, TEST_PCAP_ID)
        assert result is None  # Missing IP → None

    def test_malformed_timestamp(self):
        packet = {
            "_source": {
                "layers": {
                    "frame": {
                        "frame.number": "1",
                        "frame.time_epoch": "not-a-number",
                        "frame.len": "10",
                    },
                    "ip": {"ip.src": "1.2.3.4", "ip.dst": "5.6.7.8"},
                    "tcp": {"tcp.srcport": "80", "tcp.dstport": "443"},
                }
            }
        }
        result = parse_tcp_packet(packet, TEST_PCAP_ID)
        assert result is not None
        assert result.timestamp is None  # Gracefully degraded

    def test_partial_http_data(self):
        """Partial HTTP data should still parse what's available."""
        packet = {
            "_source": {
                "layers": {
                    "frame": {"frame.number": "1", "frame.time_epoch": "1.0", "frame.len": "10"},
                    "ip": {"ip.src": "1.2.3.4", "ip.dst": "5.6.7.8"},
                    "http": {"http.request.method": "POST"},
                }
            }
        }
        result = parse_http_packet(packet, TEST_PCAP_ID)
        assert result is not None
        assert result.method == "POST"
        assert result.host == ""  # Default empty
        assert result.uri == ""  # Default empty
