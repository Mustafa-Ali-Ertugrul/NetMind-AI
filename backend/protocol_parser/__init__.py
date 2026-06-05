"""Protocol parser package for NetMind AI.

This module provides tshark-based PCAP parsing with streaming JSON output
for memory-efficient processing of large capture files.
"""

from .parser import ProtocolParser, parse_pcap
from .tshark_wrapper import TsharkWrapper, TsharkError
from .parsers.dns import parse_dns_packet
from .parsers.http import parse_http_packet
from .parsers.ftp import parse_ftp_packet
from .parsers.smtp import parse_smtp_packet
from .parsers.tcp import parse_tcp_packet
from .parsers.udp import parse_udp_packet
from .parsers.icmp import parse_icmp_packet

__all__ = [
    "ProtocolParser",
    "parse_pcap",
    "TsharkWrapper",
    "TsharkError",
    "parse_dns_packet",
    "parse_http_packet",
    "parse_ftp_packet",
    "parse_smtp_packet",
    "parse_tcp_packet",
    "parse_udp_packet",
    "parse_icmp_packet",
]
