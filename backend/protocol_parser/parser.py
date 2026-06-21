"""Protocol parser coordinator.

Orchestrates streaming PCAP parsing by:
  1. Running tshark via TsharkWrapper to stream JSON objects
  2. Dispatching each packet to the correct protocol parsers
  3. Aggregating all parsed data into a ParsedProtocols contract
  4. Returning structured output with timing metadata
"""

import time
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID

from backend.contracts.parser_output import ParsedPacket, ParsedProtocols

from .parsers.dns import parse_dns_packet
from .parsers.ftp import parse_ftp_packet
from .parsers.http import parse_http_packet
from .parsers.icmp import parse_icmp_packet
from .parsers.smtp import parse_smtp_packet
from .parsers.tcp import parse_tcp_packet
from .parsers.udp import parse_udp_packet
from .tshark_wrapper import TsharkWrapper

PARSER_VERSION = "2.0.0"


class ProtocolParser:
    """Coordinator for streaming PCAP parsing across all supported protocols."""

    def __init__(
        self,
        tshark_path: str | None = None,
        extra_layers: list[str] | None = None,
        display_filter: str | None = None,
    ):
        """Initialize the protocol parser.

        Args:
            tshark_path: Path to tshark executable. If None, searches PATH.
            extra_layers: Additional tshark layers beyond the defaults.
            display_filter: Optional Wireshark display filter to apply.
        """
        self.tshark = TsharkWrapper(
            tshark_path=tshark_path,
            extra_layers=extra_layers,
        )
        self.display_filter = display_filter

    def _stream_packets(self, pcap_path: str | Path) -> Iterator[dict]:
        """Stream raw packet data from tshark.

        Args:
            pcap_path: Path to PCAP/PCAPNG file.

        Yields:
            Raw packet dictionary from tshark JSON output.

        Raises:
            TsharkError: If tshark execution fails.
        """
        yield from self.tshark.stream_packets(
            pcap_path,
            display_filter=self.display_filter,
        )

    def parse_pcap(self, pcap_path: str | Path, pcap_id: str | UUID) -> ParsedProtocols:
        """Parse a PCAP file and return structured protocol data.

        Args:
            pcap_path: Path to PCAP/PCAPNG file.
            pcap_id: UUID of the PCAP file record in the database.

        Returns:
            ParsedProtocols containing all parsed packets organized by protocol.

        Raises:
            TsharkError: If tshark execution fails.
            FileNotFoundError: If the PCAP file does not exist.
        """
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        # Normalize pcap_id to UUID
        if isinstance(pcap_id, str):
            pcap_id = UUID(pcap_id)

        start_time = time.monotonic()

        packets: list[ParsedPacket] = []
        dns_queries = []
        http_requests = []
        ftp_sessions = []
        smtp_messages = []

        packet_count = 0

        for raw_packet in self._stream_packets(pcap_path):
            packet_count += 1

            # Unwrap tshark's JSON array wrapper if needed
            # stream_packets yields individual objects, but handle both formats
            if isinstance(raw_packet, list):
                items = raw_packet
            else:
                items = [raw_packet]

            for item in items:
                # Extract the layers dict
                layers = item.get("_source", {}).get("layers", {})
                if not layers:
                    continue

                # Determine protocol from the protocol column if available
                # and try to parse with all relevant parsers

                # 1. Parse generic packet info (TCP/UDP/ICMP)
                parsed_packet = (
                    parse_tcp_packet(item, str(pcap_id))
                    or parse_udp_packet(item, str(pcap_id))
                    or parse_icmp_packet(item, str(pcap_id))
                )
                if parsed_packet:
                    packets.append(parsed_packet)

                # 2. Parse application-layer protocols
                dns = parse_dns_packet(item, str(pcap_id))
                if dns:
                    dns_queries.append(dns)

                http = parse_http_packet(item, str(pcap_id))
                if http:
                    http_requests.append(http)

                ftp = parse_ftp_packet(item, str(pcap_id))
                if ftp:
                    ftp_sessions.append(ftp)

                smtp = parse_smtp_packet(item, str(pcap_id))
                if smtp:
                    smtp_messages.append(smtp)

        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        return ParsedProtocols(
            pcap_id=pcap_id,
            packets=packets,
            dns_queries=dns_queries,
            http_requests=http_requests,
            ftp_sessions=ftp_sessions,
            smtp_messages=smtp_messages,
            parser_version=PARSER_VERSION,
            parse_duration_ms=elapsed_ms,
        )


def parse_pcap(
    pcap_path: str | Path,
    pcap_id: str | UUID,
    tshark_path: str | None = None,
    extra_layers: list[str] | None = None,
    display_filter: str | None = None,
) -> ParsedProtocols:
    """Convenience function to parse a PCAP file in one call.

    Args:
        pcap_path: Path to PCAP/PCAPNG file.
        pcap_id: UUID of the PCAP file record in the database.
        tshark_path: Path to tshark executable. If None, searches PATH.
        extra_layers: Additional tshark layers to include.
        display_filter: Optional Wireshark display filter.

    Returns:
        ParsedProtocols containing all parsed packets.

    Raises:
        TsharkError: If tshark execution fails.
        FileNotFoundError: If the PCAP file does not exist.
    """
    parser = ProtocolParser(
        tshark_path=tshark_path,
        extra_layers=extra_layers,
        display_filter=display_filter,
    )
    return parser.parse_pcap(pcap_path, pcap_id)
