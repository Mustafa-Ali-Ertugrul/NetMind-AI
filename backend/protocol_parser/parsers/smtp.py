"""SMTP packet parser for tshark JSON output."""

from datetime import UTC
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from uuid import UUID

from backend.contracts.parser_output import ParsedSMTP


def _safe_get(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Safely navigate nested dictionary."""
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current if current is not None else default


def _parse_ip(ip_str: str | None) -> IPv4Address | IPv6Address | None:
    """Parse IP address string to IPv4Address or IPv6Address."""
    if not ip_str:
        return None
    try:
        if ":" in ip_str:
            return IPv6Address(ip_str)
        return IPv4Address(ip_str)
    except ValueError:
        return None


def _parse_int(value: Any, default: int | None = None) -> int | None:
    """Safely parse integer from various formats."""
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    if isinstance(value, list) and value:
        return _parse_int(value[0], default)
    return default


def _parse_str(value: Any, default: str | None = None) -> str | None:
    """Safely parse string from various formats."""
    if value is None:
        return default
    if isinstance(value, str):
        return value
    if isinstance(value, list) and value:
        return _parse_str(value[0], default)
    return str(value) if value is not None else default


def parse_smtp_packet(
    packet_data: dict[str, Any],
    pcap_id: str | UUID,
) -> ParsedSMTP | None:
    """Parse SMTP packet from tshark JSON output.

    Args:
        packet_data: Raw packet data from tshark JSON output.
        pcap_id: UUID of the PCAP file this packet belongs to.

    Returns:
        ParsedSMTP object if packet contains SMTP data, None otherwise.
    """
    try:
        layers = _safe_get(packet_data, "_source", "layers", default={})
        if not layers:
            return None

        # Check if this is an SMTP packet
        smtp_layer = _safe_get(layers, "smtp")
        if not smtp_layer:
            return None

        # Extract frame info
        frame = _safe_get(layers, "frame", default={})
        timestamp_str = _safe_get(frame, "frame.time_epoch")
        timestamp = None
        if timestamp_str:
            try:
                from datetime import datetime

                timestamp = datetime.fromtimestamp(float(timestamp_str), tz=UTC)
            except (ValueError, TypeError):
                pass

        # Extract IP addresses
        ip_layer = _safe_get(layers, "ip", default={})
        ipv6_layer = _safe_get(layers, "ipv6", default={})

        src_ip = _parse_ip(_safe_get(ip_layer, "ip.src")) or _parse_ip(
            _safe_get(ipv6_layer, "ipv6.src")
        )
        dst_ip = _parse_ip(_safe_get(ip_layer, "ip.dst")) or _parse_ip(
            _safe_get(ipv6_layer, "ipv6.dst")
        )

        if not src_ip or not dst_ip:
            return None

        # Extract SMTP fields
        command = _parse_str(_safe_get(smtp_layer, "smtp.command"))
        argument = _parse_str(_safe_get(smtp_layer, "smtp.parameter"))
        response_code = _parse_int(_safe_get(smtp_layer, "smtp.response.code"))
        mail_from = _parse_str(_safe_get(smtp_layer, "smtp.mail_from"))
        rcpt_to_raw = _safe_get(smtp_layer, "smtp.rcpt_to")
        rcpt_to = None
        if rcpt_to_raw:
            if isinstance(rcpt_to_raw, list):
                rcpt_to = [str(r) for r in rcpt_to_raw if r]
            else:
                rcpt_to = [str(rcpt_to_raw)]

        return ParsedSMTP(
            pcap_id=pcap_id,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            command=command or "",
            argument=argument,
            response_code=response_code,
            mail_from=mail_from,
            rcpt_to=rcpt_to,
        )

    except Exception:
        # Gracefully handle any parsing errors
        return None
