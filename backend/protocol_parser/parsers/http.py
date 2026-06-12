"""HTTP packet parser for tshark JSON output."""

from datetime import UTC
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from uuid import UUID

from backend.contracts.parser_output import ParsedHTTP


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


def parse_http_packet(
    packet_data: dict[str, Any],
    pcap_id: str | UUID,
) -> ParsedHTTP | None:
    """Parse HTTP packet from tshark JSON output.

    Args:
        packet_data: Raw packet data from tshark JSON output.
        pcap_id: UUID of the PCAP file this packet belongs to.

    Returns:
        ParsedHTTP object if packet contains HTTP data, None otherwise.
    """
    try:
        layers = _safe_get(packet_data, "_source", "layers", default={})
        if not layers:
            return None

        # Check if this is an HTTP packet
        http_layer = _safe_get(layers, "http")
        if not http_layer:
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

        # Extract HTTP fields
        method = _parse_str(_safe_get(http_layer, "http.request.method"))
        host = _parse_str(_safe_get(http_layer, "http.host"))
        uri = _parse_str(_safe_get(http_layer, "http.request.uri"))
        status_code = _parse_int(_safe_get(http_layer, "http.response.code"))
        user_agent = _parse_str(_safe_get(http_layer, "http.user_agent"))
        content_type = _parse_str(_safe_get(http_layer, "http.content_type"))
        request_length = _parse_int(_safe_get(http_layer, "http.request.full_uri.len"))

        return ParsedHTTP(
            pcap_id=pcap_id,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            method=method or "",
            host=host or "",
            uri=uri or "",
            status_code=status_code,
            user_agent=user_agent,
            content_type=content_type,
            request_length=request_length,
        )

    except Exception:
        # Gracefully handle any parsing errors
        return None
