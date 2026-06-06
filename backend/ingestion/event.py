"""Event schemas for the streaming ingestion pipeline.

External producers POST events to ``POST /api/v1/ingest/event``.
These Pydantic models define the contract.
"""

from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RawEvent(BaseModel):
    """Single network event from external collector.

    Designed for minimal overhead — most fields are optional so
    lightweight collectors only need to send the 5-tuple.
    """

    # Timestamp (required)
    ts: datetime = Field(default_factory=datetime.utcnow)

    # 5-tuple (required)
    src_ip: str = Field(..., description="Source IP address (IPv4 or IPv6)")
    dst_ip: str = Field(..., description="Destination IP address (IPv4 or IPv6)")
    src_port: int = Field(..., ge=0, le=65535)
    dst_port: int = Field(..., ge=0, le=65535)
    protocol: str = Field(..., description="Protocol name or number (e.g. TCP, UDP, ICMP)")

    # Volume (optional but recommended)
    payload_bytes: int = Field(default=0, alias="bytes", description="Payload bytes in this event")
    packets: int = Field(default=1, ge=1, description="Number of packets represented by this event")

    # TCP flags (optional — helps SYN / RST flood detection)
    flags: str | None = Field(default=None, description="TCP flags string e.g. SYN, SYN+ACK, RST")

    # HTTP metadata (optional)
    http_method: str | None = Field(default=None, description="HTTP method (GET, POST …)")
    http_uri: str | None = Field(default=None, description="Request URI path")
    http_host: str | None = Field(default=None, description="HTTP Host header")
    http_status: int | None = Field(default=None, ge=100, le=599, description="HTTP status code")
    http_user_agent: str | None = Field(default=None, description="HTTP User-Agent header")

    # DNS metadata (optional)
    dns_qname: str | None = Field(default=None, description="DNS query name")
    dns_qtype: str | None = Field(default=None, description="DNS query type")

    # Collector identification (optional)
    session_id: str | None = Field(default=None, description="Logical session/group identifier")
    collector_id: str | None = Field(default=None, description="External collector name")

    # Extra fields silently ignored so divergent collectors don't break validation
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _validate_ip(cls, v: str) -> str:
        """Ensure valid IP address string."""
        if not v:
            raise ValueError("IP address cannot be empty")
        try:
            IPv4Address(v)
        except ValueError:
            try:
                IPv6Address(v)
            except ValueError as exc:
                raise ValueError(f"Invalid IP address: {v}") from exc
        return v

    @field_validator("protocol")
    @classmethod
    def _validate_protocol(cls, v: str) -> str:
        """Normalise protocol to upper-case name."""
        v = v.strip().upper()
        if not v:
            raise ValueError("Protocol cannot be empty")
        return v

    def to_flow_event(self) -> FlowEvent:
        """Convert a validated RawEvent into a fully-typed FlowEvent.

        ipaddress objects are created once here so downstream code
        doesn't need string parsing on every access.
        """
        try:
            src = IPv4Address(self.src_ip)
        except ValueError:
            src = IPv6Address(self.src_ip)
        try:
            dst = IPv4Address(self.dst_ip)
        except ValueError:
            dst = IPv6Address(self.dst_ip)

        return FlowEvent(
            ts=self.ts,
            src_ip=src,
            dst_ip=dst,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
            payload_bytes=self.payload_bytes,
            packets=self.packets,
            flags=self.flags,
            http_method=self.http_method,
            http_uri=self.http_uri,
            http_host=self.http_host,
            http_status=self.http_status,
            http_user_agent=self.http_user_agent,
            dns_qname=self.dns_qname,
            dns_qtype=self.dns_qtype,
            session_id=self.session_id,
            collector_id=self.collector_id,
        )


class FlowEvent(BaseModel):
    """Type-safe, parsed event used internally by the streaming pipeline.

    Created from ``RawEvent.to_flow_event()``. All IP addresses are
    Python ``ipaddress`` objects, flags are normalised.
    """

    ts: datetime = Field(default_factory=datetime.utcnow)

    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    src_port: int = Field(..., ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str

    payload_bytes: int = Field(default=0, alias="bytes")
    packets: int = Field(default=1, ge=1)

    flags: str | None = Field(default=None)

    http_method: str | None = Field(default=None)
    http_uri: str | None = Field(default=None)
    http_host: str | None = Field(default=None)
    http_status: int | None = Field(default=None)
    http_user_agent: str | None = Field(default=None)

    dns_qname: str | None = Field(default=None)
    dns_qtype: str | None = Field(default=None)

    session_id: str | None = Field(default=None)
    collector_id: str | None = Field(default=None)

    model_config = ConfigDict(populate_by_name=True)

    def syn_flag(self) -> bool:
        """True if event carries a SYN flag."""
        return self.flags is not None and "SYN" in self.flags.upper()

    def rst_flag(self) -> bool:
        """True if event carries a RST flag."""
        return self.flags is not None and "RST" in self.flags.upper()

    def ack_flag(self) -> bool:
        """True if event carries an ACK flag."""
        return self.flags is not None and "ACK" in self.flags.upper()

    def raw(self) -> dict[str, Any]:
        """Serialize as a JSON-friendly dict."""
        return self.model_dump(mode="json")
