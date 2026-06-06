"""Protocol Parser -> Feature Extractor contract."""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID

from pydantic import BaseModel, Field

from .enums import Protocol


class ParsedPacket(BaseModel):
    """A single packet from the PCAP. One row per packet."""

    pcap_id: UUID
    packet_number: int
    timestamp: datetime | None = None
    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    src_port: int | None = None
    dst_port: int | None = None
    protocol: Protocol
    length: int
    info: str | None = None
    tcp_flags: str | None = None


class ParsedDNS(BaseModel):
    """DNS query/response pair extracted from the PCAP."""

    pcap_id: UUID
    timestamp: datetime | None = None
    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    qname: str
    qtype: str
    response_code: str | None = None
    answers: list[str] = Field(default_factory=list)
    query_size_bytes: int | None = None


class ParsedHTTP(BaseModel):
    """HTTP request metadata extracted from the PCAP."""

    pcap_id: UUID
    timestamp: datetime | None = None
    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    method: str
    host: str | None = None
    uri: str
    status_code: int | None = None
    user_agent: str | None = None
    content_type: str | None = None
    request_length: int | None = None


class ParsedFTP(BaseModel):
    """FTP control-channel command or response."""

    pcap_id: UUID
    timestamp: datetime | None = None
    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    command: str
    argument: str | None = None
    response_code: int | None = None
    response_message: str | None = None


class ParsedSMTP(BaseModel):
    """SMTP command or response."""

    pcap_id: UUID
    timestamp: datetime | None = None
    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    command: str
    argument: str | None = None
    response_code: int | None = None
    mail_from: str | None = None
    rcpt_to: list[str] | None = None


class ParsedProtocols(BaseModel):
    """Fully parsed output of the Protocol Parser stage."""

    pcap_id: UUID
    packets: list[ParsedPacket]
    dns_queries: list[ParsedDNS] = Field(default_factory=list)
    http_requests: list[ParsedHTTP] = Field(default_factory=list)
    ftp_sessions: list[ParsedFTP] = Field(default_factory=list)
    smtp_messages: list[ParsedSMTP] = Field(default_factory=list)
    parser_version: str
    parse_duration_ms: int
