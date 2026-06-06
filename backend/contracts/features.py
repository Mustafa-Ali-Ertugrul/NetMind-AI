"""Feature Extractor -> Rule Engine contract."""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID

from pydantic import BaseModel, Field


class FlowRecord(BaseModel):
    """Aggregated 5-tuple flow: bidirectional conversation metadata."""

    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    src_port: int
    dst_port: int
    protocol: str
    packets_total: int
    bytes_total: int
    duration_ms: float
    start_time: datetime
    end_time: datetime
    src_bytes: int
    dst_bytes: int
    syn_count: int = 0
    rst_count: int = 0
    inter_packet_interval_ms: float = 0.0  # avg time between packets in flow
    inter_packet_interval_variance_ms: float = 0.0  # variance of inter-packet intervals
    ack_count: int = 0


class ConnectionProfile(BaseModel):
    """Per-source-IP behavioral summary."""

    src_ip: IPv4Address | IPv6Address
    unique_dst_ips: int
    unique_dst_ports: int
    total_connections: int
    failed_connections: int
    success_connections: int
    total_bytes_sent: int
    total_packets_sent: int
    first_seen: datetime
    last_seen: datetime
    distinct_protocols: list[str]
    failed_connection_ratio: float = 0.0
    port_scan_suspect: bool = False
    unique_dst_ports_per_host: int = 0
    connections_per_minute: float = 0.0


class DNSProfile(BaseModel):
    """Per-domain behavioral summary for DNS analysis."""

    qname: str
    query_count: int
    unique_qtypes: list[str]
    subdomain_entropy: float
    avg_query_size_bytes: float
    response_success_rate: float
    ttl_values: list[int]
    src_ips: list[str]
    query_frequency_per_ip: dict[str, float] = Field(default_factory=dict)
    query_frequency_per_domain: float = 0.0
    unique_subdomain_count: int = 0
    base64_ratio: float = 0.0


class TrafficBaseline(BaseModel):
    """Expected traffic profile for the capture window."""

    expected_bytes_per_second: float
    expected_packets_per_second: float
    total_bytes: int
    total_packets: int
    duration_seconds: float
    unique_src_ips: int
    unique_dst_ips: int
    protocol_percentages: dict[str, float]


class TrafficDeviation(BaseModel):
    """Per-flow or per-IP deviation from baseline."""

    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    bytes_exceeded_pct: float
    packets_per_second: float
    bytes_per_second: float
    is_upload_dominated: bool


class FTPFlow(BaseModel):
    """FTP session-level summary."""

    src_ip: IPv4Address | IPv6Address
    failed_auth_count: int
    success_auth_count: int
    total_commands: int
    auth_rate_per_second: float | None = None
    failed_auth_ratio: float = 0.0


class SMTPFlow(BaseModel):
    """SMTP session-level summary."""

    src_ip: IPv4Address | IPv6Address
    message_count: int
    unique_recipients: int
    failed_auth_count: int
    total_connections: int
    avg_message_size_bytes: float | None = None


class AggregatedFeatures(BaseModel):
    """Complete feature set for Rule Engine consumption."""

    pcap_id: UUID
    capture_duration_seconds: float
    time_window_start: datetime
    time_window_end: datetime

    traffic_baseline: TrafficBaseline
    traffic_deviations: list[TrafficDeviation] = Field(default_factory=list)

    connection_profiles: list[ConnectionProfile] = Field(default_factory=list)
    flows: list[FlowRecord] = Field(default_factory=list)

    dns_profiles: list[DNSProfile] = Field(default_factory=list)
    ftp_flows: list[FTPFlow] = Field(default_factory=list)
    smtp_flows: list[SMTPFlow] = Field(default_factory=list)

    http_method_counts: dict[str, int] = Field(default_factory=dict)
    http_status_counts: dict[int, int] = Field(default_factory=dict)
    http_top_uris: list[tuple[str, int]] = Field(default_factory=list)
    http_user_agents: list[str] = Field(default_factory=list)

    extractor_version: str
    extraction_duration_ms: int
