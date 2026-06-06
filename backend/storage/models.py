"""SQLAlchemy ORM models for NetMind AI.

Mapped to db/schema.sql with the architect-recommended simplifications:
  - No raw_hex BYTEA on packets
  - Aligned status values across pcap_files and analysis_jobs
  - No ftp_sessions, smtp_messages, users, audit_log (post-MVP)
"""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _utcnow() -> datetime:
    return datetime.utcnow()


class PcapFile(Base):
    __tablename__ = "pcap_files"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    filename: Mapped[str] = mapped_column(Text, nullable=False)
    original_name: Mapped[str] = mapped_column(Text, nullable=False)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    sha256: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    storage_key: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="uploaded",
    )
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    packet_count: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytes_total: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    start_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_accessed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    uploaded_by: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    packets: Mapped[list["Packet"]] = relationship(
        back_populates="pcap", cascade="all, delete-orphan"
    )
    flows: Mapped[list["Flow"]] = relationship(back_populates="pcap", cascade="all, delete-orphan")
    dns_queries: Mapped[list["DnsQuery"]] = relationship(
        back_populates="pcap", cascade="all, delete-orphan"
    )
    http_requests: Mapped[list["HttpRequest"]] = relationship(
        back_populates="pcap", cascade="all, delete-orphan"
    )
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="pcap", cascade="all, delete-orphan"
    )
    analysis_jobs: Mapped[list["AnalysisJob"]] = relationship(
        back_populates="pcap", cascade="all, delete-orphan"
    )
    ai_assessments: Mapped[list["AiAssessment"]] = relationship(
        back_populates="pcap", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','parsing','extracting','detecting',"
            "'assessing','completed','failed','uploaded','deleted')",
            name="ck_pcap_files_status",
        ),
        Index("idx_pcap_files_status", "status"),
        Index("idx_pcap_files_uploaded_at", "uploaded_at"),
        Index("idx_pcap_files_expires_at", "expires_at"),
        Index("idx_pcap_files_deleted_at", "deleted_at"),
    )


class Packet(Base):
    __tablename__ = "packets"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    pcap_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("pcap_files.id", ondelete="CASCADE"),
        nullable=False,
    )
    packet_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    src_ip: Mapped[IPv4Address | IPv6Address] = mapped_column(INET, nullable=False)
    dst_ip: Mapped[IPv4Address | IPv6Address] = mapped_column(INET, nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    length: Mapped[int] = mapped_column(Integer, nullable=False)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tcp_flags: Mapped[str | None] = mapped_column(String(16), nullable=True)
    info: Mapped[str | None] = mapped_column(Text, nullable=True)

    pcap: Mapped["PcapFile"] = relationship(back_populates="packets")

    __table_args__ = (
        Index("idx_packets_pcap_id", "pcap_id"),
        Index("idx_packets_ips", "src_ip", "dst_ip"),
        Index("idx_packets_protocol", "protocol"),
    )


class Flow(Base):
    __tablename__ = "flows"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    pcap_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("pcap_files.id", ondelete="CASCADE"),
        nullable=False,
    )
    src_ip: Mapped[IPv4Address | IPv6Address] = mapped_column(INET, nullable=False)
    dst_ip: Mapped[IPv4Address | IPv6Address] = mapped_column(INET, nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    bytes_sent: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_recv: Mapped[int] = mapped_column(BigInteger, default=0)
    packets_count: Mapped[int] = mapped_column(Integer, default=0)
    start_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    inter_packet_interval_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    inter_packet_interval_variance_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    ack_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)

    pcap: Mapped["PcapFile"] = relationship(back_populates="flows")

    __table_args__ = (
        Index("idx_flows_pcap_id", "pcap_id"),
        Index("idx_flows_5tuple", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"),
    )


class DnsQuery(Base):
    __tablename__ = "dns_queries"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    pcap_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("pcap_files.id", ondelete="CASCADE"),
        nullable=False,
    )
    packet_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    src_ip: Mapped[IPv4Address | None] = mapped_column(INET, nullable=True)
    dst_ip: Mapped[IPv4Address | None] = mapped_column(INET, nullable=True)
    transaction_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    qname: Mapped[str | None] = mapped_column(Text, nullable=True)
    qtype: Mapped[str | None] = mapped_column(String(16), nullable=True)
    response_code: Mapped[str | None] = mapped_column(String(16), nullable=True)
    answers: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    is_suspicious: Mapped[bool] = mapped_column(default=False)

    pcap: Mapped["PcapFile"] = relationship(back_populates="dns_queries")

    __table_args__ = (
        Index("idx_dns_pcap_id", "pcap_id"),
        Index("idx_dns_qname", "qname"),
        Index("idx_dns_suspicious", "is_suspicious"),
    )


class HttpRequest(Base):
    __tablename__ = "http_requests"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    pcap_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("pcap_files.id", ondelete="CASCADE"),
        nullable=False,
    )
    packet_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    src_ip: Mapped[IPv4Address | None] = mapped_column(INET, nullable=True)
    dst_ip: Mapped[IPv4Address | None] = mapped_column(INET, nullable=True)
    method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    host: Mapped[str | None] = mapped_column(Text, nullable=True)
    uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_headers: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    response_headers: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    is_suspicious: Mapped[bool] = mapped_column(default=False)

    pcap: Mapped["PcapFile"] = relationship(back_populates="http_requests")

    __table_args__ = (
        Index("idx_http_pcap_id", "pcap_id"),
        Index("idx_http_host", "host"),
        Index("idx_http_suspicious", "is_suspicious"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    pcap_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("pcap_files.id", ondelete="CASCADE"),
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    ai_corroborated: Mapped[bool] = mapped_column(default=False)

    pcap: Mapped["PcapFile"] = relationship(back_populates="alerts")

    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical','high','medium','low','informational')",
            name="ck_alerts_severity",
        ),
        Index("idx_alerts_pcap_id", "pcap_id"),
        Index("idx_alerts_severity", "severity"),
        Index("idx_alerts_category", "category"),
    )


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    pcap_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("pcap_files.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    worker_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_used: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    pcap: Mapped["PcapFile"] = relationship(back_populates="analysis_jobs")

    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','parsing','extracting','detecting',"
            "'assessing','completed','failed')",
            name="ck_analysis_jobs_status",
        ),
        Index("idx_jobs_pcap_id", "pcap_id"),
        Index("idx_jobs_status", "status"),
    )


class AiAssessment(Base):
    __tablename__ = "ai_assessments"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    pcap_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("pcap_files.id", ondelete="CASCADE"),
        nullable=False,
    )
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_label: Mapped[str | None] = mapped_column(String(32), nullable=True)
    executive_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    key_findings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    recommendations: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    protocol_distribution: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    top_talkers: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    model_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    raw_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    generation_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    pcap: Mapped["PcapFile"] = relationship(back_populates="ai_assessments")

    __table_args__ = (
        CheckConstraint(
            "risk_label IS NULL OR risk_label IN "
            "('Critical','High','Medium','Low','Informational')",
            name="ck_ai_assessments_risk_label",
        ),
        Index("idx_ai_pcap_id", "pcap_id"),
        Index("idx_ai_risk_score", "risk_score"),
    )


class LiveAlert(Base):
    __tablename__ = "live_alerts"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    session_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_entities: Mapped[list[str]] = mapped_column(JSONB, nullable=True, default=list)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=True, default=dict)
    feature_snapshot: Mapped[dict] = mapped_column(JSONB, nullable=True, default=dict)
    timestamp_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    timestamp_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    raw_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    events: Mapped[list["AlertEvent"]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('active','acknowledged','dismissed','resolved')",
            name="ck_live_alerts_status",
        ),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','informational')",
            name="ck_live_alerts_severity",
        ),
        CheckConstraint(
            "confidence IN ('low','medium','high','critical')",
            name="ck_live_alerts_confidence",
        ),
        Index("idx_live_alerts_session_id", "session_id"),
        Index("idx_live_alerts_rule_id", "rule_id"),
        Index("idx_live_alerts_triggered_at", "triggered_at"),
        Index("idx_live_alerts_status", "status"),
        Index("idx_live_alerts_severity_triggered", "severity", "triggered_at"),
    )


class AlertEvent(Base):
    __tablename__ = "alert_events"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    alert_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("live_alerts.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(64), nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    alert: Mapped["LiveAlert"] = relationship(back_populates="events")

    __table_args__ = (
        CheckConstraint(
            "event_type IN ('created','acknowledged','dismissed','resolved','reopened')",
            name="ck_alert_events_type",
        ),
        Index("idx_alert_events_alert_id", "alert_id"),
        Index("idx_alert_events_created", "created_at"),
    )


class RuleStats(Base):
    __tablename__ = "rule_stats"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    evaluations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    miss: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    avg_risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    max_risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    rolling_window_size: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    last_evaluation_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    __table_args__ = (
        Index("idx_rule_stats_rule_id", "rule_id"),
        Index("idx_rule_stats_session_id", "session_id"),
        Index("idx_rule_stats_last_eval_at", "last_evaluation_at"),
        Index("idx_rule_stats_rule_updated", "rule_id", "updated_at"),
    )


class RulePerformanceHistory(Base):
    __tablename__ = "rule_performance_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    bucket_duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    evaluations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    false_positive_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    avg_risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    __table_args__ = (
        Index("idx_rph_rule_id", "rule_id"),
        Index("idx_rph_bucket_start", "bucket_start"),
        Index("idx_rph_rule_bucket", "rule_id", "bucket_start"),
    )


class FlowSample(Base):
    __tablename__ = "flow_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    src_ip: Mapped[IPv4Address | IPv6Address] = mapped_column(INET, nullable=False)
    dst_ip: Mapped[IPv4Address | IPv6Address] = mapped_column(INET, nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    bytes_total: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    packets_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    flow_metadata: Mapped[dict] = mapped_column(JSONB, nullable=True, default=dict)

    __table_args__ = (
        Index("idx_flow_samples_session_id", "session_id"),
        Index("idx_flow_samples_captured_at", "captured_at"),
        Index("idx_flow_samples_session_time", "session_id", "captured_at"),
    )
