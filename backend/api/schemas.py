"""API request/response schemas (HTTP boundary)."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    """Response model for /health endpoint."""

    status: str
    app_name: str
    app_version: str
    environment: str
    database: str
    timestamp: datetime


class UploadResponse(BaseModel):
    """Response model for POST /api/v1/pcaps."""

    id: UUID
    filename: str
    original_name: str
    file_size: int
    sha256: str
    status: str
    job_id: UUID | None = None
    deduplicated: bool = False
    uploaded_at: datetime
    last_accessed_at: datetime | None = None
    expires_at: datetime | None = None
    deleted_at: datetime | None = None
    note: str = Field(default="Async analysis job enqueued. Poll GET /api/v1/jobs/{id} for status.")


class JobStatusResponse(BaseModel):
    """Response model for GET /api/v1/jobs/{job_id} (polling endpoint)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    pcap_id: UUID
    status: str
    worker_id: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    model_used: str | None = None
    created_at: datetime


class JobSummary(BaseModel):
    """Lightweight job info for inclusion in PcapFile responses."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None


class PcapDetailResponse(BaseModel):
    """Response model for GET /api/v1/pcaps/{pcap_id}."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    filename: str
    original_name: str
    file_size: int
    sha256: str
    storage_key: str
    status: str
    duration_seconds: float | None = None
    packet_count: int | None = None
    bytes_total: int | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    uploaded_at: datetime
    last_accessed_at: datetime | None = None
    expires_at: datetime | None = None
    deleted_at: datetime | None = None
    error_message: str | None = None
    analysis_jobs: list[JobSummary] = Field(default_factory=list)


class AlertResponse(BaseModel):
    """Alert row from the security findings pipeline."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    severity: str
    category: str
    title: str
    description: str | None = None
    evidence: dict[str, Any] | None = None
    rule_id: str | None = None
    triggered_at: datetime
    ai_corroborated: bool = False


class OverallRiskResponse(BaseModel):
    """Weighted overall risk score for a job."""

    score: int = 0
    label: str | None = None


class AnalysisResultResponse(BaseModel):
    """Full result bundle: job + pcap + findings + AI assessment."""

    job: JobStatusResponse
    pcap_id: UUID
    alerts: list[AlertResponse]
    ai_assessment: dict[str, Any] | None = None
    overall_risk: OverallRiskResponse | None = None


# ── Live engine API schemas (Adım 7) ─────────────────────────────────────


class IngestEventRequest(BaseModel):
    """Single network event from external collector (mirrors RawEvent)."""

    ts: datetime | None = None
    src_ip: str
    dst_ip: str
    src_port: int = Field(..., ge=0, le=65535)
    dst_port: int = Field(..., ge=0, le=65535)
    protocol: str
    bytes: int = Field(default=0, alias="bytes")
    packets: int = Field(default=1, ge=1)
    flags: str | None = None
    http_method: str | None = None
    http_uri: str | None = None
    http_host: str | None = None
    http_status: int | None = Field(default=None, ge=100, le=599)
    http_user_agent: str | None = None
    dns_qname: str | None = None
    dns_qtype: str | None = None
    session_id: str | None = None
    collector_id: str | None = None

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class IngestEventResponse(BaseModel):
    """Response for a successfully queued event."""

    queued: bool = True
    session_id: UUID
    events_queued: int
    stream_qsize: int


class LiveAlertResponse(BaseModel):
    """Live alert row — matches ``LiveAlert`` ORM model."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    session_id: UUID
    rule_id: str
    severity: str
    confidence: str
    risk_score: int
    title: str
    description: str | None = None
    recommendation: str | None = None
    affected_entities: list[str] = Field(default_factory=list)
    evidence: dict = Field(default_factory=dict)
    feature_snapshot: dict = Field(default_factory=dict)
    timestamp_start: datetime
    timestamp_end: datetime
    triggered_at: datetime
    status: str


class LiveAlertListResponse(BaseModel):
    """Paginated list of live alerts."""

    items: list[LiveAlertResponse]
    total: int
    limit: int
    offset: int


class TimelineBucketResponse(BaseModel):
    """A single timeline bucket — rule + time window + count."""

    rule_id: str
    bucket_start: datetime
    count: int
    max_severity: str


class RuleStatsResponse(BaseModel):
    """Per-rule statistics (computed + persisted)."""

    model_config = ConfigDict(from_attributes=True)

    rule_id: str
    session_id: UUID | None = None
    evaluations: int
    hits: int
    miss: int
    avg_risk_score: float
    max_risk_score: float
    rolling_window_size: int
    last_evaluation_at: datetime
    hit_ratio: float = 0.0


class LiveMetricsResponse(BaseModel):
    """Snapshot of live engine health counters."""

    queue_size: int = 0
    events_enqueued: int = 0
    events_dropped: int = 0
    events_processed: int = 0
    batches_processed: int = 0
    alerts_generated: int = 0
    active_sessions: int = 0
    uptime_seconds: float = 0.0


# ── Sprint 9A — Live Monitor schemas ───────────────────────────────────────


class LiveTalkerItem(BaseModel):
    """One IP in the live top-talkers list."""

    ip: str
    direction: str  # "src" | "dst"
    bytes: int
    packets: int


class LiveTalkersResponse(BaseModel):
    """Top talkers over a moving time window."""

    window: str
    talkers: list[LiveTalkerItem] = Field(default_factory=list)


class RiskStreamSnapshot(BaseModel):
    """Point-in-time risk summary."""

    timestamp: datetime
    risk_avg: float  # 0.0 – 1.0
    threat_level: str
    top_rules_triggered: list[str] = Field(default_factory=list)


class RiskBucket(BaseModel):
    """One bucket in the risk time series."""

    timestamp: datetime
    risk_avg: float
    count: int


class RiskStreamResponse(BaseModel):
    """Aggregated risk stream over a moving time window."""

    window: str
    current: RiskStreamSnapshot
    series: list[RiskBucket] = Field(default_factory=list)
