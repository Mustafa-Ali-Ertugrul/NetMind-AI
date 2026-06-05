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


class AnalysisResultResponse(BaseModel):
    """Full result bundle: job + pcap + findings + AI assessment."""

    job: JobStatusResponse
    pcap_id: UUID
    alerts: list[AlertResponse]
    ai_assessment: dict[str, Any] | None = None
