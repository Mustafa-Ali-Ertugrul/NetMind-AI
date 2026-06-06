"""Pydantic schemas for storage lifecycle responses."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class DiskStatus(BaseModel):
    """Current disk usage snapshot."""

    total_gb: float
    used_gb: float
    free_gb: float
    percent: float
    over_threshold: bool
    threshold_pct: float


class StorageStatus(BaseModel):
    """Aggregate storage status for the admin endpoint."""

    disk: DiskStatus
    pcap_count: int
    pcap_total_bytes: int
    artifact_count: int
    expired_pcaps: int
    orphan_artifacts: int


class CleanupResult(BaseModel):
    """Result of a storage cleanup operation."""

    expired_pcaps_found: int = 0
    files_deleted: int = 0
    rows_soft_deleted: int = 0
    artifacts_deleted: int = 0
    errors: list[str] = []


class ArtifactInfo(BaseModel):
    """Metadata for a job artifact."""

    job_id: UUID
    pcap_id: UUID
    artifact_type: str  # "result_json" | "log"
    filename: str
    file_size: int
    created_at: datetime | None = None
