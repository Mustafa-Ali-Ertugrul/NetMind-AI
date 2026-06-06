"""Storage lifecycle helpers for PCAP artifacts and job artifacts."""

from __future__ import annotations

import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.storage.models import AnalysisJob, PcapFile

logger = logging.getLogger("netmind.storage.lifecycle")


def cleanup_expired_pcaps(
    db: Session,
    upload_dir: Path,
    *,
    now: datetime | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Soft-delete expired PCAP rows and remove their disk artifacts.

    Returns a compact summary suitable for Celery task results.
    """
    now = now or datetime.utcnow()
    result = db.execute(
        select(PcapFile)
        .where(PcapFile.deleted_at.is_(None))
        .where(PcapFile.expires_at.is_not(None))
        .where(PcapFile.expires_at <= now)
        .limit(limit)
    )
    expired = result.scalars().all()

    summary: dict[str, Any] = {
        "expired_found": len(expired),
        "files_deleted": 0,
        "rows_soft_deleted": 0,
        "missing_files": 0,
        "errors": [],
    }

    for pcap in expired:
        target = upload_dir / pcap.storage_key
        try:
            if target.exists():
                target.unlink()
                summary["files_deleted"] += 1
            else:
                summary["missing_files"] += 1

            pcap.status = "deleted"
            pcap.deleted_at = now
            summary["rows_soft_deleted"] += 1
        except OSError as exc:
            logger.warning(
                "Failed to delete expired PCAP %s at %s: %s",
                pcap.id,
                target,
                exc,
            )
            summary["errors"].append({"pcap_id": str(pcap.id), "error": str(exc)})

    db.commit()
    return summary


def cleanup_expired_artifacts(
    db: Session,
    artifact_dir: Path,
    *,
    now: datetime | None = None,
    retention_hours: int = 168,
    limit: int = 100,
) -> dict[str, Any]:
    """Remove job artifact directories for jobs that completed long ago.

    Only deletes artifacts for jobs whose ``completed_at`` is older than
    ``retention_hours``. Failed jobs' artifacts are cleaned up immediately
    to reclaim space.
    """
    now = now or datetime.utcnow()
    summary: dict[str, Any] = {
        "artifacts_deleted": 0,
        "orphan_dirs_removed": 0,
        "errors": [],
    }

    if not artifact_dir.exists():
        return summary

    for job_dir in artifact_dir.iterdir():
        if not job_dir.is_dir():
            continue

        try:
            from uuid import UUID

            job_uuid = UUID(job_dir.name)
        except ValueError:
            # Not a UUID directory — remove as orphan
            try:
                shutil.rmtree(job_dir)
                summary["orphan_dirs_removed"] += 1
            except OSError as exc:
                summary["errors"].append({"dir": str(job_dir), "error": str(exc)})
            continue

        job = db.execute(select(AnalysisJob).where(AnalysisJob.id == job_uuid)).scalar_one_or_none()

        if job is None:
            # Orphan artifact dir — job was deleted
            try:
                shutil.rmtree(job_dir)
                summary["orphan_dirs_removed"] += 1
            except OSError as exc:
                summary["errors"].append({"dir": str(job_dir), "error": str(exc)})
            continue

        # Failed jobs: clean up immediately
        if job.status == "failed" or job.status == "cancelled":
            try:
                shutil.rmtree(job_dir)
                summary["artifacts_deleted"] += 1
            except OSError as exc:
                summary["errors"].append({"job_id": str(job.id), "error": str(exc)})
            continue

        # Completed jobs: check retention
        if job.status == "completed" and job.completed_at:
            age_hours = (now - job.completed_at).total_seconds() / 3600
            if age_hours >= retention_hours:
                try:
                    shutil.rmtree(job_dir)
                    summary["artifacts_deleted"] += 1
                except OSError as exc:
                    summary["errors"].append({"job_id": str(job.id), "error": str(exc)})

    return summary


def disk_pressure_cleanup(
    db: Session,
    upload_dir: Path,
    *,
    now: datetime | None = None,
    limit: int = 50,
    disk_usage_pct: float = 85.0,
) -> dict[str, Any]:
    """Emergency cleanup when disk usage exceeds threshold.

    Deletes the oldest expired (or soon-to-expire) PCAPs first,
    then falls through to orphan artifacts.
    """
    now = now or datetime.utcnow()
    summary: dict[str, Any] = {
        "files_deleted": 0,
        "rows_soft_deleted": 0,
        "errors": [],
    }

    # Delete oldest PCAPs (by expires_at) that are already expired
    result = db.execute(
        select(PcapFile)
        .where(PcapFile.deleted_at.is_(None))
        .where(PcapFile.expires_at.is_not(None))
        .order_by(PcapFile.expires_at.asc())
        .limit(limit)
    )
    candidates = result.scalars().all()

    for pcap in candidates:
        target = upload_dir / pcap.storage_key
        try:
            if target.exists():
                target.unlink()
                summary["files_deleted"] += 1
            pcap.status = "deleted"
            pcap.deleted_at = now
            summary["rows_soft_deleted"] += 1
        except OSError as exc:
            logger.warning("Disk pressure cleanup: failed on %s: %s", pcap.id, exc)
            summary["errors"].append({"pcap_id": str(pcap.id), "error": str(exc)})

    db.commit()
    return summary
