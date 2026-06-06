"""Celery tasks for storage lifecycle management.

Single entry point ``storage_lifecycle_cleanup`` runs all policies:
  1. Expired PCAP soft-delete + file removal
  2. Expired job artifact removal
  3. Failed/cancelled job artifact cleanup
  4. Orphan artifact directory cleanup
  5. Disk-pressure emergency cleanup (when threshold exceeded)
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.storage.disk_monitor import DiskMonitor
from backend.storage.lifecycle import (
    cleanup_expired_artifacts,
    cleanup_expired_pcaps,
    disk_pressure_cleanup,
)
from backend.worker import celery_app
from backend.worker.tasks.pcap_analysis import _SyncSessionLocal

logger = logging.getLogger("netmind.worker.storage_cleanup")


@celery_app.task(name="storage_lifecycle_cleanup")
def storage_lifecycle_cleanup_task(limit: int = 200) -> dict:
    """Run all storage cleanup policies.

    This is the Celery beat entry point. It is safe to run
    concurrently (cleanup is idempotent).
    """
    settings = get_settings()
    if not settings.storage_cleanup_enabled:
        return {"status": "disabled"}

    summary: dict = {
        "status": "completed",
        "pcap_cleanup": {},
        "artifact_cleanup": {},
        "disk_pressure": {},
    }

    with _SyncSessionLocal() as db:
        assert isinstance(db, Session)

        # 1. Expired PCAPs
        pcap_result = cleanup_expired_pcaps(
            db,
            settings.upload_dir,
            limit=limit,
        )
        summary["pcap_cleanup"] = pcap_result

        # 2. Expired / failed job artifacts
        artifact_result = cleanup_expired_artifacts(
            db,
            settings.artifact_storage_path,
            retention_hours=settings.artifact_retention_hours,
            limit=limit,
        )
        summary["artifact_cleanup"] = artifact_result

        # 3. Disk-pressure emergency cleanup
        monitor = DiskMonitor(
            path=settings.upload_dir,
            threshold_pct=settings.disk_usage_threshold_pct,
        )
        if monitor.is_over_threshold():
            logger.warning(
                "Disk usage %.1f%% exceeds threshold %.0f%%; triggering emergency cleanup",
                monitor.get_usage()["percent"],
                settings.disk_usage_threshold_pct,
            )
            pressure_result = disk_pressure_cleanup(
                db,
                settings.upload_dir,
                limit=limit,
            )
            summary["disk_pressure"] = pressure_result

    total_deleted = (
        summary["pcap_cleanup"].get("files_deleted", 0)
        + summary["artifact_cleanup"].get("artifacts_deleted", 0)
        + summary["artifact_cleanup"].get("orphan_dirs_removed", 0)
    )
    logger.info(
        "Storage cleanup complete: %d files deleted, %d PCAP rows soft-deleted",
        total_deleted,
        summary["pcap_cleanup"].get("rows_soft_deleted", 0),
    )
    return summary
