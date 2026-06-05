"""Celery tasks for storage lifecycle management."""

from __future__ import annotations

from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.storage.lifecycle import cleanup_expired_pcaps
from backend.worker import celery_app
from backend.worker.tasks.pcap_analysis import _SyncSessionLocal


@celery_app.task(name="cleanup_expired_pcaps")
def cleanup_expired_pcaps_task(limit: int = 100) -> dict:
    """Delete expired PCAP artifacts and soft-delete their DB rows."""
    settings = get_settings()
    if not settings.storage_cleanup_enabled:
        return {"status": "disabled"}

    with _SyncSessionLocal() as db:
        assert isinstance(db, Session)
        summary = cleanup_expired_pcaps(db, settings.upload_dir, limit=limit)
        summary["status"] = "completed"
        return summary
