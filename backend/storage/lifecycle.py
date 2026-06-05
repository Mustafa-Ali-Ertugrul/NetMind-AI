"""Storage lifecycle helpers for PCAP artifacts."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.storage.models import PcapFile

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
            logger.warning("Failed to delete expired PCAP %s at %s: %s", pcap.id, target, exc)
            summary["errors"].append({"pcap_id": str(pcap.id), "error": str(exc)})

    db.commit()
    return summary


def mark_missing_artifacts_deleted(
    db: Session,
    upload_dir: Path,
    *,
    now: datetime | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Soft-delete expired rows whose artifact is already absent.

    Kept separate for future policies; currently cleanup_expired_pcaps handles
    both present and missing files.
    """
    return cleanup_expired_pcaps(db, upload_dir, now=now, limit=limit)
