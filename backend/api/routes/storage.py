"""Storage lifecycle admin endpoints.

Provides visibility into disk usage, PCAP/artifact counts,
and manual cleanup triggers.

Rate limited: cleanup is limited to 5 requests/minute per IP.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_db_session
from backend.api.rate_limit import limiter
from backend.config import get_settings
from backend.storage.schemas import CleanupResult, StorageStatus
from backend.storage.service import StorageService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/storage", tags=["storage"])


def _svc(db: AsyncSession) -> StorageService:
    """Build a StorageService from request-scoped deps."""
    return StorageService(db=db, settings=get_settings())


@router.get("/status", response_model=StorageStatus)
async def get_storage_status(
    db: AsyncSession = Depends(get_db_session),
) -> StorageStatus:
    """Return aggregate storage health: disk usage, PCAP/artifact counts."""
    return await _svc(db).get_storage_status()


@router.post("/cleanup", response_model=CleanupResult)
@limiter.limit("5/minute")
async def run_cleanup(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> CleanupResult:
    """Trigger an immediate storage lifecycle cleanup.

    Expired PCAPs are soft-deleted and their files removed.
    Orphan artifact directories are pruned.
    """
    service = _svc(db)
    logger.info("Manual cleanup triggered")
    result = await service.run_cleanup()
    logger.info(
        "Cleanup complete: %d files deleted, %d artifacts removed, %d errors",
        result.files_deleted,
        result.artifacts_deleted,
        len(result.errors),
    )
    return result
