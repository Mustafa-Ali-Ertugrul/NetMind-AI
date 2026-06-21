"""Health check endpoints."""

from datetime import datetime

from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_db_session
from backend.api.schemas import HealthResponse
from backend.config import get_settings

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health_check(
    db: AsyncSession = Depends(get_db_session),
) -> HealthResponse:
    """Liveness + readiness check.

    Returns 200 if the service is running and can reach the database.
    """
    settings = get_settings()
    db_status = "ok"

    try:
        result = await db.execute(text("SELECT 1"))
        result.scalar()
    except Exception:
        db_status = "unavailable"

    return HealthResponse(
        status="ok" if db_status == "ok" else "degraded",
        app_name=settings.app_name,
        app_version=settings.app_version,
        environment=settings.environment,
        database=db_status,
        timestamp=datetime.utcnow(),
    )
