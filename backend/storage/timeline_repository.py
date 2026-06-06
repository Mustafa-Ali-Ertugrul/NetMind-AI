"""Dialect-aware timeline query repository for LiveAlert.

Routes call repository methods, never raw SQL.  The repository
detects the database dialect and selects the appropriate SQL
function (``date_trunc`` for PostgreSQL, ``strftime`` for SQLite).

Usage::

    repo = TimelineRepository(async_session)
    buckets = await repo.query(since=..., bucket="hour")
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.storage.models import LiveAlert


class TimelineBucket(BaseModel):
    """Single bucket: rule_id + time window start + count + max severity."""

    rule_id: str
    bucket_start: datetime
    count: int
    max_severity: str


# Severity rank (lower = more severe) for MIN aggregation
_SEVERITY_RANK = case(
    (LiveAlert.severity == "critical", 1),
    (LiveAlert.severity == "high", 2),
    (LiveAlert.severity == "medium", 3),
    (LiveAlert.severity == "low", 4),
    (LiveAlert.severity == "informational", 5),
    else_=6,
)

_RANK_TO_SEVERITY = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
    5: "informational",
    6: "informational",
}


class TimelineRepository:
    """Dialect-aware timeline queries for ``LiveAlert``."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def query(
        self,
        *,
        since: datetime,
        bucket: str = "hour",
        session_id: UUID | None = None,
    ) -> list[TimelineBucket]:
        """Return aggregated timeline buckets.

        Args:
            since: Only include alerts triggered at or after this time.
            bucket: ``"hour"`` (default) or ``"day"``.
            session_id: Optional session ID filter.

        Returns:
            List of ``TimelineBucket`` ordered by bucket_start DESC,
            then count DESC.
        """
        bucket_expr = self._bucket_expr(bucket)

        stmt = (
            select(
                LiveAlert.rule_id,
                bucket_expr.label("bucket_start"),
                func.count(LiveAlert.id).label("count"),
                func.min(_SEVERITY_RANK).label("min_rank"),
            )
            .where(LiveAlert.triggered_at >= since)
            .group_by(LiveAlert.rule_id, bucket_expr)
            .order_by(bucket_expr.desc(), func.count(LiveAlert.id).desc())
        )

        if session_id is not None:
            stmt = stmt.where(LiveAlert.session_id == session_id)

        result = await self._db.execute(stmt)
        rows = result.all()

        return [
            TimelineBucket(
                rule_id=row.rule_id,
                bucket_start=row.bucket_start,
                count=row.count,
                max_severity=_RANK_TO_SEVERITY.get(row.min_rank, "informational"),
            )
            for row in rows
        ]

    def _bucket_expr(self, bucket: str) -> func:
        """Return the dialect-appropriate time-truncation expression."""
        try:
            dialect = self._db.get_bind().dialect.name
        except Exception:
            dialect = "sqlite"  # safest fallback

        if bucket == "day":
            if dialect == "postgresql":
                return func.date_trunc("day", LiveAlert.triggered_at)
            return func.strftime("%Y-%m-%d 00:00:00", LiveAlert.triggered_at)

        # default: hour
        if dialect == "postgresql":
            return func.date_trunc("hour", LiveAlert.triggered_at)
        return func.strftime("%Y-%m-%d %H:00:00", LiveAlert.triggered_at)
