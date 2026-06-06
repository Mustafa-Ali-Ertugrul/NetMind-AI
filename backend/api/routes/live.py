"""Live streaming ingestion and monitoring endpoints (Adım 7).

Provides 5 endpoints:

    POST /api/v1/live/ingest    — enqueue external network event
    GET  /api/v1/live/alerts    — query live alerts with filters
    GET  /api/v1/live/alerts/timeline — aggregated timeline buckets
    GET  /api/v1/live/stats     — per-rule evaluation statistics
    GET  /api/v1/live/metrics   — service health and throughput counters
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_db_session
from backend.api.schemas import (
    IngestEventRequest,
    IngestEventResponse,
    LiveAlertListResponse,
    LiveAlertResponse,
    LiveMetricsResponse,
    RuleStatsResponse,
    TimelineBucketResponse,
)
from backend.live_engine.service import LiveEngineService
from backend.storage.models import LiveAlert, RuleStats
from backend.storage.timeline_repository import TimelineRepository

logger = logging.getLogger("netmind.api.live")

router = APIRouter(prefix="/live", tags=["live"])


# ── Dependency: extract LiveEngineService from app state ────────────────


def _get_live_service(request: Request) -> LiveEngineService:
    """FastAPI dependency: return the app's singleton LiveEngineService."""
    svc: LiveEngineService | None = getattr(request.app.state, "live_service", None)
    if svc is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Live engine is not initialised. Service may be starting or stopping.",
        )
    return svc


# ── Helper: RawEvent → session_id validation ───────────────────────────


def _resolve_session_id(session_id_str: str | None) -> tuple[UUID | None, str | None]:
    """Validate a client-provided session_id string.

    Returns ``(parsed_uuid, error_message)``.  When ``session_id_str``
    is None, both values are None (caller auto-generates).  When the
    string is present but invalid, ``parsed_uuid`` is None and
    ``error_message`` contains the reason.
    """
    if session_id_str is None:
        return None, None
    try:
        return UUID(session_id_str), None
    except ValueError:
        return None, f"Invalid session_id: '{session_id_str}' (expected a UUID)"


# ── Endpoint: ingest (POST /live/ingest) ────────────────────────────────


@router.post("/ingest", response_model=IngestEventResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(
    body: IngestEventRequest,
    request: Request,
) -> IngestEventResponse:
    """Enqueue a raw network event into the live streaming pipeline.

    The event is placed onto an async bounded queue.  A background
    ``EventConsumer`` periodically flushes accumulated events through
    ``StreamingRuleEngine`` which generates alerts and rule stats.
    """
    svc = _get_live_service(request)

    # Resolve session_id — only auto-generate when NOT provided
    sid, err = _resolve_session_id(body.session_id)
    if err is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err)

    # Convert to FlowEvent and enqueue
    from backend.ingestion.event import FlowEvent
    from ipaddress import IPv4Address, IPv6Address

    # Validate IPs
    try:
        try:
            src = IPv4Address(body.src_ip)
        except ValueError:
            src = IPv6Address(body.src_ip)
        try:
            dst = IPv4Address(body.dst_ip)
        except ValueError:
            dst = IPv6Address(body.dst_ip)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid IP address: {exc}",
        ) from exc

    flow_event = FlowEvent(
        ts=body.ts or datetime.utcnow(),
        src_ip=src,
        dst_ip=dst,
        src_port=body.src_port,
        dst_port=body.dst_port,
        protocol=body.protocol.upper().strip(),
        payload_bytes=body.bytes,
        packets=max(body.packets, 1),
        flags=body.flags,
        http_method=body.http_method,
        http_uri=body.http_uri,
        http_host=body.http_host,
        http_status=body.http_status,
        http_user_agent=body.http_user_agent,
        dns_qname=body.dns_qname,
        dns_qtype=body.dns_qtype,
        session_id=str(sid) if sid else None,
        collector_id=body.collector_id,
    )

    outcome = await svc.ingest(flow_event, session_id=sid)
    return IngestEventResponse(
        queued=outcome.queued,
        session_id=outcome.session_id,
        events_queued=1,
        stream_qsize=outcome.stream_qsize,
    )


# ── Endpoint: list alerts (GET /live/alerts) ────────────────────────────


@router.get("/alerts", response_model=LiveAlertListResponse)
async def list_alerts(
    status_filter: str | None = Query(None, alias="status", description="Filter by status"),
    severity: str | None = Query(None, description="Filter by severity"),
    rule_id: str | None = Query(None, description="Filter by rule ID"),
    session_id: UUID | None = Query(None, description="Filter by session ID"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db_session),
) -> LiveAlertListResponse:
    """Query live alerts with optional filters.  Ordered by ``triggered_at DESC``."""
    stmt = select(LiveAlert).order_by(LiveAlert.triggered_at.desc())

    if status_filter is not None:
        stmt = stmt.where(LiveAlert.status == status_filter)
    if severity is not None:
        stmt = stmt.where(LiveAlert.severity == severity)
    if rule_id is not None:
        stmt = stmt.where(LiveAlert.rule_id == rule_id)
    if session_id is not None:
        stmt = stmt.where(LiveAlert.session_id == session_id)

    # Total count
    count_stmt = select(func.count()).select_from(LiveAlert)
    if status_filter is not None:
        count_stmt = count_stmt.where(LiveAlert.status == status_filter)
    if severity is not None:
        count_stmt = count_stmt.where(LiveAlert.severity == severity)
    if rule_id is not None:
        count_stmt = count_stmt.where(LiveAlert.rule_id == rule_id)
    if session_id is not None:
        count_stmt = count_stmt.where(LiveAlert.session_id == session_id)
    total_res = await db.execute(count_stmt)
    total: int = total_res.scalar() or 0

    # Paginated items
    stmt = stmt.offset(offset).limit(limit)
    res = await db.execute(stmt)
    rows = res.scalars().all()

    return LiveAlertListResponse(
        items=[LiveAlertResponse.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


# ── Endpoint: timeline (GET /live/alerts/timeline) ──────────────────────


@router.get("/alerts/timeline", response_model=list[TimelineBucketResponse])
async def get_alert_timeline(
    session_id: UUID | None = Query(None, description="Filter by session ID"),
    since: datetime | None = Query(None, description="ISO 8601 start (default: now − 24h)"),
    bucket: str = Query("hour", pattern="^(hour|day)$"),
    db: AsyncSession = Depends(get_db_session),
) -> list[TimelineBucketResponse]:
    """Aggregated timeline: alerts grouped by rule_id and time bucket."""
    if since is None:
        since = datetime.utcnow() - timedelta(hours=24)

    repo = TimelineRepository(db)
    buckets = await repo.query(since=since, bucket=bucket, session_id=session_id)
    return [TimelineBucketResponse.model_validate(b) for b in buckets]


# ── Endpoint: rule stats (GET /live/stats) ──────────────────────────────


@router.get("/stats", response_model=list[RuleStatsResponse])
async def get_rule_stats(
    session_id: UUID | None = Query(None, description="Filter by session ID"),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db_session),
) -> list[RuleStatsResponse]:
    """Per-rule evaluation statistics.  Ordered by ``updated_at DESC``."""
    stmt = select(RuleStats).order_by(RuleStats.updated_at.desc()).limit(limit)

    if session_id is not None:
        stmt = stmt.where(RuleStats.session_id == session_id)

    res = await db.execute(stmt)
    rows = res.scalars().all()

    results: list[RuleStatsResponse] = []
    for r in rows:
        hit_ratio = 0.0
        if r.evaluations > 0:
            hit_ratio = round(r.hits / r.evaluations, 4)
        results.append(
            RuleStatsResponse(
                rule_id=r.rule_id,
                session_id=r.session_id,
                evaluations=r.evaluations,
                hits=r.hits,
                miss=r.miss,
                avg_risk_score=r.avg_risk_score,
                max_risk_score=r.max_risk_score,
                rolling_window_size=r.rolling_window_size,
                last_evaluation_at=r.last_evaluation_at,
                hit_ratio=hit_ratio,
            )
        )

    return results


# ── Endpoint: metrics (GET /live/metrics) ────────────────────────────────


@router.get("/metrics", response_model=LiveMetricsResponse)
async def get_live_metrics(
    request: Request,
) -> LiveMetricsResponse:
    """Return live engine health counters (queue depth, throughput, alerts)."""
    svc = _get_live_service(request)
    m = svc.metrics()
    return LiveMetricsResponse(
        queue_size=m.queue_size,
        events_enqueued=m.events_enqueued,
        events_dropped=m.events_dropped,
        events_processed=m.events_processed,
        batches_processed=m.batches_processed,
        alerts_generated=m.alerts_generated,
        active_sessions=m.active_sessions,
        uptime_seconds=m.uptime_seconds,
    )
