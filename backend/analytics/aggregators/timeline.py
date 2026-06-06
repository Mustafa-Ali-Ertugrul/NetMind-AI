"""Timeline aggregator — traffic volume over time buckets."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.analytics.base import BaseAggregator
from backend.analytics.schemas import TimelineBucket, TimelineResult
from backend.storage.models import Flow


class TimelineAggregator(BaseAggregator):
    """Aggregate traffic into time buckets for a single PCAP."""

    def aggregate(
        self,
        db: Session,
        pcap_id: UUID,
        bucket_count: int = 60,
    ) -> TimelineResult:
        """Return traffic timeline divided into ``bucket_count`` slices.

        Args:
            db: Active SQLAlchemy session.
            pcap_id: UUID of the PCAP to analyse.
            bucket_count: Number of time buckets (default 60).
        """
        # Get min/max start_time for this pcap
        bounds = db.execute(
            select(
                func.min(Flow.start_time).label("min_ts"),
                func.max(Flow.end_time).label("max_ts"),
            ).where(Flow.pcap_id == pcap_id)
        ).first()

        if not bounds or not bounds.min_ts or not bounds.max_ts:
            return TimelineResult(buckets=[], bucket_duration_seconds=0)

        min_ts: datetime = bounds.min_ts
        max_ts: datetime = bounds.max_ts
        duration = (max_ts - min_ts).total_seconds()
        if duration <= 0:
            return TimelineResult(buckets=[], bucket_duration_seconds=0)

        bucket_sec = max(1, int(duration / bucket_count))

        # Build buckets using integer division of epoch seconds
        rows = db.execute(
            select(
                (func.extract("epoch", Flow.start_time) / bucket_sec)
                .cast(func.Integer())
                .label("bucket"),
                func.sum(Flow.packets_count).label("packets"),
                (func.sum(Flow.bytes_sent) + func.sum(Flow.bytes_recv)).label("bytes"),
                func.count(Flow.id).label("flows"),
            )
            .where(Flow.pcap_id == pcap_id)
            .group_by((func.extract("epoch", Flow.start_time) / bucket_sec).cast(func.Integer()))
            .order_by("bucket")
        ).all()

        buckets = []
        for r in rows:
            bucket_start = min_ts + timedelta(seconds=r.bucket * bucket_sec)
            buckets.append(
                TimelineBucket(
                    bucket_start=bucket_start.isoformat(),
                    packets=r.packets,
                    bytes=r.bytes,
                    flows=r.flows,
                )
            )

        return TimelineResult(
            buckets=buckets,
            bucket_duration_seconds=bucket_sec,
        )
