"""Protocol distribution aggregator."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.analytics.base import BaseAggregator
from backend.analytics.schemas import ProtocolDistributionResult, ProtocolStat
from backend.storage.models import Flow


class ProtocolDistributionAggregator(BaseAggregator):
    """Aggregate protocol distribution for a single PCAP."""

    def aggregate(self, db: Session, pcap_id: UUID) -> ProtocolDistributionResult:
        rows = db.execute(
            select(
                Flow.protocol,
                func.sum(Flow.packets_count).label("packets"),
                (func.sum(Flow.bytes_sent) + func.sum(Flow.bytes_recv)).label("bytes"),
            )
            .where(Flow.pcap_id == pcap_id)
            .group_by(Flow.protocol)
            .order_by((func.sum(Flow.bytes_sent) + func.sum(Flow.bytes_recv)).desc())
        ).all()

        total_bytes = sum(r.bytes for r in rows) or 1
        return ProtocolDistributionResult(
            protocols=[
                ProtocolStat(
                    protocol=r.protocol,
                    packets=r.packets,
                    bytes=r.bytes,
                    percentage=round((r.bytes / total_bytes) * 100, 2),
                )
                for r in rows
            ]
        )
