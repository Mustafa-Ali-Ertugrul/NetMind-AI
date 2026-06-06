"""Live top-talkers aggregator — per-IP traffic over a moving time window.

Queries the ``Flow`` table for PCAPs uploaded within ``window``, groups
by ``src_ip`` and ``dst_ip``, and returns the top-N talkers sorted by
total bytes descending.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.analytics.window import parse_window
from backend.api.schemas import LiveTalkerItem, LiveTalkersResponse
from backend.storage.models import Flow, PcapFile


class LiveTalkerAggregator:
    """Aggregate top talkers across all PCAPs in a time window."""

    async def aggregate(
        self,
        db: AsyncSession,
        window: str = "5m",
        limit: int = 10,
    ) -> LiveTalkersResponse:
        """Return top-N src and dst IPs aggregated over *window*."""
        delta = parse_window(window)
        cutoff = datetime.utcnow() - delta

        # Subquery: PCAP IDs uploaded in the window (not deleted)
        pcap_ids = (
            select(PcapFile.id)
            .where(
                PcapFile.uploaded_at >= cutoff,
                PcapFile.deleted_at.is_(None),
            )
            .scalar_subquery()
        )

        # ── Top src IPs ─────────────────────────────────────────
        src_rows = (
            await db.execute(
                select(
                    Flow.src_ip,
                    (func.sum(Flow.bytes_sent) + func.sum(Flow.bytes_recv)).label("bytes"),
                    func.sum(Flow.packets_count).label("packets"),
                )
                .where(Flow.pcap_id.in_(pcap_ids))
                .group_by(Flow.src_ip)
                .order_by((func.sum(Flow.bytes_sent) + func.sum(Flow.bytes_recv)).desc())
                .limit(limit)
            )
        ).all()

        # ── Top dst IPs ─────────────────────────────────────────
        dst_rows = (
            await db.execute(
                select(
                    Flow.dst_ip,
                    (func.sum(Flow.bytes_sent) + func.sum(Flow.bytes_recv)).label("bytes"),
                    func.sum(Flow.packets_count).label("packets"),
                )
                .where(Flow.pcap_id.in_(pcap_ids))
                .group_by(Flow.dst_ip)
                .order_by((func.sum(Flow.bytes_sent) + func.sum(Flow.bytes_recv)).desc())
                .limit(limit)
            )
        ).all()

        # ── Merge, deduplicate by IP, keep highest bytes ────────
        seen: dict[str, LiveTalkerItem] = {}
        for r in src_rows:
            ip = str(r.src_ip)
            item = LiveTalkerItem(ip=ip, direction="src", bytes=r.bytes, packets=r.packets)
            # If the same IP appears as both src and dst, keep the direction with more bytes
            existing = seen.get(ip)
            if existing is None or r.bytes > existing.bytes:
                seen[ip] = item

        for r in dst_rows:
            ip = str(r.dst_ip)
            item = LiveTalkerItem(ip=ip, direction="dst", bytes=r.bytes, packets=r.packets)
            existing = seen.get(ip)
            if existing is None or r.bytes > existing.bytes:
                seen[ip] = item

        talkers = sorted(seen.values(), key=lambda x: x.bytes, reverse=True)[:limit]

        return LiveTalkersResponse(window=window, talkers=talkers)
