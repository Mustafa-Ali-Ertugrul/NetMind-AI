"""Live risk-stream aggregator — assessment + alert aggregation over a window.

Computes the average risk score, threat level, and top triggered rules for
PCAPs uploaded within a moving time window.  Also returns a minute-bucketed
time series suitable for a trend chart.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.analytics.window import parse_window
from backend.api.schemas import (
    RiskBucket,
    RiskStreamResponse,
    RiskStreamSnapshot,
)
from backend.storage.models import AiAssessment, Alert, PcapFile


def _compute_threat_level(risk_avg: float) -> str:
    """Map a 0–1 risk average to a threat-level string.

    Thresholds mirror the engine's score-to-label mapping but on 0–1 scale.
    """
    if risk_avg >= 0.76:
        return "critical"
    if risk_avg >= 0.51:
        return "high"
    if risk_avg >= 0.26:
        return "medium"
    return "low"


class LiveRiskAggregator:
    """Aggregate risk metrics across all PCAPs in a time window."""

    async def aggregate(self, db: AsyncSession, window: str = "5m") -> RiskStreamResponse:
        """Return a risk-stream snapshot + minute-bucketed series."""
        delta = parse_window(window)
        cutoff = datetime.utcnow() - delta

        # ── PCAPs in window (used as a filter for other queries) ──
        pcap_ids = (
            select(PcapFile.id)
            .where(
                PcapFile.uploaded_at >= cutoff,
                PcapFile.deleted_at.is_(None),
            )
            .scalar_subquery()
        )

        # ── Average risk score from AI assessments ────────────────
        risk_res = await db.execute(
            select(func.avg(AiAssessment.risk_score)).where(AiAssessment.created_at >= cutoff)
        )
        raw_avg: float | None = risk_res.scalar()
        risk_avg = round((raw_avg or 0) / 100, 4)  # normalize 0–100 → 0–1

        # ── Threat level ─────────────────────────────────────────
        threat_level = _compute_threat_level(risk_avg)

        # ── Top triggered rules (by alert count) ─────────────────
        rules_res = await db.execute(
            select(Alert.rule_id, func.count().label("cnt"))
            .where(Alert.pcap_id.in_(pcap_ids), Alert.rule_id.isnot(None))
            .group_by(Alert.rule_id)
            .order_by(func.count().desc())
            .limit(5)
        )
        top_rules = [str(r.rule_id) for r in rules_res.all() if r.rule_id]

        # ── Minute-bucketed risk time series ─────────────────────
        # Fetch all assessments in window, bucket by minute in Python
        # (portable across Postgres & SQLite).
        all_assessments = (
            await db.execute(
                select(AiAssessment.risk_score, AiAssessment.created_at).where(
                    AiAssessment.created_at >= cutoff,
                    AiAssessment.risk_score.isnot(None),
                )
            )
        ).all()

        buckets: dict[datetime, list[int]] = defaultdict(list)
        for row in all_assessments:
            minute_key = row.created_at.replace(second=0, microsecond=0)
            buckets[minute_key].append(row.risk_score)

        series = [
            RiskBucket(
                timestamp=ts,
                risk_avg=round(sum(scores) / len(scores) / 100, 4),
                count=len(scores),
            )
            for ts, scores in sorted(buckets.items())
        ]

        now = datetime.utcnow()
        return RiskStreamResponse(
            window=window,
            current=RiskStreamSnapshot(
                timestamp=now,
                risk_avg=risk_avg,
                threat_level=threat_level,
                top_rules_triggered=top_rules,
            ),
            series=series,
        )
