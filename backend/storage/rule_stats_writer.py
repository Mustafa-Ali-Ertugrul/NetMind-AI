"""Persist per-rule evaluation statistics to the ``rule_stats`` table.

``RuleStatsWriter`` tracks how often each rule evaluates, how often it
triggers, and aggregates risk scores.  Designed for dependency-injection
into ``StreamingRuleEngine``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable
from uuid import UUID

from sqlalchemy.orm import Session

from backend.storage.models import RuleStats

logger = logging.getLogger("netmind.storage.rule_stats_writer")


@dataclass
class WriteResult:
    """Outcome of a single write operation."""

    success: bool
    count: int = 0
    error: str | None = None


class RuleStatsWriter:
    """Track per-rule evaluation statistics.

    Stats are keyed by ``(rule_id, session_id)`` to allow session-aware
    trend analysis.  Each call to ``record_evaluation`` performs an
    **upsert** — existing rows are updated in-place.

    Usage::

        writer = RuleStatsWriter(db_session)
        writer.record_evaluation("NET-001", triggered=True, risk_score=75.0, session_id=my_session)
    """

    def __init__(self, db_session: Session) -> None:
        self._db = db_session

    def record_evaluation(
        self,
        rule_id: str,
        *,
        triggered: bool,
        risk_score: float = 0.0,
        session_id: UUID | None = None,
    ) -> WriteResult:
        """Record a single rule evaluation.

        Args:
            rule_id: The rule identifier (e.g. ``NET-001``).
            triggered: Whether this evaluation produced at least one finding.
            risk_score: The max risk score from this evaluation (0 if not triggered).
            session_id: Optional session to scope the stats.

        Returns:
            A ``WriteResult`` indicating success/failure.
        """
        try:
            self._upsert_rule(rule_id, triggered, risk_score, session_id)
            self._db.flush()
            return WriteResult(success=True, count=1)
        except Exception as exc:
            logger.exception(
                "Failed to record evaluation for rule %s (session=%s)",
                rule_id,
                session_id,
            )
            return WriteResult(success=False, count=0, error=str(exc))

    def record_evaluations(
        self,
        evaluations: Iterable[tuple[str, bool, float, UUID | None]],
    ) -> WriteResult:
        """Record multiple evaluations in a single transaction.

        Args:
            evaluations: Iterable of ``(rule_id, triggered, risk_score, session_id)`` tuples.

        Returns:
            A ``WriteResult`` with total count of upserted rows.
        """
        count = 0
        try:
            for rule_id, triggered, risk_score, session_id in evaluations:
                self._upsert_rule(rule_id, triggered, risk_score, session_id)
                count += 1
            self._db.flush()
            logger.info("Recorded %d rule evaluation(s)", count)
            return WriteResult(success=True, count=count)
        except Exception as exc:
            logger.exception("Failed to record %d evaluation(s)", count)
            return WriteResult(success=False, count=count, error=str(exc))

    def _upsert_rule(
        self,
        rule_id: str,
        triggered: bool,
        risk_score: float,
        session_id: UUID | None,
    ) -> None:
        """Find existing row or create a new one, then update stats."""
        now = datetime.now(timezone.utc)

        row: RuleStats | None = (
            self._db.query(RuleStats)
            .filter_by(
                rule_id=rule_id,
                session_id=session_id,
            )
            .first()
        )

        if row is None:
            row = RuleStats(
                rule_id=rule_id,
                session_id=session_id,
                evaluations=1,
                hits=1 if triggered else 0,
                miss=0 if triggered else 1,
                avg_risk_score=risk_score,
                max_risk_score=risk_score,
                rolling_window_size=100,
                last_evaluation_at=now,
                updated_at=now,
            )
            self._db.add(row)
        else:
            n = row.evaluations
            old_avg = row.avg_risk_score

            row.evaluations = n + 1
            if triggered:
                row.hits = row.hits + 1
            else:
                row.miss = row.miss + 1
            if risk_score > row.max_risk_score:
                row.max_risk_score = risk_score
            # Incremental mean: new_avg = old_avg + (score - old_avg) / n
            if n > 0:
                row.avg_risk_score = old_avg + (risk_score - old_avg) / (n + 1)
            row.last_evaluation_at = now
            row.updated_at = now
