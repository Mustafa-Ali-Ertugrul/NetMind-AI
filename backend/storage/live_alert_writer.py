"""Persist streaming Findings as LiveAlert rows.

``LiveAlertWriter`` bridges ``Finding`` (Pydantic contract) to
``LiveAlert`` (SQLAlchemy ORM model).  Designed for dependency-injection
into ``StreamingRuleEngine``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable
from uuid import UUID

from sqlalchemy.orm import Session

from backend.contracts.findings import Finding
from backend.storage.models import LiveAlert

logger = logging.getLogger("netmind.storage.live_alert_writer")


@dataclass
class WriteResult:
    """Outcome of a single write operation."""

    success: bool
    count: int = 0
    error: str | None = None


class LiveAlertWriter:
    """Write ``Finding`` objects to the ``live_alerts`` table.

    Usage::

        writer = LiveAlertWriter(db_session)
        result = writer.write_alerts(findings)
    """

    def __init__(self, db_session: Session) -> None:
        self._db = db_session

    def write_alert(self, finding: Finding, **kwargs: UUID) -> WriteResult:
        """Persist a single finding.

        Args:
            finding: The finding to persist.
            **kwargs: Optional override for ``session_id``.

        Returns:
            A ``WriteResult`` indicating success/failure.
        """
        try:
            self._db.add(self._finding_to_row(finding, **kwargs))
            self._db.flush()
            return WriteResult(success=True, count=1)
        except Exception as exc:
            logger.exception("Failed to write alert for rule %s", finding.rule_id)
            return WriteResult(success=False, count=0, error=str(exc))

    def write_alerts(
        self,
        findings: Iterable[Finding],
        **kwargs: UUID,
    ) -> WriteResult:
        """Persist multiple findings in a single transaction.

        Args:
            findings: Iterable of findings to persist.
            **kwargs: Optional override for ``session_id``.

        Returns:
            A ``WriteResult`` with total count of persisted rows.
        """
        rows = [self._finding_to_row(f, **kwargs) for f in findings]
        if not rows:
            return WriteResult(success=True, count=0)

        try:
            self._db.add_all(rows)
            self._db.flush()
            logger.info("Persisted %d live alert(s)", len(rows))
            return WriteResult(success=True, count=len(rows))
        except Exception as exc:
            logger.exception("Failed to write %d alert(s)", len(rows))
            return WriteResult(success=False, count=0, error=str(exc))

    def _finding_to_row(
        self,
        finding: Finding,
        **kwargs: UUID,
    ) -> LiveAlert:
        """Map a Finding to an ORM LiveAlert instance.

        Keyword args may override ``session_id``.
        """
        evidence_payload = {
            "rule_id": finding.rule_id,
            "rule_name": finding.rule_name,
            "rule_version": finding.rule_version,
            "evidences": [
                {
                    "key": e.key,
                    "value": str(e.value),
                    "threshold": str(e.threshold),
                    "unit": e.unit,
                }
                for e in finding.evidences
            ],
        }

        now = datetime.now(timezone.utc)

        return LiveAlert(
            session_id=kwargs.get("session_id", finding.pcap_id),
            rule_id=finding.rule_id,
            severity=finding.severity.name.lower(),
            confidence=finding.confidence.name.lower(),
            risk_score=finding.risk_score,
            title=finding.title,
            description=finding.description,
            recommendation=finding.recommendation,
            affected_entities=finding.affected_entities,
            evidence=evidence_payload,
            feature_snapshot=finding.feature_snapshot,
            timestamp_start=finding.timestamp_start,
            timestamp_end=finding.timestamp_end,
            triggered_at=finding.created_at,
            raw_score=finding.raw_score,
            created_at=now,
            updated_at=now,
        )
