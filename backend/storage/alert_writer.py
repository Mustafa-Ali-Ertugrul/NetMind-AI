"""Persist Rule Engine findings as Alert rows.

The rule engine produces ``Finding`` contracts (Pydantic). The
storage layer needs ``Alert`` rows that match the SQLAlchemy
model in ``storage/models.py``. This module is the bridge.
"""

from __future__ import annotations

import logging
from uuid import UUID

from sqlalchemy.orm import Session

from backend.contracts.findings import Finding
from backend.storage.models import Alert

logger = logging.getLogger("netmind.storage.alerts")


def write_alerts_from_findings(
    db: Session,
    *,
    job_id: UUID,
    pcap_id: UUID,
    findings: list[Finding],
) -> int:
    """Insert one Alert row per Finding.

    Args:
        db: Active sync SQLAlchemy session.
        job_id: The AnalysisJob that produced these findings.
        pcap_id: The PcapFile these findings relate to.
        findings: Rule engine output.

    Returns:
        The number of Alert rows written.
    """
    if not findings:
        logger.info("No findings to persist for job %s", job_id)
        return 0

    rows = [
        Alert(
            pcap_id=pcap_id,
            severity=f.severity.name.lower(),
            category=f.rule_id,
            title=f.title,
            description=f.description,
            evidence={
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "rule_version": f.rule_version,
                "confidence": f.confidence.name,
                "risk_score": f.risk_score,
                "raw_score": f.raw_score,
                "recommendation": f.recommendation,
                "affected_entities": f.affected_entities,
                "evidences": [
                    {
                        "key": e.key,
                        "value": str(e.value),
                        "threshold": str(e.threshold),
                        "unit": e.unit,
                    }
                    for e in f.evidences
                ],
            },
            rule_id=f.rule_id,
            ai_corroborated=False,
        )
        for f in findings
    ]

    db.add_all(rows)
    db.flush()
    logger.info(
        "Persisted %d alert(s) for job %s (pcap %s)",
        len(rows),
        job_id,
        pcap_id,
    )
    return len(rows)
