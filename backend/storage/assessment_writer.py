"""Persist AI Assessment results as an AiAssessment row.

Bridges the Pydantic ``AIAssessment`` contract from the AI
Assessor layer into the SQLAlchemy ``AiAssessment`` model.
"""

from __future__ import annotations

import logging
from uuid import UUID

from sqlalchemy.orm import Session

from backend.contracts.ai_output import AIAssessment
from backend.storage.models import AiAssessment

logger = logging.getLogger("netmind.storage.assessments")


def write_ai_assessment(
    db: Session,
    *,
    job_id: UUID,
    pcap_id: UUID,
    assessment: AIAssessment,
) -> AiAssessment:
    """Insert an AiAssessment row for a completed job.

    Args:
        db: Active sync SQLAlchemy session.
        job_id: The AnalysisJob that produced this assessment.
        pcap_id: The PcapFile that was analyzed.
        assessment: Result from ``AIAssessor.assess()``.

    Returns:
        The freshly inserted AiAssessment row.
    """
    row = AiAssessment(
        job_id=job_id,
        pcap_id=pcap_id,
        risk_score=None,  # score is on OverallRiskScore; the contract here is C-level
        risk_label=None,
        executive_summary=assessment.executive_summary,
        key_findings={
            "rationales": [
                {
                    "finding_id": r.finding_id,
                    "explanation": r.explanation,
                    "confidence_qualifier": r.confidence_qualifier,
                    "false_positive_likelihood": r.false_positive_likelihood,
                }
                for r in assessment.finding_rationales
            ],
        },
        recommendations={
            "steps": [
                {
                    "priority": s.priority,
                    "action": s.action,
                    "reason": s.reason,
                    "reference": s.reference,
                }
                for s in assessment.remediation_steps
            ],
        },
        protocol_distribution=None,
        top_talkers=None,
        model_name=assessment.model,
        model_confidence=None,
        raw_response=(
            f"provider={assessment.provider};"
            f"fallback_used={assessment.fallback_used};"
            f"generation_time_ms={assessment.generation_time_ms}"
        ),
        generation_time_ms=assessment.generation_time_ms,
    )
    db.add(row)
    db.flush()
    logger.info(
        "Persisted AiAssessment for job %s (provider=%s, fallback=%s)",
        job_id,
        assessment.provider,
        assessment.fallback_used,
    )
    return row
