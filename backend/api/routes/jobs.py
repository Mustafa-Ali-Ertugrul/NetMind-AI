"""Job polling endpoints (Phase 5).

Provides the polling endpoint for frontend progress and a result
endpoint that returns the full analysis bundle (findings + AI).
"""

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_db_session
from backend.api.schemas import (
    AlertResponse,
    AnalysisResultResponse,
    JobStatusResponse,
)
from backend.storage.models import AiAssessment, Alert, AnalysisJob, PcapFile

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("/{job_id}", response_model=JobStatusResponse)
async def get_job_status(
    job_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> JobStatusResponse:
    """Return the current status of an AnalysisJob.

    Frontend polls this endpoint (e.g. once per second) to render
    a progress bar. Always returns 200 with the current state
    if the job exists.
    """
    result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_id))
    job = result.scalar_one_or_none()
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found",
        )
    return JobStatusResponse.model_validate(job)


@router.get("/{job_id}/result", response_model=AnalysisResultResponse)
async def get_job_result(
    job_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> AnalysisResultResponse:
    """Return the full analysis result for a completed job.

    Returns 409 Conflict if the job has not completed yet —
    the frontend should keep polling ``/{job_id}`` until status
    is ``completed`` or ``failed``.
    """
    job_res = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_id))
    job = job_res.scalar_one_or_none()
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found",
        )

    if job.status not in {"completed", "failed"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Job is in status '{job.status}'. "
                "Poll GET /api/v1/jobs/{id} until status is 'completed' or 'failed'."
            ),
        )

    if job.status == "failed":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Job failed: {job.error_message or 'unknown error'}",
        )

    # Pull alerts written by the worker for this job's pcap
    alerts_res = await db.execute(
        select(Alert).where(Alert.pcap_id == job.pcap_id).order_by(Alert.triggered_at.asc())
    )
    alerts = alerts_res.scalars().all()
    alert_responses = [AlertResponse.model_validate(a) for a in alerts]

    # Pull the most recent AI assessment for this job
    assess_res = await db.execute(
        select(AiAssessment)
        .where(AiAssessment.job_id == job.id)
        .order_by(AiAssessment.created_at.desc())
        .limit(1)
    )
    assessment = assess_res.scalar_one_or_none()
    assessment_dict: dict[str, Any] | None = None
    if assessment is not None:
        assessment_dict = {
            "executive_summary": assessment.executive_summary,
            "key_findings": assessment.key_findings,
            "recommendations": assessment.recommendations,
            "model_name": assessment.model_name,
            "generation_time_ms": assessment.generation_time_ms,
        }

    return AnalysisResultResponse(
        job=JobStatusResponse.model_validate(job),
        pcap_id=job.pcap_id,
        alerts=alert_responses,
        ai_assessment=assessment_dict,
    )


@router.get("/by_pcap/{pcap_id}", response_model=list[JobStatusResponse])
async def list_jobs_for_pcap(
    pcap_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[JobStatusResponse]:
    """List all analysis jobs for a given PCAP file."""
    pcap_res = await db.execute(select(PcapFile.id).where(PcapFile.id == pcap_id))
    if pcap_res.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"PCAP {pcap_id} not found",
        )

    jobs_res = await db.execute(
        select(AnalysisJob)
        .where(AnalysisJob.pcap_id == pcap_id)
        .order_by(AnalysisJob.created_at.desc())
    )
    jobs = jobs_res.scalars().all()
    return [JobStatusResponse.model_validate(j) for j in jobs]
