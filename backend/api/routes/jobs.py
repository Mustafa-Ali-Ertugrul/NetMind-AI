"""Job polling endpoints (Phase 5).

Provides the polling endpoint for frontend progress and a result
endpoint that returns the full analysis bundle (findings + AI).
"""

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_db_session
from backend.api.schemas import (
    AlertResponse,
    AnalysisResultResponse,
    JobStatusResponse,
    OverallRiskResponse,
)
from backend.config import get_settings
from backend.storage.models import AiAssessment, Alert, AnalysisJob, PcapFile

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("", response_model=list[JobStatusResponse])
async def list_jobs(
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db_session),
) -> list[JobStatusResponse]:
    """List recent analysis jobs ordered by creation time."""
    result = await db.execute(
        select(AnalysisJob).order_by(AnalysisJob.created_at.desc()).limit(limit)
    )
    jobs = result.scalars().all()
    return [JobStatusResponse.model_validate(j) for j in jobs]


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
        overall_risk=OverallRiskResponse(
            score=assessment.risk_score or 0,
            label=assessment.risk_label,
        )
        if assessment
        else None,
    )


@router.get("/{job_id}/talkers")
async def get_job_talkers(
    job_id: UUID,
    limit: int = Query(10, ge=1, le=100),
    db: AsyncSession = Depends(get_db_session),
):
    """Return top talkers for a job's PCAP."""
    from backend.analytics.aggregators.talkers import TopTalkerAggregator

    job_res = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_id))
    job = job_res.scalar_one_or_none()
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found",
        )
    aggregator = TopTalkerAggregator()
    result = aggregator.aggregate(db, pcap_id=job.pcap_id, limit=limit)
    return result.model_dump(mode="json")


@router.get("/{job_id}/report")
async def download_job_report(
    job_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """Return a downloadable JSON analysis report for a completed job."""
    result = await get_job_result(job_id, db)
    payload = result.model_dump(mode="json")
    payload["generated_at"] = datetime.utcnow().isoformat() + "Z"
    payload["report_version"] = "1.0"
    return JSONResponse(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="netmind-report-{job_id}.json"'},
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


@router.get("/{job_id}/artifacts")
async def list_job_artifacts(
    job_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[dict]:
    """List downloadable artifact files for a given job.

    Returns artifact metadata (filename, type, size, created_at).
    Actual file download is handled by the dedicated artifact download handler.
    """
    from backend.storage.service import StorageService
    from backend.storage.schemas import ArtifactInfo

    svc = StorageService(db=db, settings=get_settings())
    artifacts = await svc.list_artifacts(job_id)
    return [ArtifactInfo.model_validate(a).model_dump(mode="json") for a in artifacts]


@router.get("/{job_id}/artifacts/{filename}")
async def download_job_artifact(
    job_id: UUID,
    filename: str,
    db: AsyncSession = Depends(get_db_session),
):
    """Download a specific artifact file for a job."""
    from fastapi.responses import FileResponse
    from backend.storage.service import StorageService
    from backend.storage.exceptions import ArtifactNotFoundError

    svc = StorageService(db=db, settings=get_settings())
    try:
        target = await svc.get_artifact_path(job_id, filename)
    except ArtifactNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    # Infer media type
    media_type = "application/octet-stream"
    if filename.endswith(".json"):
        media_type = "application/json"
    elif filename.endswith(".log"):
        media_type = "text/plain"

    return FileResponse(path=target, filename=filename, media_type=media_type)
