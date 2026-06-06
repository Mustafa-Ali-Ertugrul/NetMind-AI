"""PCAP upload and management endpoints (Phase 5).

Upload flow:
    1. Validate extension + size + magic bytes
    2. SHA-256 dedup: if a PcapFile with this hash already exists,
       return 200 with deduplicated=True and the existing job_id
    3. Persist the file to disk under upload_dir/{storage_key}
    4. Insert PcapFile row (status="uploaded")
    5. Insert AnalysisJob row (status="queued")
    6. Enqueue Celery task analyze_pcap_task.delay(job_id)

Rate limited to 10 requests/minute per IP.
"""

from backend.api.rate_limit import limiter

import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_db_session
from backend.api.schemas import (
    JobSummary,
    PcapDetailResponse,
    UploadResponse,
)
from backend.config import get_settings
from backend.storage.models import AnalysisJob, PcapFile

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/pcaps", tags=["pcaps"])


@router.post(
    "",
    response_model=UploadResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit("10/minute")
async def upload_pcap(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db_session),
) -> UploadResponse:
    """Upload a PCAP/PCAPNG file. Enqueues an async analysis job."""
    settings = get_settings()

    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is required",
        )

    suffix = Path(file.filename).suffix.lower()
    if suffix not in settings.upload_allowed_extensions:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Unsupported file type: {suffix}. "
            f"Allowed: {settings.upload_allowed_extensions}",
        )

    content = await file.read()

    # Magic bytes validation: PCAP = d4c3b2a1 / a1b2c3d4, PCAPNG = 0a0d0d0a
    if len(content) >= 4:
        header = content[:4]
        pcap_magic = any(
            header == m for m in [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"]
        )
        if not pcap_magic:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="File does not appear to be a valid PCAP/PCAPNG (invalid magic bytes)",
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="File is too small to be a valid PCAP/PCAPNG",
        )

    if len(content) > settings.upload_max_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum size of {settings.upload_max_size_mb} MB",
        )

    sha256 = hashlib.sha256(content).hexdigest()

    # Dedup: return the existing row + its latest job if already uploaded
    existing_res = await db.execute(select(PcapFile).where(PcapFile.sha256 == sha256))
    existing = existing_res.scalar_one_or_none()
    if existing is not None:
        latest_job_res = await db.execute(
            select(AnalysisJob)
            .where(AnalysisJob.pcap_id == existing.id)
            .order_by(AnalysisJob.created_at.desc())
            .limit(1)
        )
        latest_job = latest_job_res.scalar_one_or_none()
        logger.info(
            "Deduplicated upload: pcap %s already exists (sha256=%s)",
            existing.id,
            sha256[:12],
        )
        return UploadResponse(
            id=existing.id,
            filename=existing.filename,
            original_name=existing.original_name,
            file_size=existing.file_size,
            sha256=existing.sha256,
            status=existing.status,
            job_id=latest_job.id if latest_job else None,
            deduplicated=True,
            uploaded_at=existing.uploaded_at,
            last_accessed_at=existing.last_accessed_at,
            expires_at=existing.expires_at,
            deleted_at=existing.deleted_at,
        )

    # Persist to disk
    storage_key = f"{sha256[:2]}/{sha256}{suffix}"
    target = settings.upload_dir / storage_key
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    except OSError as exc:
        logger.exception("Failed to write PCAP to disk: %s", target)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to persist upload: {exc}",
        ) from exc

    # Insert PcapFile + AnalysisJob atomically
    pcap = PcapFile(
        id=uuid4(),
        filename=sha256 + suffix,
        original_name=file.filename,
        file_size=len(content),
        mime_type=file.content_type,
        sha256=sha256,
        storage_key=storage_key,
        status="uploaded",
        uploaded_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=settings.storage_retention_days),
    )
    db.add(pcap)
    await db.flush()  # populate pcap.id

    job = AnalysisJob(
        id=uuid4(),
        pcap_id=pcap.id,
        status="queued",
        model_used="llama3.1:8b",
        created_at=datetime.utcnow(),
    )
    db.add(job)
    await db.commit()
    await db.refresh(pcap)
    await db.refresh(job)

    # Enqueue Celery task. Imported lazily so the API process doesn't
    # need Celery at import time when only running unit tests.
    try:
        from backend.worker.tasks.pcap_analysis import analyze_pcap_task

        analyze_pcap_task.delay(str(job.id))
    except Exception as exc:
        # Broker may be down in test envs. Mark the job as failed but
        # leave the PcapFile in 'uploaded' so a retry endpoint can re-enqueue.
        logger.exception("Failed to enqueue Celery task for job %s", job.id)
        job.status = "failed"
        job.error_message = f"queue enqueue failed: {exc}"
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(f"Uploaded but could not enqueue analysis job. Reason: {exc}"),
        ) from exc

    logger.info(
        "Uploaded pcap %s (sha256=%s, size=%d bytes), enqueued job %s",
        pcap.id,
        sha256[:12],
        len(content),
        job.id,
    )

    return UploadResponse(
        id=pcap.id,
        filename=pcap.filename,
        original_name=pcap.original_name,
        file_size=pcap.file_size,
        sha256=pcap.sha256,
        status=pcap.status,
        job_id=job.id,
        deduplicated=False,
        uploaded_at=pcap.uploaded_at,
        last_accessed_at=pcap.last_accessed_at,
        expires_at=pcap.expires_at,
        deleted_at=pcap.deleted_at,
    )


@router.get("/{pcap_id}/download")
async def download_pcap(
    pcap_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> FileResponse:
    """Download the stored PCAP/PCAPNG artifact for a PCAP row."""
    settings = get_settings()
    pcap_res = await db.execute(select(PcapFile).where(PcapFile.id == pcap_id))
    pcap = pcap_res.scalar_one_or_none()
    if pcap is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"PCAP {pcap_id} not found",
        )
    if pcap.status == "deleted" or pcap.deleted_at is not None:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=f"PCAP {pcap_id} has been deleted by retention policy",
        )

    target = settings.upload_dir / pcap.storage_key
    if not target.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"PCAP file is missing on disk: {pcap.storage_key}",
        )

    pcap.last_accessed_at = datetime.utcnow()
    await db.commit()

    return FileResponse(
        path=target,
        filename=pcap.original_name,
        media_type=pcap.mime_type or "application/vnd.tcpdump.pcap",
    )


@router.get("/{pcap_id}", response_model=PcapDetailResponse)
async def get_pcap(
    pcap_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> PcapDetailResponse:
    """Return the PcapFile metadata + a summary of its analysis jobs."""
    pcap_res = await db.execute(select(PcapFile).where(PcapFile.id == pcap_id))
    pcap = pcap_res.scalar_one_or_none()
    if pcap is None:
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

    return PcapDetailResponse(
        id=pcap.id,
        filename=pcap.filename,
        original_name=pcap.original_name,
        file_size=pcap.file_size,
        sha256=pcap.sha256,
        storage_key=pcap.storage_key,
        status=pcap.status,
        duration_seconds=pcap.duration_seconds,
        packet_count=pcap.packet_count,
        bytes_total=pcap.bytes_total,
        start_time=pcap.start_time,
        end_time=pcap.end_time,
        uploaded_at=pcap.uploaded_at,
        last_accessed_at=pcap.last_accessed_at,
        expires_at=pcap.expires_at,
        deleted_at=pcap.deleted_at,
        error_message=pcap.error_message,
        analysis_jobs=[JobSummary.model_validate(j) for j in jobs],
    )


@router.delete("/{pcap_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_pcap(
    pcap_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> None:
    """Soft-delete a PCAP record and remove its file from disk."""
    from backend.storage.service import StorageService

    svc = StorageService(db=db, settings=get_settings())
    await svc.delete_pcap(pcap_id)
