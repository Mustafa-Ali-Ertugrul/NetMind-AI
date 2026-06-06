"""StorageService: orchestration for PCAP and artifact lifecycle.

Provides a single entry point for the API layer, combining disk I/O,
database operations, and lifecycle policies.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import Settings
from backend.storage.disk_monitor import DiskMonitor
from backend.storage.exceptions import (
    ArtifactNotFoundError,
    DiskFullError,
    PcapNotFoundError,
)
from backend.storage.models import AiAssessment, Alert, AnalysisJob, PcapFile
from backend.storage.schemas import (
    ArtifactInfo,
    CleanupResult,
    DiskStatus,
    StorageStatus,
)

logger = logging.getLogger(__name__)


class StorageService:
    """High-level storage operations for PCAPs and analysis artifacts."""

    def __init__(self, db: AsyncSession, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.pcap_dir = settings.upload_dir
        self.artifact_dir = settings.artifact_storage_path
        self.disk_monitor = DiskMonitor(
            path=self.pcap_dir,
            threshold_pct=settings.disk_usage_threshold_pct,
        )

    # ── PCAP operations ──────────────────────────────────────────────

    async def get_pcap(self, pcap_id: UUID) -> PcapFile:
        """Return the PcapFile ORM row or raise PcapNotFoundError."""
        result = await self.db.execute(select(PcapFile).where(PcapFile.id == pcap_id))
        pcap = result.scalar_one_or_none()
        if pcap is None:
            raise PcapNotFoundError(f"PCAP {pcap_id} not found")
        return pcap

    async def get_pcap_path(self, pcap_id: UUID) -> Path:
        """Resolve the on-disk path for a PCAP, raising if missing."""
        pcap = await self.get_pcap(pcap_id)
        target = self.pcap_dir / pcap.storage_key
        if not target.exists():
            raise PcapNotFoundError(f"PCAP {pcap_id} file is missing on disk: {pcap.storage_key}")
        return target

    async def delete_pcap(self, pcap_id: UUID) -> None:
        """Soft-delete a PCAP row and remove its file from disk.

        Raises PcapNotFoundError if the record does not exist.
        The cascading relationship deletes analysis_jobs, alerts,
        and ai_assessments from the DB.
        """
        pcap = await self.get_pcap(pcap_id)

        # Remove from disk
        target = self.pcap_dir / pcap.storage_key
        if target.exists():
            try:
                target.unlink()
            except OSError as exc:
                logger.warning("Failed to delete PCAP file %s: %s", target, exc)

        # Check for artifact dir and clean it
        for job in pcap.analysis_jobs:
            self._remove_artifact_dir(job.id)

        # Soft-delete the DB row
        pcap.status = "deleted"
        pcap.deleted_at = datetime.utcnow()
        await self.db.commit()

        logger.info(
            "Deleted PCAP %s (sha256=%s, file=%s)",
            pcap_id,
            pcap.sha256[:12],
            pcap.storage_key,
        )

    async def touch_pcap(self, pcap_id: UUID) -> None:
        """Update last_accessed_at for a PCAP record."""
        pcap = await self.get_pcap(pcap_id)
        pcap.last_accessed_at = datetime.utcnow()
        await self.db.commit()

    async def count_pcaps(self) -> int:
        """Return the total number of PCAP records (excluding soft-deleted)."""
        result = await self.db.execute(
            select(func.count(PcapFile.id)).where(PcapFile.deleted_at.is_(None))
        )
        return result.scalar() or 0

    async def total_pcap_bytes(self) -> int:
        """Sum of file sizes for all non-deleted PCAP records."""
        result = await self.db.execute(
            select(func.coalesce(func.sum(PcapFile.file_size), 0)).where(
                PcapFile.deleted_at.is_(None)
            )
        )
        return result.scalar() or 0

    async def count_expired_pcaps(self) -> int:
        """Count PCAPs whose expires_at has passed (not yet cleaned up)."""
        now = datetime.utcnow()
        result = await self.db.execute(
            select(func.count(PcapFile.id))
            .where(PcapFile.deleted_at.is_(None))
            .where(PcapFile.expires_at.is_not(None))
            .where(PcapFile.expires_at <= now)
        )
        return result.scalar() or 0

    # ── Artifact operations ──────────────────────────────────────────

    async def list_artifacts(self, job_id: UUID) -> list[ArtifactInfo]:
        """List all on-disk artifacts for a given job."""
        # Verify the job exists
        job_res = await self.db.execute(select(AnalysisJob).where(AnalysisJob.id == job_id))
        job = job_res.scalar_one_or_none()
        if job is None:
            raise ArtifactNotFoundError(f"Job {job_id} not found")

        artifact_dir = self._artifact_path(job_id)
        if not artifact_dir.exists():
            return []

        pcap_res = await self.db.execute(select(PcapFile.id).where(PcapFile.id == job.pcap_id))
        pcap_id = pcap_res.scalar_one_or_none()

        artifacts: list[ArtifactInfo] = []
        for fpath in sorted(artifact_dir.iterdir()):
            if fpath.is_file():
                stat = fpath.stat()
                artifacts.append(
                    ArtifactInfo(
                        job_id=job_id,
                        pcap_id=pcap_id or job.pcap_id,
                        artifact_type=self._infer_artifact_type(fpath),
                        filename=fpath.name,
                        file_size=stat.st_size,
                        created_at=datetime.fromtimestamp(stat.st_mtime),
                    )
                )
        return artifacts

    async def get_artifact_path(self, job_id: UUID, filename: str) -> Path:
        """Resolve the path for a specific job artifact file.

        Prevents path traversal by verifying the resolved path
        stays within the artifact directory.
        """
        base = self._artifact_path(job_id).resolve()
        target = (base / filename).resolve()
        try:
            target.relative_to(base)
        except ValueError:
            raise ArtifactNotFoundError(f"Invalid artifact path: {filename}")
        if not target.exists() or not target.is_file():
            raise ArtifactNotFoundError(f"Artifact {filename} not found for job {job_id}")
        return target

    async def write_artifact(self, job_id: UUID, filename: str, content: str | bytes) -> Path:
        """Write an artifact (e.g. JSON result, analysis log) to disk."""
        artifact_dir = self._artifact_path(job_id)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        target = artifact_dir / filename
        if isinstance(content, str):
            target.write_text(content, encoding="utf-8")
        else:
            target.write_bytes(content)
        logger.debug("Wrote artifact %s for job %s", filename, job_id)
        return target

    async def count_artifacts(self) -> int:
        """Count artifact files across all job directories."""
        count = 0
        if not self.artifact_dir.exists():
            return 0
        for job_dir in self.artifact_dir.iterdir():
            if job_dir.is_dir():
                count += sum(1 for _ in job_dir.iterdir())
        return count

    async def count_orphan_artifacts(self) -> int:
        """Count artifact dirs whose corresponding job no longer exists."""
        if not self.artifact_dir.exists():
            return 0
        orphan_count = 0
        for job_dir in self.artifact_dir.iterdir():
            if not job_dir.is_dir():
                continue
            try:
                job_uuid = UUID(job_dir.name)
            except ValueError:
                orphan_count += 1
                continue
            result = await self.db.execute(select(AnalysisJob.id).where(AnalysisJob.id == job_uuid))
            if result.scalar_one_or_none() is None:
                orphan_count += 1
        return orphan_count

    # ── Storage status ───────────────────────────────────────────────

    async def get_storage_status(self) -> StorageStatus:
        """Aggregate storage health and usage info."""
        disk_data = self.disk_monitor.get_usage()

        return StorageStatus(
            disk=DiskStatus(**disk_data),
            pcap_count=await self.count_pcaps(),
            pcap_total_bytes=await self.total_pcap_bytes(),
            artifact_count=await self.count_artifacts(),
            expired_pcaps=await self.count_expired_pcaps(),
            orphan_artifacts=await self.count_orphan_artifacts(),
        )

    async def check_disk_before_upload(self, required_bytes: int) -> None:
        """Raise DiskFullError if disk cannot accommodate the upload."""
        if self.disk_monitor.is_over_threshold():
            logger.warning(
                "Disk usage above threshold (%d%%); rejecting upload of %d bytes",
                self.disk_monitor.threshold_pct,
                required_bytes,
            )
            raise DiskFullError(
                f"Disk usage exceeds {self.disk_monitor.threshold_pct}% threshold. "
                "Clean up old files before uploading."
            )
        if self.disk_monitor.available_bytes < required_bytes:
            raise DiskFullError(
                f"Only {self.disk_monitor.available_bytes / (1024**2):.1f} MB "
                f"available, need {required_bytes / (1024**2):.1f} MB"
            )

    # ── Cleanup ──────────────────────────────────────────────────────

    async def run_cleanup(self) -> CleanupResult:
        """Run all lifecycle cleanup policies.

        1. Soft-delete expired PCAPs and remove their files.
        2. Remove orphan artifact directories.
        """
        now = datetime.utcnow()
        result = CleanupResult()

        # Expired PCAPs
        expired_res = await self.db.execute(
            select(PcapFile)
            .where(PcapFile.deleted_at.is_(None))
            .where(PcapFile.expires_at.is_not(None))
            .where(PcapFile.expires_at <= now)
        )
        expired = expired_res.scalars().all()
        result.expired_pcaps_found = len(expired)

        for pcap in expired:
            target = self.pcap_dir / pcap.storage_key
            try:
                if target.exists():
                    target.unlink()
                    result.files_deleted += 1

                pcap.status = "deleted"
                pcap.deleted_at = now
                result.rows_soft_deleted += 1
            except OSError as exc:
                msg = f"PCAP {pcap.id}: {exc}"
                logger.warning(msg)
                result.errors.append(msg)

        await self.db.commit()

        # Orphan artifact dirs
        if self.artifact_dir.exists():
            for job_dir in self.artifact_dir.iterdir():
                if not job_dir.is_dir():
                    continue
                try:
                    job_uuid = UUID(job_dir.name)
                except ValueError:
                    continue
                jr = await self.db.execute(select(AnalysisJob.id).where(AnalysisJob.id == job_uuid))
                if jr.scalar_one_or_none() is None:
                    self._remove_artifact_dir(job_uuid, as_path=job_dir)
                    result.artifacts_deleted += 1

        return result

    # ── Internals ────────────────────────────────────────────────────

    def _artifact_path(self, job_id: UUID) -> Path:
        return self.artifact_dir / str(job_id)

    @staticmethod
    def _infer_artifact_type(path: Path) -> str:
        name = path.name
        if name == "result.json":
            return "result_json"
        if name == "analysis.log":
            return "log"
        return "other"

    def _remove_artifact_dir(self, job_id: UUID, as_path: Path | None = None) -> None:
        target = as_path or self._artifact_path(job_id)
        if target.exists():
            import shutil

            try:
                shutil.rmtree(target)
                logger.debug("Removed artifact dir %s", target)
            except OSError as exc:
                logger.warning("Failed to remove artifact dir %s: %s", target, exc)
