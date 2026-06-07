"""PCAP analysis Celery task.

Pipeline:
    1. parse   (tshark)  -> ParsedProtocols
    2. extract           -> AggregatedFeatures
    3. detect            -> Findings + OverallRiskScore
    4. assess            -> AIAssessment

All DB writes go through sync SQLAlchemy session (Celery workers
are sync, so the async asyncpg engine would deadlock under load).
"""

from __future__ import annotations

import logging
import traceback
from datetime import datetime
from pathlib import Path
from uuid import UUID

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from backend.ai_assessor import AIAssessor
from backend.ai_assessor.config import AssessorConfig
from backend.config import get_settings
from backend.feature_extractor.extractor import FeatureExtractor
from backend.protocol_parser.parser import ProtocolParser
from backend.protocol_parser.tshark_wrapper import TsharkError
from backend.rule_engine import RuleEngine
from backend.storage.alert_writer import write_alerts_from_findings
from backend.storage.assessment_writer import write_ai_assessment
from backend.storage.flow_writer import write_flows_from_features
from backend.storage.object_store import get_object_store
from backend.storage.models import AnalysisJob, PcapFile
from backend.worker import celery_app

logger = logging.getLogger("netmind.worker")


def _make_sync_session_factory() -> sessionmaker[Session]:
    """Create a sync SQLAlchemy session factory for the worker.

    The Celery worker uses sync I/O; calling asyncpg from inside
    a Celery task would block the event loop and deadlock under
    load. We translate the async DATABASE_URL to a sync one.
    """
    settings = get_settings()
    url = settings.database_url
    if url.startswith("postgresql+asyncpg://"):
        url = url.replace("postgresql+asyncpg://", "postgresql+psycopg2://", 1)
    elif url.startswith("postgresql://"):
        url = "postgresql+psycopg2://" + url[len("postgresql://") :]

    engine = create_engine(url, pool_pre_ping=True, future=True)
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


# Build the sync session factory once at import time
_SyncSessionLocal = _make_sync_session_factory()


def _to_status(status: str, pcap: PcapFile, job: AnalysisJob) -> None:
    """Persist the current status to both the job and the pcap file."""
    job.status = status
    job.started_at = job.started_at or datetime.utcnow()
    pcap.status = status


@celery_app.task(
    bind=True,
    name="analyze_pcap",
    acks_late=True,
    autoretry_for=(),
)
def analyze_pcap_task(self, job_id: str) -> dict:
    """Run the full PCAP analysis pipeline for a queued AnalysisJob.

    Args:
        job_id: UUID of the AnalysisJob row.

    Returns:
        A summary dict with the final job status and counts.
    """
    settings = get_settings()
    job_uuid = UUID(job_id)
    worker_id = self.request.id or "unknown"

    summary: dict = {
        "job_id": job_id,
        "status": "failed",
        "flows_persisted": 0,
        "alerts_persisted": 0,
        "ai_assessment_persisted": False,
        "error": None,
    }

    with _SyncSessionLocal() as db:
        try:
            job = db.execute(
                select(AnalysisJob).where(AnalysisJob.id == job_uuid)
            ).scalar_one_or_none()
            if job is None:
                logger.error("Job %s not found", job_id)
                summary["error"] = "job not found"
                return summary

            pcap = db.execute(
                select(PcapFile).where(PcapFile.id == job.pcap_id)
            ).scalar_one_or_none()
            if pcap is None:
                msg = f"PCAP {job.pcap_id} not found for job {job_id}"
                logger.error(msg)
                job.status = "failed"
                job.error_message = msg
                job.completed_at = datetime.utcnow()
                db.commit()
                summary["error"] = msg
                return summary

            job.worker_id = worker_id
            job.started_at = job.started_at or datetime.utcnow()

            # ----------------------------------------------------------------
            # 1. PARSE
            # ----------------------------------------------------------------
            _to_status("parsing", pcap, job)
            db.commit()

            object_store = get_object_store(settings)
            if not object_store.exists(pcap.storage_key):
                msg = f"PCAP object missing: {pcap.storage_key}"
                raise FileNotFoundError(msg)

            storage_path = object_store.get_as_path(pcap.storage_key)
            parser = ProtocolParser()
            parsed = parser.parse_pcap(storage_path, pcap.id)
            pcap.packet_count = len(parsed.packets)
            pcap.bytes_total = sum(p.length for p in parsed.packets)
            if parsed.packets:
                pcap.start_time = min(p.timestamp for p in parsed.packets if p.timestamp)
                pcap.end_time = max(p.timestamp for p in parsed.packets if p.timestamp)
                if pcap.end_time and pcap.start_time:
                    pcap.duration_seconds = (pcap.end_time - pcap.start_time).total_seconds()
            db.commit()

            # ----------------------------------------------------------------
            # 2. EXTRACT
            # ----------------------------------------------------------------
            _to_status("extracting", pcap, job)
            db.commit()

            extractor = FeatureExtractor()
            features = extractor.extract(parsed)
            flows_written = write_flows_from_features(db, pcap_id=pcap.id, features=features)
            summary["flows_persisted"] = flows_written
            db.commit()

            # ----------------------------------------------------------------
            # 3. DETECT
            # ----------------------------------------------------------------
            _to_status("detecting", pcap, job)
            db.commit()

            engine = RuleEngine()
            findings, overall = engine.analyze(features)
            alerts_written = write_alerts_from_findings(
                db, job_id=job.id, pcap_id=pcap.id, findings=findings
            )
            db.commit()
            summary["alerts_persisted"] = alerts_written

            # Track per-rule failures in the error_message field
            if overall.failed_rules:
                logger.warning(
                    "Job %s completed with %d failed rule(s): %s",
                    job_id,
                    len(overall.failed_rules),
                    overall.failed_rules,
                )

            # ----------------------------------------------------------------
            # 4. ASSESS
            # ----------------------------------------------------------------
            _to_status("assessing", pcap, job)
            db.commit()

            assessor = AIAssessor(config=AssessorConfig())
            assessment = assessor.assess(findings, overall)
            job.model_used = assessment.model
            write_ai_assessment(
                db,
                job_id=job.id,
                pcap_id=pcap.id,
                assessment=assessment,
            )
            db.commit()
            summary["ai_assessment_persisted"] = True

            # ----------------------------------------------------------------
            # DONE
            # ----------------------------------------------------------------
            job.status = "completed"
            job.completed_at = datetime.utcnow()
            pcap.status = "completed"
            db.commit()
            summary["status"] = "completed"
            logger.info(
                "Job %s completed: %d alerts, ai_used=%s",
                job_id,
                alerts_written,
                not assessment.fallback_used,
            )
            return summary

        except TsharkError as exc:
            logger.exception("Tshark error in job %s", job_id)
            _mark_failed(db, job, pcap, summary, f"tshark: {exc}")
        except FileNotFoundError as exc:
            logger.exception("File missing for job %s", job_id)
            _mark_failed(db, job, pcap, summary, str(exc))
        except Exception as exc:
            logger.exception("Unhandled error in job %s", job_id)
            _mark_failed(db, job, pcap, summary, f"{type(exc).__name__}: {exc}")
            summary["traceback"] = traceback.format_exc()

    return summary


def _mark_failed(
    db: Session,
    job: AnalysisJob,
    pcap: PcapFile,
    summary: dict,
    error: str,
) -> None:
    """Persist a failed status to both the job and pcap rows."""
    try:
        job.status = "failed"
        job.error_message = error[:2000]  # cap to fit TEXT column comfortably
        job.completed_at = datetime.utcnow()
        pcap.status = "failed"
        pcap.error_message = error[:2000]
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to persist failure status for job %s", job.id)
    summary["status"] = "failed"
    summary["error"] = error


def write_pcap_to_disk(content: bytes, storage_key: str) -> Path:
    """Write a PCAP file to its content-addressable path.

    Used by the upload handler before the AnalysisJob is enqueued.
    The directory structure is ``{upload_dir}/{sha256[:2]}/{sha256}{suffix}``,
    so different suffixes of the same SHA-256 do not collide.
    """
    settings = get_settings()
    target = settings.upload_dir / storage_key
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return target
