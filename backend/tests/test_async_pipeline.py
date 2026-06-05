"""Tests for the async pipeline (Sprint 5).

Covers:
    - Celery app configuration (broker, time limit, ack late)
    - analyze_pcap_task registered with the right name
    - alert_writer persistence semantics
    - assessment_writer persistence semantics
    - Task status transitions on success and failure
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.contracts.ai_output import AIAssessment
from backend.contracts.findings import Finding, OverallRiskScore
from backend.worker import celery_app
from backend.worker.tasks.pcap_analysis import analyze_pcap_task


# ---------------------------------------------------------------------------
# Celery app configuration
# ---------------------------------------------------------------------------


class TestCeleryApp:
    def test_app_name(self):
        assert celery_app.main == "netmind"

    def test_broker_set(self):
        assert "redis" in celery_app.conf.broker_url

    def test_result_backend_set(self):
        assert "redis" in celery_app.conf.result_backend

    def test_acks_late_enabled(self):
        assert celery_app.conf.task_acks_late is True

    def test_task_time_limit_set(self):
        assert celery_app.conf.task_time_limit > 0

    def test_soft_time_limit_set(self):
        assert celery_app.conf.task_soft_time_limit > 0

    def test_tracks_started_enabled(self):
        assert celery_app.conf.task_track_started is True

    def test_prefetch_multiplier_one(self):
        # Worker should pick up one task at a time for long-running PCAPs
        assert celery_app.conf.worker_prefetch_multiplier == 1

    def test_analyze_task_registered(self):
        # Task is registered with name "analyze_pcap"
        assert analyze_pcap_task.name == "analyze_pcap"
        assert "analyze_pcap" in celery_app.tasks

    def test_cleanup_task_registered(self):
        import backend.worker.tasks.storage_cleanup  # noqa: F401

        assert "cleanup_expired_pcaps" in celery_app.tasks

    def test_cleanup_beat_schedule_registered(self):
        schedule = celery_app.conf.beat_schedule
        assert "cleanup-expired-pcaps" in schedule
        assert schedule["cleanup-expired-pcaps"]["task"] == "cleanup_expired_pcaps"


# ---------------------------------------------------------------------------
# Test fixture: in-memory SQLite + sync engine for the task
# ---------------------------------------------------------------------------


@pytest.fixture
def sync_db_session(monkeypatch):
    """Build a fresh in-memory SQLite database with only the tables
    the worker pipeline actually touches.

    The worker task normally uses a real PostgreSQL engine. For unit
    tests, we swap the module-level sync engine for a SQLite one and
    create only the subset of tables that don't contain Postgres-only
    types (INET, JSONB).
    """
    from backend.storage import models as models_mod

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    models_mod.Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

    import backend.worker.tasks.pcap_analysis as task_mod

    monkeypatch.setattr(task_mod, "_SyncSessionLocal", SessionLocal)

    yield SessionLocal

    engine.dispose()


def _make_pcap_row(db, storage_key: str = "ab/" + "a" * 64 + ".pcap") -> tuple:
    """Insert a stub PcapFile + AnalysisJob and return their IDs."""
    from backend.storage.models import AnalysisJob, PcapFile

    pcap_id = uuid4()
    pcap = PcapFile(
        id=pcap_id,
        filename="abc.pcap",
        original_name="test.pcap",
        file_size=1024,
        sha256="a" * 64,
        storage_key=storage_key,
        status="uploaded",
        uploaded_at=datetime.utcnow(),
    )
    job_id = uuid4()
    job = AnalysisJob(
        id=job_id,
        pcap_id=pcap_id,
        status="queued",
        created_at=datetime.utcnow(),
    )
    db.add(pcap)
    db.add(job)
    db.commit()
    return pcap_id, job_id


def _make_finding(pcap_id):
    from backend.contracts.enums import Confidence, Severity

    return Finding(
        pcap_id=pcap_id,
        rule_id="NET-001",
        rule_name="PortScanRule",
        rule_version="1.0.0",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        risk_score=80,
        title="Port Scan",
        description="50 ports",
        recommendation="Block",
        timestamp_start=datetime.utcnow(),
        timestamp_end=datetime.utcnow(),
        raw_score=80.0,
    )


# ---------------------------------------------------------------------------
# Happy path: full pipeline with mocked parser/extractor/rules/assessor
# ---------------------------------------------------------------------------


class TestAnalyzeTaskHappyPath:
    def test_completes_when_all_stages_succeed(self, sync_db_session, tmp_path):
        from backend.storage.models import AiAssessment, Alert, AnalysisJob, PcapFile

        SessionLocal = sync_db_session

        # Pre-create a real file on disk so the storage_path check passes
        storage_dir = tmp_path / "ab"
        storage_dir.mkdir()
        target = storage_dir / ("a" * 64 + ".pcap")
        target.write_bytes(b"\xd4\xc3\xb2\xa1")  # pcap magic header

        with SessionLocal() as db:
            pcap_id, job_id = _make_pcap_row(db)

        # Mock the heavy stages
        mock_parser_inst = MagicMock()
        mock_parser_inst.parse_pcap.return_value = MagicMock(
            packets=[],
            dns_queries=[],
            http_requests=[],
            ftp_sessions=[],
            smtp_messages=[],
        )
        mock_extractor_inst = MagicMock()
        mock_extractor_inst.extract.return_value = MagicMock()

        from backend.contracts.enums import RiskLabel

        f = _make_finding(pcap_id)
        overall = OverallRiskScore(
            max_score=80,
            weighted_score=70,
            severity_label=RiskLabel.HIGH,
            total_findings=1,
            findings_by_severity={"high": 1},
            top_finding_ids=[f.id],
        )
        mock_engine_inst = MagicMock()
        mock_engine_inst.analyze.return_value = ([f], overall)

        assessment = AIAssessment(
            executive_summary="Test",
            finding_rationales=[],
            remediation_steps=[],
            provider="ollama",
            model="llama3.1:8b",
            generation_time_ms=120,
        )
        mock_assessor_inst = MagicMock()
        mock_assessor_inst.assess.return_value = assessment

        with (
            patch(
                "backend.worker.tasks.pcap_analysis.ProtocolParser", return_value=mock_parser_inst
            ),
            patch(
                "backend.worker.tasks.pcap_analysis.FeatureExtractor",
                return_value=mock_extractor_inst,
            ),
            patch("backend.worker.tasks.pcap_analysis.RuleEngine", return_value=mock_engine_inst),
            patch("backend.worker.tasks.pcap_analysis.AIAssessor", return_value=mock_assessor_inst),
            patch("backend.worker.tasks.pcap_analysis.get_settings") as mock_settings,
        ):
            mock_settings.return_value.upload_dir = tmp_path
            result = analyze_pcap_task.apply(args=[str(job_id)]).get()

        assert result["status"] == "completed"
        assert result["alerts_persisted"] == 1
        assert result["ai_assessment_persisted"] is True

        with SessionLocal() as db:
            job = db.get(AnalysisJob, job_id)
            pcap = db.get(PcapFile, pcap_id)
            assert job.status == "completed"
            assert pcap.status == "completed"

            alerts = db.query(Alert).filter(Alert.pcap_id == pcap_id).all()
            assert len(alerts) == 1
            assert alerts[0].rule_id == "NET-001"
            assert alerts[0].severity == "high"

            ai = db.query(AiAssessment).filter(AiAssessment.job_id == job_id).all()
            assert len(ai) == 1
            assert ai[0].executive_summary == "Test"
            assert ai[0].model_name == "llama3.1:8b"


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------


class TestAnalyzeTaskFailures:
    def test_tshark_error_marks_job_failed(self, sync_db_session, tmp_path):
        from backend.protocol_parser.tshark_wrapper import TsharkError
        from backend.storage.models import AnalysisJob, PcapFile

        SessionLocal = sync_db_session
        (tmp_path / "ab").mkdir()
        (tmp_path / "ab" / ("a" * 64 + ".pcap")).write_bytes(b"x")

        with SessionLocal() as db:
            pcap_id, job_id = _make_pcap_row(db)

        with (
            patch("backend.worker.tasks.pcap_analysis.ProtocolParser") as MockParser,
            patch("backend.worker.tasks.pcap_analysis.get_settings") as mock_settings,
        ):
            mock_settings.return_value.upload_dir = tmp_path
            MockParser.return_value.parse_pcap.side_effect = TsharkError("tshark not found")

            result = analyze_pcap_task.apply(args=[str(job_id)]).get()

        assert result["status"] == "failed"
        assert "tshark" in result["error"].lower()

        with SessionLocal() as db:
            job = db.get(AnalysisJob, job_id)
            pcap = db.get(PcapFile, pcap_id)
            assert job.status == "failed"
            assert "tshark" in job.error_message.lower()
            assert pcap.status == "failed"

    def test_file_missing_marks_job_failed(self, sync_db_session, tmp_path):
        from backend.storage.models import AnalysisJob, PcapFile

        SessionLocal = sync_db_session

        with SessionLocal() as db:
            pcap_id, job_id = _make_pcap_row(db, storage_key="no/such/file.pcap")

        with patch("backend.worker.tasks.pcap_analysis.get_settings") as mock_settings:
            mock_settings.return_value.upload_dir = tmp_path
            result = analyze_pcap_task.apply(args=[str(job_id)]).get()

        assert result["status"] == "failed"
        with SessionLocal() as db:
            job = db.get(AnalysisJob, job_id)
            assert job.status == "failed"
            assert (
                "missing" in job.error_message.lower() or "not found" in job.error_message.lower()
            )

    def test_unhandled_exception_marks_job_failed(self, sync_db_session, tmp_path):
        from backend.storage.models import AnalysisJob, PcapFile

        SessionLocal = sync_db_session
        (tmp_path / "ab").mkdir()
        (tmp_path / "ab" / ("a" * 64 + ".pcap")).write_bytes(b"x")

        with SessionLocal() as db:
            pcap_id, job_id = _make_pcap_row(db)

        with (
            patch("backend.worker.tasks.pcap_analysis.ProtocolParser") as MockParser,
            patch("backend.worker.tasks.pcap_analysis.get_settings") as mock_settings,
        ):
            mock_settings.return_value.upload_dir = tmp_path
            MockParser.return_value.parse_pcap.side_effect = RuntimeError("boom")

            result = analyze_pcap_task.apply(args=[str(job_id)]).get()

        assert result["status"] == "failed"
        with SessionLocal() as db:
            job = db.get(AnalysisJob, job_id)
            assert job.status == "failed"
            assert "RuntimeError" in job.error_message

    def test_unknown_job_id_returns_failure(self, sync_db_session):
        fake_id = str(uuid4())
        result = analyze_pcap_task.apply(args=[fake_id]).get()
        assert result["status"] == "failed"
        assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# alert_writer unit tests
# ---------------------------------------------------------------------------


class TestAlertWriter:
    def test_writes_one_alert_per_finding(self):
        from backend.contracts.enums import Confidence, Severity
        from backend.storage.alert_writer import write_alerts_from_findings
        from backend.storage.models import Alert, Base

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        pcap_id = uuid4()
        job_id = uuid4()

        f1 = Finding(
            pcap_id=pcap_id,
            rule_id="NET-001",
            rule_name="PortScanRule",
            rule_version="1.0.0",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            risk_score=70,
            title="Port Scan",
            description="50 ports from 10.0.0.5",
            recommendation="Block IP",
            affected_entities=["10.0.0.5"],
            timestamp_start=datetime.utcnow(),
            timestamp_end=datetime.utcnow(),
            raw_score=75.0,
        )
        f2 = Finding(
            pcap_id=pcap_id,
            rule_id="NET-002",
            rule_name="DNSTunnelingRule",
            rule_version="1.0.0",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            risk_score=90,
            title="DNS Tunneling",
            description="High entropy DNS",
            recommendation="Inspect domain",
            timestamp_start=datetime.utcnow(),
            timestamp_end=datetime.utcnow(),
            raw_score=95.0,
        )

        with SessionLocal() as db:
            n = write_alerts_from_findings(db, job_id=job_id, pcap_id=pcap_id, findings=[f1, f2])
            db.commit()
            assert n == 2

            rows = db.query(Alert).all()
            assert len(rows) == 2
            assert {r.rule_id for r in rows} == {"NET-001", "NET-002"}
            assert {r.severity for r in rows} == {"high", "critical"}

    def test_empty_findings_writes_zero_rows(self):
        from backend.storage.alert_writer import write_alerts_from_findings
        from backend.storage.models import Base

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)

        with SessionLocal() as db:
            n = write_alerts_from_findings(db, job_id=uuid4(), pcap_id=uuid4(), findings=[])
            assert n == 0

    def test_alert_evidence_serialized(self):
        from backend.contracts.enums import Confidence, Severity
        from backend.contracts.findings import Evidence
        from backend.storage.alert_writer import write_alerts_from_findings
        from backend.storage.models import Alert, Base

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)

        f = Finding(
            pcap_id=uuid4(),
            rule_id="NET-001",
            rule_name="PortScanRule",
            rule_version="1.0.0",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            risk_score=70,
            title="Port Scan",
            description="50 ports",
            recommendation="Block",
            evidences=[
                Evidence(key="unique_dst_ports", value=50, threshold="20", unit="ports"),
            ],
            timestamp_start=datetime.utcnow(),
            timestamp_end=datetime.utcnow(),
            raw_score=75.0,
        )

        with SessionLocal() as db:
            write_alerts_from_findings(db, job_id=uuid4(), pcap_id=uuid4(), findings=[f])
            db.commit()
            row = db.query(Alert).one()
            ev = row.evidence
            assert ev["rule_id"] == "NET-001"
            assert ev["risk_score"] == 70
            assert ev["evidences"][0]["key"] == "unique_dst_ports"


# ---------------------------------------------------------------------------
# assessment_writer unit tests
# ---------------------------------------------------------------------------


class TestAssessmentWriter:
    def test_writes_ai_assessment_row(self):
        from backend.contracts.ai_output import (
            AIAssessment,
            FindingRationale,
            RemediationStep,
        )
        from backend.storage.assessment_writer import write_ai_assessment
        from backend.storage.models import AiAssessment, Base

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        job_id = uuid4()
        pcap_id = uuid4()

        assessment = AIAssessment(
            executive_summary="Test summary",
            finding_rationales=[
                FindingRationale(
                    finding_id="abc",
                    explanation="Why",
                    confidence_qualifier="high",
                    false_positive_likelihood=0.2,
                )
            ],
            remediation_steps=[
                RemediationStep(
                    priority=1,
                    action="Block",
                    reason="Port scan",
                    reference="https://example.com",
                )
            ],
            provider="ollama",
            model="llama3.1:8b",
            generation_time_ms=120,
            fallback_used=False,
        )

        with SessionLocal() as db:
            row = write_ai_assessment(db, job_id=job_id, pcap_id=pcap_id, assessment=assessment)
            db.commit()
            assert row.id is not None
            assert row.executive_summary == "Test summary"
            assert row.model_name == "llama3.1:8b"
            assert row.generation_time_ms == 120

            fetched = db.get(AiAssessment, row.id)
            assert fetched.key_findings["rationales"][0]["finding_id"] == "abc"
            assert fetched.recommendations["steps"][0]["action"] == "Block"

    def test_fallback_assessment_persists(self):
        from backend.contracts.ai_output import AIAssessment
        from backend.storage.assessment_writer import write_ai_assessment
        from backend.storage.models import Base

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)

        assessment = AIAssessment(
            executive_summary="Fallback summary",
            finding_rationales=[],
            remediation_steps=[],
            provider="fallback",
            model="template",
            generation_time_ms=0,
            fallback_used=True,
        )

        with SessionLocal() as db:
            row = write_ai_assessment(db, job_id=uuid4(), pcap_id=uuid4(), assessment=assessment)
            db.commit()
            assert row.model_name == "template"
            assert "fallback_used=True" in row.raw_response


# ---------------------------------------------------------------------------
# storage lifecycle unit tests
# ---------------------------------------------------------------------------


class TestStorageLifecycle:
    def test_cleanup_expired_pcaps_deletes_file_and_soft_deletes_row(self, tmp_path):
        from backend.storage.lifecycle import cleanup_expired_pcaps
        from backend.storage.models import Base, PcapFile

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)

        artifact_dir = tmp_path / "ab"
        artifact_dir.mkdir()
        artifact = artifact_dir / ("a" * 64 + ".pcap")
        artifact.write_bytes(b"pcap")

        pcap_id = uuid4()
        with SessionLocal() as db:
            db.add(
                PcapFile(
                    id=pcap_id,
                    filename="abc.pcap",
                    original_name="test.pcap",
                    file_size=4,
                    sha256="a" * 64,
                    storage_key=f"ab/{artifact.name}",
                    status="completed",
                    uploaded_at=datetime.utcnow() - timedelta(days=10),
                    expires_at=datetime.utcnow() - timedelta(days=1),
                )
            )
            db.commit()

            summary = cleanup_expired_pcaps(db, tmp_path)

            row = db.get(PcapFile, pcap_id)
            assert summary["expired_found"] == 1
            assert summary["files_deleted"] == 1
            assert summary["rows_soft_deleted"] == 1
            assert artifact.exists() is False
            assert row.status == "deleted"
            assert row.deleted_at is not None

        engine.dispose()
