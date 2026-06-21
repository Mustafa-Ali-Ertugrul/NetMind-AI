"""Tests for LiveAlertWriter — persisting findings to ``live_alerts``."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.contracts.enums import Confidence, Severity
from backend.contracts.findings import Evidence, Finding
from backend.storage.database import Base
from backend.storage.live_alert_writer import LiveAlertWriter
from backend.storage.models import LiveAlert


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def _make_finding(**overrides) -> Finding:
    """Helper to create a Finding with sensible defaults."""
    now = datetime.now(UTC)
    defaults = dict(
        pcap_id=uuid4(),
        rule_id="NET-001",
        rule_name="PortScanRule",
        rule_version="1.0.0",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        risk_score=42,
        title="Port scan detected",
        description="Multiple ports accessed from single source",
        recommendation="Investigate source IP",
        evidences=[
            Evidence(key="port_count", value=25, threshold=20, unit="ports"),
        ],
        affected_entities=["10.0.0.1"],
        timestamp_start=now,
        timestamp_end=now,
        raw_score=0.85,
        feature_snapshot={"port_count": 25.0},
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestLiveAlertWriter:
    def test_write_alert_inserts_row(self, db_session):
        writer = LiveAlertWriter(db_session)
        finding = _make_finding()
        result = writer.write_alert(finding)
        assert result.success is True
        assert result.count == 1
        row = db_session.query(LiveAlert).first()
        assert row is not None
        assert row.rule_id == "NET-001"

    def test_write_alerts_batch(self, db_session):
        writer = LiveAlertWriter(db_session)
        findings = [
            _make_finding(rule_id="NET-001"),
            _make_finding(rule_id="NET-002"),
            _make_finding(rule_id="NET-003"),
        ]
        result = writer.write_alerts(findings)
        assert result.success is True
        assert result.count == 3
        count = db_session.query(LiveAlert).count()
        assert count == 3

    def test_write_alert_persists_all_fields(self, db_session):
        writer = LiveAlertWriter(db_session)
        datetime.now(UTC)
        finding = _make_finding(
            rule_id="NET-005",
            severity=Severity.CRITICAL,
            confidence=Confidence.LOW,
            risk_score=95,
            title="Critical alert",
            description="Something bad happened",
            recommendation="Fix it now",
            affected_entities=["10.0.0.1", "10.0.0.2"],
            raw_score=0.99,
        )
        writer.write_alert(finding)
        row = db_session.query(LiveAlert).first()
        assert row.rule_id == "NET-005"
        assert row.severity == "critical"
        assert row.confidence == "low"
        assert row.risk_score == 95
        assert row.title == "Critical alert"
        assert row.description == "Something bad happened"
        assert row.recommendation == "Fix it now"
        assert "10.0.0.1" in row.affected_entities
        assert row.raw_score == 0.99
        assert row.status == "active"

    def test_severity_lowercased(self, db_session):
        writer = LiveAlertWriter(db_session)
        for sev in Severity:
            f = _make_finding(severity=sev)
            writer.write_alert(f)
        rows = db_session.query(LiveAlert).all()
        assert len(rows) == len(Severity)
        for row in rows:
            assert row.severity == row.severity.lower()

    def test_confidence_lowercased(self, db_session):
        writer = LiveAlertWriter(db_session)
        for conf in Confidence:
            f = _make_finding(confidence=conf)
            writer.write_alert(f)
        rows = db_session.query(LiveAlert).all()
        assert len(rows) == len(Confidence)
        for row in rows:
            assert row.confidence == row.confidence.lower()

    def test_evidence_transformed(self, db_session):
        writer = LiveAlertWriter(db_session)
        finding = _make_finding()
        writer.write_alert(finding)
        row = db_session.query(LiveAlert).first()
        assert row.evidence is not None
        assert row.evidence["rule_id"] == "NET-001"
        assert len(row.evidence["evidences"]) == 1
        ev = row.evidence["evidences"][0]
        assert ev["key"] == "port_count"
        assert ev["value"] == "25"

    def test_session_id_from_finding_pcap_id(self, db_session):
        writer = LiveAlertWriter(db_session)
        pcap_id = uuid4()
        finding = _make_finding(pcap_id=pcap_id)
        writer.write_alert(finding)
        row = db_session.query(LiveAlert).first()
        assert row.session_id == pcap_id

    def test_session_id_can_override(self, db_session):
        writer = LiveAlertWriter(db_session)
        pcap_id = uuid4()
        override_id = uuid4()
        finding = _make_finding(pcap_id=pcap_id)
        writer.write_alert(finding, session_id=override_id)
        row = db_session.query(LiveAlert).first()
        assert row.session_id == override_id
        assert row.session_id != pcap_id

    def test_empty_findings_no_insert(self, db_session):
        writer = LiveAlertWriter(db_session)
        result = writer.write_alerts([])
        assert result.success is True
        assert result.count == 0
        count = db_session.query(LiveAlert).count()
        assert count == 0

    def test_default_status_is_active(self, db_session):
        writer = LiveAlertWriter(db_session)
        writer.write_alert(_make_finding())
        row = db_session.query(LiveAlert).first()
        assert row.status == "active"

    def test_triggered_at_set(self, db_session):
        writer = LiveAlertWriter(db_session)
        writer.write_alert(_make_finding())
        row = db_session.query(LiveAlert).first()
        assert row.triggered_at is not None

    def test_feature_snapshot_stored(self, db_session):
        writer = LiveAlertWriter(db_session)
        snapshot = {"port_count": 25.0, "failed_ratio": 0.5}
        finding = _make_finding(feature_snapshot=snapshot)
        writer.write_alert(finding)
        row = db_session.query(LiveAlert).first()
        assert row.feature_snapshot == snapshot
