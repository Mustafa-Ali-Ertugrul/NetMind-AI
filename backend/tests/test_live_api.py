"""Tests for /api/v1/live/ endpoints.

Ingest endpoint: uses a real FastAPI test client with a mocked
LiveEngineService on app.state.

Read endpoints (alerts, timeline, stats): mock the DB dependency
via the conftest_api fixtures.

Metrics endpoint: uses mocked LiveEngineService on app.state.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from backend.api.app import create_app
from backend.api.dependencies import get_db_session
from backend.live_engine.service import LiveEngineService, ServiceMetrics
from backend.storage.models import LiveAlert

# ── Helpers ─────────────────────────────────────────────────────────────


@pytest.fixture(name="app")
def _app() -> FastAPI:
    """Return a bare-minimum FastAPI app (lifespan NOT started)."""
    return create_app()


@pytest.fixture(name="mock_db")
def _mock_db():
    """Return a mock DB session."""
    from unittest.mock import AsyncMock

    return AsyncMock()


@pytest.fixture(name="mock_svc")
def _mock_service() -> MagicMock:
    """Return a fully-mocked LiveEngineService."""
    svc = MagicMock(spec=LiveEngineService)
    svc.metrics.return_value = ServiceMetrics(
        queue_size=0,
        events_enqueued=100,
        events_dropped=0,
        events_processed=95,
        batches_processed=10,
        alerts_generated=5,
        active_sessions=1,
        uptime_seconds=42.0,
    )
    return svc


@pytest.fixture(name="client")
async def _client(app: FastAPI, mock_db, mock_svc) -> AsyncClient:
    """Return an async test client with overridden dependencies."""
    app.state.live_service = mock_svc
    # Override DB dependency for read endpoints
    app.dependency_overrides[get_db_session] = lambda: mock_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


# ── Tests: POST /live/ingest ────────────────────────────────────────────


class TestIngestEndpoint:
    async def test_ingest_202_with_minimal_event(self, client: AsyncClient, mock_svc):
        """POST valid minimal event -> 202."""
        mock_svc.ingest.return_value = MagicMock(
            queued=True,
            session_id=uuid4(),
            stream_qsize=3,
        )
        payload = {
            "src_ip": "10.0.0.5",
            "dst_ip": "8.8.8.8",
            "src_port": 51515,
            "dst_port": 443,
            "protocol": "TCP",
        }
        resp = await client.post("/api/v1/live/ingest", json=payload)
        assert resp.status_code == 202
        body = resp.json()
        assert body["queued"] is True
        # session_id should be a valid UUID
        UUID(body["session_id"])

    async def test_ingest_202_with_full_event(self, client: AsyncClient, mock_svc):
        """POST with all fields -> 202."""
        mock_svc.ingest.return_value = MagicMock(
            queued=True,
            session_id=uuid4(),
            stream_qsize=0,
        )
        payload = {
            "src_ip": "10.0.0.5",
            "dst_ip": "8.8.8.8",
            "src_port": 51515,
            "dst_port": 443,
            "protocol": "TCP",
            "bytes": 1500,
            "packets": 12,
            "flags": "SYN",
            "http_method": "GET",
            "http_uri": "/index.html",
            "http_host": "example.com",
            "http_status": 200,
            "http_user_agent": "curl/7.68",
            "dns_qname": "example.com",
            "dns_qtype": "A",
            "session_id": str(uuid4()),
            "collector_id": "test-collector-1",
        }
        resp = await client.post("/api/v1/live/ingest", json=payload)
        assert resp.status_code == 202

    async def test_ingest_400_on_invalid_ip(self, client: AsyncClient, mock_svc):
        """Invalid src_ip -> 400."""
        payload = {
            "src_ip": "not_an_ip",
            "dst_ip": "8.8.8.8",
            "src_port": 51515,
            "dst_port": 443,
            "protocol": "TCP",
        }
        resp = await client.post("/api/v1/live/ingest", json=payload)
        assert resp.status_code == 400

    async def test_ingest_400_on_invalid_session_id(self, client: AsyncClient, mock_svc):
        """Invalid session_id string -> 400 (not silently auto-generated)."""
        payload = {
            "src_ip": "10.0.0.5",
            "dst_ip": "8.8.8.8",
            "src_port": 51515,
            "dst_port": 443,
            "protocol": "TCP",
            "session_id": "not-a-uuid",
        }
        resp = await client.post("/api/v1/live/ingest", json=payload)
        assert resp.status_code == 400
        assert "session_id" in resp.json()["detail"].lower()

    async def test_ingest_503_when_service_not_started(self, app: FastAPI):
        """Without live_service on app.state -> 503."""
        # Clear app.state.live_service (simulate lifespan not started)
        if hasattr(app.state, "live_service"):
            del app.state.live_service

        # Need a new client without the mock_svc override
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            payload = {
                "src_ip": "10.0.0.5",
                "dst_ip": "8.8.8.8",
                "src_port": 51515,
                "dst_port": 443,
                "protocol": "TCP",
            }
            resp = await ac.post("/api/v1/live/ingest", json=payload)
            assert resp.status_code == 503


# ── Tests: GET /live/alerts ────────────────────────────────────────────


class TestAlertsEndpoint:
    async def test_alerts_returns_empty_list(self, client: AsyncClient, mock_db):
        """No alerts in DB -> empty response."""
        mock_res = MagicMock()
        mock_res.scalar.return_value = 0
        mock_res.scalars.return_value.all.return_value = []
        mock_db.execute.return_value = mock_res

        resp = await client.get("/api/v1/live/alerts")
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["total"] == 0

    async def test_alerts_returns_rows(self, client: AsyncClient, mock_db):
        """Alerts exist -> paginated response."""
        alert_id = uuid4()
        mock_alert = MagicMock(spec=LiveAlert)
        mock_alert.id = alert_id
        mock_alert.session_id = uuid4()
        mock_alert.rule_id = "NET-001"
        mock_alert.severity = "high"
        mock_alert.confidence = "high"
        mock_alert.risk_score = 75
        mock_alert.title = "Test alert"
        mock_alert.description = None
        mock_alert.recommendation = None
        mock_alert.affected_entities = []
        mock_alert.evidence = {}
        mock_alert.feature_snapshot = {}
        mock_alert.timestamp_start = datetime.utcnow()
        mock_alert.timestamp_end = datetime.utcnow()
        mock_alert.triggered_at = datetime.utcnow()
        mock_alert.status = "active"

        # Mock two separate execute calls: one for count, one for rows
        mock_db.execute.side_effect = [
            MagicMock(scalar=lambda: 1),  # count
            MagicMock(scalars=lambda: MagicMock(all=lambda: [mock_alert])),  # rows
        ]

        resp = await client.get("/api/v1/live/alerts?status=active&limit=10")
        assert resp.status_code == 200

    async def test_alerts_filter_by_status_and_severity(self, client: AsyncClient, mock_db):
        """Filters are passed to the DB query."""
        mock_db.execute.side_effect = [
            MagicMock(scalar=lambda: 0),
            MagicMock(scalars=lambda: MagicMock(all=lambda: [])),
        ]
        resp = await client.get("/api/v1/live/alerts?status=active&severity=high&limit=5&offset=10")
        assert resp.status_code == 200


# ── Tests: GET /live/alerts/timeline ───────────────────────────────────


class TestTimelineEndpoint:
    async def test_timeline_returns_empty(self, client: AsyncClient, mock_db):
        mock_exec = MagicMock()
        mock_exec.all.return_value = []
        mock_db.execute.return_value = mock_exec

        resp = await client.get("/api/v1/live/alerts/timeline")
        assert resp.status_code == 200
        assert resp.json() == []


# ── Tests: GET /live/stats ──────────────────────────────────────────────


class TestStatsEndpoint:
    async def test_stats_returns_empty(self, client: AsyncClient, mock_db):
        mock_exec = MagicMock()
        mock_exec.scalars.return_value.all.return_value = []
        mock_db.execute.return_value = mock_exec

        resp = await client.get("/api/v1/live/stats")
        assert resp.status_code == 200
        assert resp.json() == []


# ── Tests: GET /live/metrics ────────────────────────────────────────────


class TestMetricsEndpoint:
    async def test_metrics_returns_counters(self, client: AsyncClient, mock_svc):
        resp = await client.get("/api/v1/live/metrics")
        assert resp.status_code == 200
        body = resp.json()
        assert body["queue_size"] == 0
        assert body["events_enqueued"] == 100
        assert body["events_processed"] == 95
        assert body["alerts_generated"] == 5
        assert body["active_sessions"] == 1
        assert body["uptime_seconds"] == 42.0

    async def test_metrics_503_when_service_not_started(self, app: FastAPI):
        if hasattr(app.state, "live_service"):
            del app.state.live_service
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/api/v1/live/metrics")
            assert resp.status_code == 503
