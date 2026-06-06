"""Tests for the /health endpoint."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_returns_ok(client: AsyncClient, mock_db: AsyncMock) -> None:
    """GET /health returns 200 with HealthResponse when DB is reachable."""
    # Simulate a successful DB ping
    exec_mock = AsyncMock()
    exec_mock.scalar.return_value = 1
    mock_db.execute.return_value = exec_mock

    resp = await client.get("/health")
    assert resp.status_code == 200

    body = resp.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert "app_name" in body
    assert "app_version" in body
    assert "environment" in body
    assert "timestamp" in body


@pytest.mark.asyncio
async def test_health_degraded_on_db_failure(client: AsyncClient, mock_db: AsyncMock) -> None:
    """GET /health returns degraded when the DB ping fails."""
    mock_db.execute.side_effect = Exception("connection refused")

    resp = await client.get("/health")
    assert resp.status_code == 200

    body = resp.json()
    assert body["status"] == "degraded"
    assert body["database"] == "unavailable"
