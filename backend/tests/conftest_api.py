"""Pytest fixtures for API-level (FastAPI test client) tests.

These fixtures override the DB dependency so tests can run
without a real PostgreSQL connection.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from backend.api.app import create_app
from backend.api.dependencies import get_db_session
from backend.config import get_settings


@pytest.fixture(name="app")
def _app(tmp_path, monkeypatch) -> FastAPI:
    """Return a bare-bones app instance (lifespan skipped via override approach)."""
    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path / "pcaps"))
    monkeypatch.setenv("ARTIFACT_STORAGE_PATH", str(tmp_path / "artifacts"))
    get_settings.cache_clear()
    return create_app()


@pytest.fixture(name="mock_db")
def _mock_db() -> AsyncMock:
    """Return a mock async database session."""
    return AsyncMock()


@pytest.fixture(name="client")
async def _client(app: FastAPI, mock_db: AsyncMock) -> AsyncClient:
    """Return an async test client with DB dependency overridden to a mock."""
    app.dependency_overrides[get_db_session] = lambda: mock_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
