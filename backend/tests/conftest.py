"""Shared pytest fixtures and SQLite type shims.

The ORM models in backend.storage.models use Postgres-only types
(INET, JSONB, PG_UUID). For unit tests we need them to compile to
SQLite-friendly equivalents. This conftest registers type compilers
that map each Postgres type to a TEXT/JSON/CHAR(36) representation.
The PostgreSQL compilation path is unchanged.
"""

from collections.abc import AsyncIterator
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.compiler import compiles

from backend.api.app import app
from backend.api.dependencies import get_db_session


@compiles(INET, "sqlite")
def _compile_inet_sqlite(_type, _compiler, **_kw) -> str:
    return "TEXT"


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(_type, _compiler, **_kw) -> str:
    return "JSON"


@compiles(PG_UUID, "sqlite")
def _compile_pguuid_sqlite(_type, _compiler, **_kw) -> str:
    return "CHAR(36)"


@pytest.fixture
def mock_db() -> AsyncMock:
    """Return an AsyncMock that behaves like an AsyncSession."""
    return AsyncMock()


@pytest.fixture
async def client(mock_db: AsyncMock) -> AsyncIterator[AsyncClient]:
    """Return an httpx AsyncClient wired to the app with a mocked DB session.

    Overrides the ``get_db_session`` dependency so route handlers receive
    ``mock_db`` instead of a real database connection.
    """

    async def _override_db() -> AsyncIterator[AsyncMock]:
        yield mock_db

    app.dependency_overrides[get_db_session] = _override_db

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac

    app.dependency_overrides.clear()
