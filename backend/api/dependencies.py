"""FastAPI dependencies for route handlers."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from backend.storage.database import get_db

__all__ = ["get_db_session"]


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Re-export of the storage get_db for API routes."""
    async for session in get_db():
        yield session
