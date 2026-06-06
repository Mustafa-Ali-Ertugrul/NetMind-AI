"""SQLAlchemy async engine and session factory."""

from collections.abc import AsyncGenerator
import os

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy import text

from backend.config import get_settings

settings = get_settings()

engine = create_async_engine(
    settings.database_url,
    echo=settings.database_echo,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

# Sync session factory for writer services that use sync Session
SyncSessionLocal = sessionmaker(
    bind=engine.sync_engine,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for all ORM models."""


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async DB session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db() -> None:
    """Apply all pending Alembic migrations."""
    import alembic.config
    import alembic.command

    ini_path = os.path.join(os.path.dirname(__file__), "..", "alembic.ini")
    alembic_cfg = alembic.config.Config(ini_path)
    alembic.command.upgrade(alembic_cfg, "head")
