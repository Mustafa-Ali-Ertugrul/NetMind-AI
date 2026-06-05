"""SQLAlchemy async engine and session factory."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
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
    """Create all tables. MVP-only: replace with Alembic for production."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_ensure_storage_lifecycle_columns)


def _ensure_storage_lifecycle_columns(sync_conn) -> None:
    """Apply minimal additive DDL for pre-Sprint-6 databases.

    This keeps existing Docker volumes usable until the project adopts Alembic.
    """
    if sync_conn.dialect.name != "postgresql":
        return

    sync_conn.execute(
        text(
            """
            ALTER TABLE pcap_files
              ADD COLUMN IF NOT EXISTS last_accessed_at TIMESTAMPTZ,
              ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
              ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
            """
        )
    )
    sync_conn.execute(
        text(
            """
            ALTER TABLE pcap_files
              DROP CONSTRAINT IF EXISTS ck_pcap_files_status;
            ALTER TABLE pcap_files
              ADD CONSTRAINT ck_pcap_files_status
              CHECK (status IN (
                'queued','parsing','extracting','detecting','assessing',
                'completed','failed','uploaded','deleted'
              ));
            CREATE INDEX IF NOT EXISTS idx_pcap_files_expires_at
              ON pcap_files (expires_at);
            CREATE INDEX IF NOT EXISTS idx_pcap_files_deleted_at
              ON pcap_files (deleted_at);
            """
        )
    )
