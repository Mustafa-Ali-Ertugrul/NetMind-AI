"""Tests for StorageService (backend.storage.service) and lifecycle functions.

Uses the same mock patterns as test_storage_api.py for consistency.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.storage.database import Base
from backend.storage.exceptions import PcapNotFoundError
from backend.storage.schemas import CleanupResult, StorageStatus
from backend.storage.service import StorageService


class _ScalarResult:
    """Mock for SQLAlchemy Result that returns one or no row."""

    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value

    def scalar(self):
        if isinstance(self._value, (int, float)):
            return self._value
        return None


class _ScalarsResultFull:
    """Mock for Result that supports .scalars().all()."""

    def __init__(self, values: list):
        self._values = values

    def scalars(self):
        return _ScalarSubResult(self._values)

    def scalar_one_or_none(self):
        return self._values[0] if self._values else None


class _ScalarSubResult:
    def __init__(self, values: list):
        self._values = values

    def all(self):
        return self._values


class _FakeAsyncSession:
    """Minimal fake for AsyncSession used in select/execute-heavy tests.

    Values are consumed in FIFO order from the provided list.
    A value can be:
      - An ORM-like object (returned as scalars result)
      - An int (returned as scalar)
      - A list of objects (returned via scalars().all())
    """

    def __init__(self, values: list | None = None):
        self._values = list(values) if values else []
        self.committed = False
        self.added: list = []

    async def execute(self, _query):
        if not self._values:
            return _ScalarsResultFull([])
        val = self._values.pop(0)
        if isinstance(val, list):
            return _ScalarsResultFull(val)
        return _ScalarResult(val)

    async def commit(self):
        self.committed = True

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        pass

    async def refresh(self, obj):
        pass


def _make_settings(tmp_path: Path, **overrides) -> SimpleNamespace:
    """Build a minimal Settings-like object for testing."""
    base = {
        "upload_dir": tmp_path / "pcaps",
        "artifact_storage_path": tmp_path / "artifacts",
        "storage_retention_days": 7,
        "disk_usage_threshold_pct": 85.0,
        "artifact_retention_hours": 168,
        "storage_cleanup_enabled": True,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


# ── StorageService ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_pcap_path_raises_for_missing_record(tmp_path: Path):
    db = _FakeAsyncSession([None])
    settings = _make_settings(tmp_path)
    svc = StorageService(db=db, settings=settings)

    with pytest.raises(PcapNotFoundError):
        await svc.get_pcap_path(uuid4())


@pytest.mark.asyncio
async def test_get_storage_status_returns_valid_shape(tmp_path: Path):
    from backend.storage.schemas import DiskStatus

    # Provide int values for count queries, empty list for PCAP query
    db = _FakeAsyncSession([0, 0, 0, 0, []])
    settings = _make_settings(tmp_path)
    svc = StorageService(db=db, settings=settings)

    status = await svc.get_storage_status()

    assert isinstance(status, StorageStatus)
    assert isinstance(status.disk, DiskStatus)
    assert status.disk.total_gb > 0
    assert status.pcap_count == 0


@pytest.mark.asyncio
async def test_run_cleanup_on_empty_storage(tmp_path: Path):
    # Empty list for expired PCAP query, artifact dir doesn't exist
    db = _FakeAsyncValues([])
    settings = _make_settings(tmp_path)
    svc = StorageService(db=db, settings=settings)

    result = await svc.run_cleanup()

    assert isinstance(result, CleanupResult)
    assert result.files_deleted == 0
    assert result.rows_soft_deleted == 0


# ── Lifecycle helpers (sync, real SQLite) ───────────────────────────


def _init_sqlite_memory() -> sessionmaker:
    """Create an in-memory SQLite engine with all tables created."""
    engine = create_engine("sqlite://", echo=False)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)


def test_cleanup_expired_pcaps_noop_when_table_empty(tmp_path: Path):
    from backend.storage.lifecycle import cleanup_expired_pcaps

    session_factory = _init_sqlite_memory()
    with session_factory() as db:
        result = cleanup_expired_pcaps(db, tmp_path)
        assert result["expired_found"] == 0
        assert result["files_deleted"] == 0


def test_cleanup_expired_artifacts_noop_when_empty(tmp_path: Path):
    from backend.storage.lifecycle import cleanup_expired_artifacts

    session_factory = _init_sqlite_memory()
    with session_factory() as db:
        result = cleanup_expired_artifacts(db, tmp_path)
        assert result["artifacts_deleted"] == 0


def test_cleanup_expired_pcaps_with_expired_row(tmp_path: Path):
    from backend.storage.lifecycle import cleanup_expired_pcaps
    from backend.storage.models import PcapFile

    session_factory = _init_sqlite_memory()
    with session_factory() as db:
        # Create a file on disk
        key = "ab/expired.pcap"
        target = tmp_path / key
        target.parent.mkdir(parents=True)
        target.write_bytes(b"data")

        # Create an expired PCAP row
        pcap = PcapFile(
            id=uuid4(),
            filename="expired.pcap",
            original_name="test.pcap",
            file_size=4,
            sha256="aaaa",
            storage_key=key,
            status="completed",
            uploaded_at=datetime.utcnow() - timedelta(days=30),
            expires_at=datetime.utcnow() - timedelta(days=1),
        )
        db.add(pcap)
        db.commit()

        result = cleanup_expired_pcaps(db, tmp_path)
        assert result["expired_found"] == 1
        assert result["files_deleted"] == 1
        assert result["rows_soft_deleted"] == 1
        assert not target.exists()


# ── Helper for async cleanup test ───────────────────────────────────


class _FakeAsyncValues:
    """Simpler mock: execute returns a list directly via scalars().all()."""

    def __init__(self, values: list):
        self._values = values
        self.committed = False

    async def execute(self, _query):
        return _ScalarsResultFull(self._values)

    async def commit(self):
        self.committed = True

    def add(self, obj):
        pass

    async def flush(self):
        pass

    async def refresh(self, obj):
        pass
