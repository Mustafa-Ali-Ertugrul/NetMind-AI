"""Tests for Sprint 6 storage artifact API helpers."""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from backend.api.routes import jobs as jobs_routes
from backend.api.routes import pcaps as pcaps_routes
from backend.api.schemas import AnalysisResultResponse, JobStatusResponse


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _FakeAsyncSession:
    def __init__(self, values):
        self._values = list(values)
        self.committed = False

    async def execute(self, _query):
        return _ScalarResult(self._values.pop(0))

    async def commit(self):
        self.committed = True


@pytest.mark.asyncio
async def test_download_pcap_returns_file_response_and_updates_access_time(tmp_path, monkeypatch):
    artifact = tmp_path / "ab" / "sample.pcap"
    artifact.parent.mkdir()
    artifact.write_bytes(b"pcap")
    pcap = SimpleNamespace(
        id=uuid4(),
        storage_key="ab/sample.pcap",
        status="completed",
        deleted_at=None,
        original_name="sample.pcap",
        mime_type="application/vnd.tcpdump.pcap",
        last_accessed_at=None,
    )
    db = _FakeAsyncSession([pcap])
    monkeypatch.setattr(
        pcaps_routes,
        "get_settings",
        lambda: SimpleNamespace(upload_dir=tmp_path, object_store_backend="local"),
    )

    response = await pcaps_routes.download_pcap(pcap.id, db)

    # download_pcap now returns StreamingResponse
    from fastapi.responses import StreamingResponse

    assert isinstance(response, StreamingResponse)
    assert response.media_type == "application/vnd.tcpdump.pcap"
    assert pcap.last_accessed_at is not None
    assert db.committed is True


@pytest.mark.asyncio
async def test_download_pcap_deleted_row_returns_410(tmp_path, monkeypatch):
    pcap = SimpleNamespace(
        id=uuid4(),
        storage_key="ab/sample.pcap",
        status="deleted",
        deleted_at=datetime.utcnow(),
    )
    db = _FakeAsyncSession([pcap])
    monkeypatch.setattr(
        pcaps_routes,
        "get_settings",
        lambda: SimpleNamespace(upload_dir=tmp_path, object_store_backend="local"),
    )

    with pytest.raises(HTTPException) as exc:
        await pcaps_routes.download_pcap(pcap.id, db)

    assert exc.value.status_code == 410


@pytest.mark.asyncio
async def test_download_job_report_returns_attachment_json(monkeypatch):
    job_id = uuid4()
    result = AnalysisResultResponse(
        job=JobStatusResponse(
            id=job_id,
            pcap_id=uuid4(),
            status="completed",
            created_at=datetime.utcnow(),
        ),
        pcap_id=uuid4(),
        alerts=[],
        ai_assessment=None,
    )

    async def fake_get_job_result(_job_id, _db):
        return result

    monkeypatch.setattr(jobs_routes, "get_job_result", fake_get_job_result)

    response = await jobs_routes.download_job_report(job_id, db=object())

    assert response.media_type == "application/json"
    assert f"netmind-report-{job_id}.json" in response.headers["Content-Disposition"]
