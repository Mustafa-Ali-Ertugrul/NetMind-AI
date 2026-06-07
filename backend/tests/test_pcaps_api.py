"""Tests for the /pcaps upload endpoint validation.

These tests validate the upload pipeline without a real DB:
  - File extension rejection
  - Empty filename rejection
  - Oversize file rejection
  - Magic bytes validation (invalid content, empty content)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_upload_rejects_bad_extension(client: AsyncClient, mock_db: AsyncMock) -> None:
    """POST /pcaps with .txt file returns 415."""
    resp = await client.post(
        "/api/v1/pcaps",
        files={"file": ("test.txt", b"dummy content", "text/plain")},
    )
    assert resp.status_code == 415
    assert "extension" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_upload_rejects_no_filename(client: AsyncClient, mock_db: AsyncMock) -> None:
    """POST /pcaps without filename is rejected by FastAPI multipart validation."""
    resp = await client.post(
        "/api/v1/pcaps",
        files={"file": ("", b"dummy content", "application/octet-stream")},
    )
    assert resp.status_code == 422
    assert "file" in str(resp.json()["detail"]).lower()


@pytest.mark.asyncio
async def test_upload_rejects_oversize(client: AsyncClient, mock_db: AsyncMock) -> None:
    """POST /pcaps with a file exceeding the max size returns 413.

    Uses the default setting (100 MB) and sends a payload larger than that.
    """
    # Send a payload that exceeds the default 100 MiB limit
    big_content = b"X" * (101 * 1024 * 1024)  # 101 MiB
    resp = await client.post(
        "/api/v1/pcaps",
        files={"file": ("oversize.pcap", big_content, "application/octet-stream")},
    )
    assert resp.status_code == 413, f"Expected 413, got {resp.status_code}"


@pytest.mark.asyncio
async def test_upload_rejects_invalid_magic_bytes(client: AsyncClient, mock_db: AsyncMock) -> None:
    """POST /pcaps with a .pcap file that has invalid magic bytes returns 415."""
    resp = await client.post(
        "/api/v1/pcaps",
        files={"file": ("bad.pcap", b"\x00\x01\x02\x03extra", "application/octet-stream")},
    )
    assert resp.status_code == 415
    assert "magic" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_upload_rejects_empty_content(client: AsyncClient, mock_db: AsyncMock) -> None:
    """POST /pcaps with a .pcap file that is too small returns 415."""
    resp = await client.post(
        "/api/v1/pcaps",
        files={"file": ("empty.pcap", b"", "application/octet-stream")},
    )
    assert resp.status_code == 415
    assert "too small" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_upload_accepts_valid_pcap(client: AsyncClient, mock_db: AsyncMock) -> None:
    """POST /pcaps with a valid PCAP file returns 201 (or 200 if dedup'ed).

    Because the DB is mocked, the route will attempt DB operations.
    We mock the dedup SELECT to return None (no existing file),
    and the INSERT to succeed. This exercises the full validation chain.
    """
    # Mock the dedup query: SELECT from PcapFile WHERE sha256 = ...
    from unittest.mock import MagicMock

    execute_result = MagicMock()
    execute_result.scalar_one_or_none.return_value = None

    async def async_execute(*args, **kwargs):
        return execute_result

    mock_db.execute = AsyncMock(side_effect=async_execute)
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    mock_db.flush = AsyncMock()

    valid_pcap = b"\xd4\xc3\xb2\xa1" + b"\x00" * 100  # PCAP magic + padding

    # Mock Celery task to avoid broker dependency.
    # The route lazily imports analyze_pcap_task from backend.worker.tasks.pcap_analysis.
    mock_task = MagicMock()
    mock_task.delay.return_value = None

    with patch(
        "backend.worker.tasks.pcap_analysis.analyze_pcap_task",
        mock_task,
        create=True,
    ):
        resp = await client.post(
            "/api/v1/pcaps",
            files={"file": ("valid.pcap", valid_pcap, "application/octet-stream")},
        )

    # 201 = created, 200 = deduplicated — both are acceptable
    assert resp.status_code in (200, 201), f"Expected 2xx, got {resp.status_code}"
