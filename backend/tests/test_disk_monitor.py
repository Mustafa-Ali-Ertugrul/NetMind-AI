"""Tests for DiskMonitor (backend.storage.disk_monitor)."""

from pathlib import Path

import pytest

from backend.storage.disk_monitor import DiskMonitor


def test_get_usage_returns_expected_keys(tmp_path: Path):
    monitor = DiskMonitor(path=tmp_path, threshold_pct=85.0)
    usage = monitor.get_usage()

    assert "total_gb" in usage
    assert "used_gb" in usage
    assert "free_gb" in usage
    assert "percent" in usage
    assert "over_threshold" in usage
    assert usage["threshold_pct"] == 85.0


def test_get_usage_creates_path_if_missing(tmp_path: Path):
    new_dir = tmp_path / "nonexistent" / "deep"
    monitor = DiskMonitor(path=new_dir, threshold_pct=85.0)
    usage = monitor.get_usage()

    assert usage["total_gb"] > 0  # Directory was created
    assert new_dir.exists()


def test_is_over_threshold_with_very_low_threshold(tmp_path: Path):
    # threshold=0% should always be over (disk usage > 0%)
    monitor = DiskMonitor(path=tmp_path, threshold_pct=0.0)
    assert monitor.is_over_threshold() is True


def test_is_over_threshold_with_very_high_threshold(tmp_path: Path):
    # threshold=100% should never be over on a healthy disk
    monitor = DiskMonitor(path=tmp_path, threshold_pct=100.0)
    assert monitor.is_over_threshold() is False


def test_available_bytes_returns_positive(tmp_path: Path):
    monitor = DiskMonitor(path=tmp_path)
    assert monitor.available_bytes > 0


def test_get_usage_graceful_on_inaccessible_path():
    # A path that is unlikely to exist and cannot be created
    monitor = DiskMonitor(path=Path(r"\\.\NonExistentVolume\path"))
    usage = monitor.get_usage()
    # Should return zeros with error, not crash
    assert usage["total_gb"] == 0.0
    assert usage["over_threshold"] is False
