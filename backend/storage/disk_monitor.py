"""Disk usage monitoring for storage lifecycle management."""

from __future__ import annotations

import ctypes
import logging
import os
import platform
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _get_disk_usage_win32(path: str) -> tuple[int, int, int]:
    """Get disk usage on Windows via GetDiskFreeSpaceExW."""
    free_bytes = ctypes.c_ulonglong(0)
    total_bytes = ctypes.c_ulonglong(0)
    ctypes.windll.kernel32.GetDiskFreeSpaceExW(
        ctypes.c_wchar_p(path),
        None,
        ctypes.byref(total_bytes),
        ctypes.byref(free_bytes),
    )
    total = total_bytes.value
    free = free_bytes.value
    used = total - free
    return total, used, free


def _get_disk_usage_posix(path: str) -> tuple[int, int, int]:
    """Get disk usage on POSIX via os.statvfs."""
    st = os.statvfs(path)  # type: ignore[attr-defined]
    total = st.f_frsize * st.f_blocks
    free = st.f_frsize * st.f_bavail
    used = total - free
    return total, used, free


if platform.system() == "Windows":
    _get_disk_usage = _get_disk_usage_win32
else:
    _get_disk_usage = _get_disk_usage_posix


class DiskMonitor:
    """Monitor disk usage under a given path.

    Falls back gracefully when the monitored path does not exist
    or is inaccessible, returning a zero-usage status rather than
    crashing the caller.
    """

    def __init__(self, path: Path, threshold_pct: float = 85.0) -> None:
        self.path = path
        self.threshold_pct = threshold_pct

    def get_usage(self) -> dict[str, Any]:
        """Return a disk usage snapshot dict."""
        try:
            self.path.mkdir(parents=True, exist_ok=True)
            total, used, free = _get_disk_usage(str(self.path.resolve()))
            percent = (used / total * 100) if total > 0 else 0.0

            return {
                "total_gb": round(total / (1024**3), 2),
                "used_gb": round(used / (1024**3), 2),
                "free_gb": round(free / (1024**3), 2),
                "percent": round(percent, 1),
                "over_threshold": percent > self.threshold_pct,
                "threshold_pct": self.threshold_pct,
            }
        except (OSError, PermissionError) as exc:
            logger.warning("Disk monitor could not stat %s: %s", self.path, exc)
            return {
                "total_gb": 0.0,
                "used_gb": 0.0,
                "free_gb": 0.0,
                "percent": 0.0,
                "over_threshold": False,
                "threshold_pct": self.threshold_pct,
                "error": str(exc),
            }

    def is_over_threshold(self) -> bool:
        """Return True if disk usage exceeds the configured threshold."""
        usage = self.get_usage()
        return usage.get("over_threshold", False)

    @property
    def available_bytes(self) -> int:
        """Return estimated free bytes on the monitored volume."""
        usage = self.get_usage()
        return int(usage.get("free_gb", 0) * (1024**3))
