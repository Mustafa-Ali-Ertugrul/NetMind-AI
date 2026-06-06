"""Window-string parser for live aggregation endpoints.

Accepts shorthand strings such as ``"5m"``, ``"10m"``, ``"1h"``, ``"1d"``
and converts them to :class:`~datetime.timedelta`.

Grammar::

    window = number unit
    unit   = "s" | "m" | "h" | "d"
"""

from __future__ import annotations

import re
from datetime import timedelta

_WINDOW_RE = re.compile(r"^(\d+)([smhd])$")

_UNIT_MAP: dict[str, str] = {
    "s": "seconds",
    "m": "minutes",
    "h": "hours",
    "d": "days",
}


def parse_window(window: str) -> timedelta:
    """Parse *window* (e.g. ``"5m"``) and return the corresponding timedelta.

    Raises :class:`ValueError` when the format is invalid.
    """
    match = _WINDOW_RE.match(window.strip().lower())
    if not match:
        raise ValueError(
            f"Invalid window format: {window!r}. "
            "Expected a number followed by s/m/h/d (e.g. 5m, 10m, 1h, 1d)."
        )
    value = int(match.group(1))
    unit = match.group(2)
    return timedelta(**{_UNIT_MAP[unit]: value})
