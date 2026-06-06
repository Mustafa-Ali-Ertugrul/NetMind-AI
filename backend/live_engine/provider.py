"""Pluggable StreamingRuleEngine provider.

Current:
    GlobalEngineProvider — single shared engine for all sessions.
Future:
    EnginePoolProvider — per-session engine pool with LRU eviction.

Usage::

    provider: EngineProvider = GlobalEngineProvider()
    engine = provider.get(session_id)
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable
from uuid import UUID

from backend.live_engine.streaming_engine import StreamingRuleEngine


@runtime_checkable
class EngineProvider(Protocol):
    """Pluggable engine factory.

    ``get()`` returns a ``StreamingRuleEngine`` instance. Today the
    ``session_id`` parameter is accepted for forward-compatibility
    with a future per-session pool.
    """

    def get(self, session_id: UUID | None = None) -> StreamingRuleEngine:
        """Return a rule engine, optionally scoped to a session."""
        ...


class GlobalEngineProvider:
    """Single shared engine.  All callers see the same instance."""

    def __init__(self) -> None:
        self._engine = StreamingRuleEngine()

    def get(self, session_id: UUID | None = None) -> StreamingRuleEngine:
        return self._engine
