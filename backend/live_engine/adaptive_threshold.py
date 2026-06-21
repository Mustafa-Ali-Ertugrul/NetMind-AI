"""Adaptive thresholds — learn per-rule baseline risk score distributions and
calibrate raw scores relative to historical patterns.

No database schema changes required.  All state is kept in application memory
and is volatile (resets on restart).  This is intentional — persistent
adaptive state will be added once the PostgreSQL / TimescaleDB migration is
performed in a later phase.
"""

from __future__ import annotations

import logging
import math
from collections import deque
from dataclasses import dataclass

logger = logging.getLogger("netmind.live_engine.adaptive")


@dataclass(frozen=True)
class RuleBaselineStats:
    """Snapshot of baseline stats for a single rule."""

    rule_id: str
    mean: float
    std_dev: float
    sample_count: int
    window_size: int


@dataclass
class AdaptiveConfig:
    """Tunable parameters for the adaptive layer."""

    enabled: bool = True
    window_size: int = 100
    min_samples: int = 10
    z_boost: float = 0.15
    z_suppress: float = 0.15
    z_cap: float = 3.0


class AdaptiveThresholdTracker:
    """Rule-agnostic adaptive threshold tracker.

    Maintains a rolling window of recent ``raw_score`` values per rule,
    computes mean / std-dev on demand, and normalises a new raw score
    relative to that learned baseline.

    The tracker is **dual-pass** on purpose::

        1. ``adapt()`` is called with the raw score *before* the window
           is updated, so the baseline reflects *previous* behaviour
           (not the current score).
        2. ``record()`` adds the raw score to the window afterwards.

    This prevents circular reinforcement (a high score immediately
    shifting the baseline and hiding anomalies).
    """

    def __init__(
        self,
        config: AdaptiveConfig | None = None,
        *,
        window_size: int | None = None,
        min_samples: int | None = None,
        z_boost: float | None = None,
        z_suppress: float | None = None,
        z_cap: float | None = None,
    ) -> None:
        base = config or AdaptiveConfig()
        self._config = AdaptiveConfig(
            window_size=window_size if window_size is not None else base.window_size,
            min_samples=min_samples if min_samples is not None else base.min_samples,
            z_boost=z_boost if z_boost is not None else base.z_boost,
            z_suppress=z_suppress if z_suppress is not None else base.z_suppress,
            z_cap=z_cap if z_cap is not None else base.z_cap,
        )
        self._windows: dict[str, deque[float]] = {}
        self._disabled_rules: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def config(self) -> AdaptiveConfig:
        return self._config

    def enabled_for(self, rule_id: str) -> bool:
        """Return whether adaptive thresholding is active for *rule_id*."""
        if not self._config.enabled:
            return False
        return rule_id not in self._disabled_rules

    def enable_rule(self, rule_id: str) -> None:
        """Enable adaptive tracking for a specific rule."""
        self._disabled_rules.discard(rule_id)

    def disable_rule(self, rule_id: str) -> None:
        """Disable adaptive tracking for a specific rule."""
        self._disabled_rules.add(rule_id)

    def adapt(self, rule_id: str, raw_score: float) -> float:
        """Return an adapted raw score for *rule_id*.

        The score is boosted when it is an anomaly (z-score > cap)
        and suppressed when it is below the learned baseline.
        When there are not enough samples the score passes through
        unchanged.
        """
        # Clamp raw input to valid range first
        raw_score = min(max(float(raw_score), 0.0), 1.0)

        if not self.enabled_for(rule_id):
            return raw_score

        stats = self._compute_stats(rule_id)
        if stats.sample_count < self._config.min_samples:
            return raw_score

        # Z-score relative to learned baseline
        if stats.std_dev > 1e-9:
            z = (raw_score - stats.mean) / stats.std_dev
        else:
            # Zero variance: every score at mean == no anomaly, else treat as capped
            if raw_score > stats.mean:
                z = self._config.z_cap
            elif raw_score < stats.mean:
                z = -self._config.z_cap
            else:
                z = 0.0

        if z > self._config.z_cap:
            # Strong anomaly → cap at max boost
            boost = 1.0 + self._config.z_cap * self._config.z_boost
            adapted = raw_score * boost
            logger.debug(
                "rule=%s raw=%.4f z=%.2f → boosted (capped) to %.4f",
                rule_id,
                raw_score,
                z,
                adapted,
            )
            return min(adapted, 1.0)

        if z > 0.0:
            # Moderate anomaly → proportional boost
            boost = 1.0 + z * self._config.z_boost
            adapted = raw_score * boost
            logger.debug(
                "rule=%s raw=%.4f z=%.2f → boosted to %.4f",
                rule_id,
                raw_score,
                z,
                adapted,
            )
            return min(adapted, 1.0)

        if z < -self._config.z_cap:
            # Far below baseline → cap suppression
            damp = max(1.0 - self._config.z_cap * self._config.z_suppress, 0.0)
            adapted = raw_score * damp
            logger.debug(
                "rule=%s raw=%.4f z=%.2f → suppressed (capped) to %.4f",
                rule_id,
                raw_score,
                z,
                adapted,
            )
            return max(adapted, 0.0)

        # Negative z → suppression (z_suppress is positive, so 1.0 - |z| * z_suppress < 1.0)
        damp = 1.0 + z * self._config.z_suppress
        adapted = raw_score * damp
        logger.debug(
            "rule=%s raw=%.4f z=%.2f → suppressed to %.4f",
            rule_id,
            raw_score,
            z,
            adapted,
        )
        return max(adapted, 0.0)

    def record(self, rule_id: str, raw_score: float) -> None:
        """Add *raw_score* to the historical window for *rule_id*."""
        window = self._windows.setdefault(rule_id, deque(maxlen=self._config.window_size))
        window.append(raw_score)

    def stats(self, rule_id: str) -> RuleBaselineStats | None:
        """Return current baseline stats for *rule_id*, or None."""
        stats = self._compute_stats(rule_id)
        if stats.sample_count == 0:
            return None
        return stats

    def all_stats(self) -> dict[str, RuleBaselineStats]:
        """Return baseline stats for every rule with data."""
        return {
            rid: s
            for rid, s in ((rid, self._compute_stats(rid)) for rid in self._windows)
            if s.sample_count > 0
        }

    def get_all_stats(self) -> dict[str, RuleBaselineStats]:
        """Alias for ``all_stats()`` — used by API consumers."""
        return self.all_stats()

    def reset(self) -> None:
        """Clear all learned state (useful for tests and session resets)."""
        self._windows.clear()
        self._disabled_rules.clear()
        logger.info("Adaptive threshold state reset")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _compute_stats(self, rule_id: str) -> RuleBaselineStats:
        window = self._windows.get(rule_id)
        if not window:
            return RuleBaselineStats(
                rule_id=rule_id,
                mean=0.0,
                std_dev=0.0,
                sample_count=0,
                window_size=self._config.window_size,
            )

        n = len(window)
        mean = sum(window) / n
        variance = sum((x - mean) ** 2 for x in window) / n
        std_dev = math.sqrt(variance)

        return RuleBaselineStats(
            rule_id=rule_id,
            mean=mean,
            std_dev=std_dev,
            sample_count=n,
            window_size=self._config.window_size,
        )
