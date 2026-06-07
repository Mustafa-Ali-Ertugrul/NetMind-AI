"""Tests for live engine adaptive threshold calibration."""

from __future__ import annotations

import pytest

from backend.live_engine.adaptive_threshold import AdaptiveThresholdTracker


class TestAdaptiveThresholdTracker:
    """Unit tests for the rolling-window z-score tracker."""

    def test_adapt_falls_back_to_raw_score_with_no_history(self):
        tracker = AdaptiveThresholdTracker()
        assert tracker.adapt("beaconing", 0.6) == pytest.approx(0.6)

    def test_record_then_adapt_with_enough_samples(self):
        tracker = AdaptiveThresholdTracker(min_samples=5, window_size=10)
        # Fill window with baseline scores around 0.5
        for _ in range(7):
            tracker.record("beaconing", 0.50)
        # Steady score: z ≈ 0 → raw unchanged
        assert tracker.adapt("beaconing", 0.50) == pytest.approx(0.50)

    def test_anomaly_boosts_high_zscore(self):
        tracker = AdaptiveThresholdTracker(
            min_samples=5,
            window_size=10,
            z_cap=3.0,
        )
        for _ in range(7):
            tracker.record("beaconing", 0.50)
        # z ≈ (0.90 - 0.50) / 0.0?  Be careful — std could be zero.
        # First add slight variance to avoid zero std.
        tracker.record("beaconing", 0.52)
        tracker.record("beaconing", 0.48)
        adapted = tracker.adapt("beaconing", 0.90)
        assert adapted > 0.90

    def test_suppresses_low_zscore(self):
        tracker = AdaptiveThresholdTracker(min_samples=5, window_size=10)
        for _ in range(7):
            tracker.record("beaconing", 0.80)
        tracker.record("beaconing", 0.82)
        tracker.record("beaconing", 0.78)
        adapted = tracker.adapt("beaconing", 0.10)
        assert adapted < 0.10

    def test_clamping(self):
        tracker = AdaptiveThresholdTracker(min_samples=0)
        # Without enough samples it should still clamp to [0,1]
        assert tracker.adapt("beaconing", -0.5) == pytest.approx(0.0)
        assert tracker.adapt("beaconing", 1.5) == pytest.approx(1.0)

    def test_rule_isolation(self):
        tracker = AdaptiveThresholdTracker(min_samples=5, window_size=10)
        for _ in range(7):
            tracker.record("beaconing", 0.80)
            tracker.record("port_scan", 0.20)
        tracker.record("port_scan", 0.18)
        tracker.record("port_scan", 0.22)
        # beaconing raw 0.10 should be suppressed (below its baseline)
        assert tracker.adapt("beaconing", 0.10) < 0.10
        # port_scan has its own lower baseline, so a high relative score is boosted
        assert tracker.adapt("port_scan", 0.40) > 0.40

    def test_rolling_window_evicts_old(self):
        tracker = AdaptiveThresholdTracker(min_samples=5, window_size=5)
        for _ in range(5):
            tracker.record("beaconing", 0.10)
        # Window full of low values
        assert tracker.adapt("beaconing", 0.50) > 0.50  # high relative to baseline
        # Now overwrite with high values
        for _ in range(5):
            tracker.record("beaconing", 0.90)
        # Same raw 0.50 should now be suppressed (below new baseline)
        assert tracker.adapt("beaconing", 0.50) < 0.50

    def test_disable_enable_rule(self):
        tracker = AdaptiveThresholdTracker(min_samples=1)
        tracker.record("beaconing", 0.50)
        tracker.disable_rule("beaconing")
        assert tracker.adapt("beaconing", 0.90) == pytest.approx(0.90)
        tracker.enable_rule("beaconing")
        assert tracker.adapt("beaconing", 0.90) != pytest.approx(
            0.90
        )  # boosted since baseline was 0.5

    def test_stats_structure(self):
        tracker = AdaptiveThresholdTracker(min_samples=0)
        tracker.record("beaconing", 0.50)
        stats = tracker.get_all_stats()
        assert "beaconing" in stats
        assert stats["beaconing"].sample_count == 1
        assert stats["beaconing"].mean == pytest.approx(0.50)

    def test_reset_clears_state(self):
        tracker = AdaptiveThresholdTracker(min_samples=1)
        tracker.record("beaconing", 0.50)
        tracker.reset()
        assert tracker.adapt("beaconing", 0.50) == pytest.approx(0.50)
        assert tracker.get_all_stats() == {}
