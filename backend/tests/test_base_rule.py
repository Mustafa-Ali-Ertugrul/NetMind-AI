"""Tests for BaseDetectionRule helper methods."""

from backend.contracts.enums import Confidence, Severity
from backend.rule_engine.base_rule import BaseDetectionRule


class TestBaseDetectionRule:
    """BaseDetectionRule static helpers."""

    def test_compute_risk_score_zero(self):
        assert BaseDetectionRule._compute_risk_score(0.0) == 0

    def test_compute_risk_score_max(self):
        assert BaseDetectionRule._compute_risk_score(1.0) == 100

    def test_compute_risk_score_clamp(self):
        assert BaseDetectionRule._compute_risk_score(1.5) == 100
        assert BaseDetectionRule._compute_risk_score(-0.1) == 0

    def test_risk_score_to_severity(self):
        assert BaseDetectionRule._risk_score_to_severity(0) == Severity.INFORMATIONAL
        assert BaseDetectionRule._risk_score_to_severity(10) == Severity.LOW
        assert BaseDetectionRule._risk_score_to_severity(30) == Severity.MEDIUM
        assert BaseDetectionRule._risk_score_to_severity(60) == Severity.HIGH
        assert BaseDetectionRule._risk_score_to_severity(90) == Severity.CRITICAL

    def test_compute_confidence(self):
        assert BaseDetectionRule._compute_confidence(0, 3) == Confidence.LOW
        assert BaseDetectionRule._compute_confidence(1, 3) == Confidence.LOW
        assert BaseDetectionRule._compute_confidence(2, 3) == Confidence.MEDIUM
        assert BaseDetectionRule._compute_confidence(3, 3) == Confidence.HIGH
        assert BaseDetectionRule._compute_confidence(0, 0) == Confidence.LOW

    def test_make_evidence(self):
        ev = BaseDetectionRule._make_evidence("test_key", 42.5, ">10", unit="count")
        assert ev.key == "test_key"
        assert ev.value == 42.5
        assert ev.threshold == ">10"
        assert ev.unit == "count"

    def test_severity_weight(self):
        assert BaseDetectionRule._severity_weight(Severity.INFORMATIONAL) == 1
        assert BaseDetectionRule._severity_weight(Severity.LOW) == 2
        assert BaseDetectionRule._severity_weight(Severity.MEDIUM) == 3
        assert BaseDetectionRule._severity_weight(Severity.HIGH) == 4
        assert BaseDetectionRule._severity_weight(Severity.CRITICAL) == 5
