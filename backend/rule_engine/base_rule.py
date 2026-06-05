"""Abstract base class for all detection rules."""

from abc import ABC, abstractmethod
from ipaddress import IPv4Address, IPv6Address
from math import log10
from uuid import UUID

from contracts.enums import Confidence, Severity
from contracts.features import AggregatedFeatures
from contracts.findings import Evidence, Finding


class BaseDetectionRule(ABC):
    """Abstract detection rule.

    Subclasses define:
    - rule_id, rule_name, rule_version (class-level)
    - _evaluate() returning list[Finding]

    The public evaluate() method wraps _evaluate() with common
    timestamp inference logic.
    """

    rule_id: str = ""
    rule_name: str = ""
    rule_version: str = "1.0.0"

    @abstractmethod
    def _evaluate(self, features: AggregatedFeatures) -> list[Finding]:
        """Implement rule logic. Return 0+ Findings."""
        ...

    def evaluate(self, features: AggregatedFeatures) -> list[Finding]:
        """Evaluate rule against features. Returns 0+ Findings."""
        return self._evaluate(features)

    # ------------------------------------------------------------------
    # Helpers for subclasses
    # ------------------------------------------------------------------

    @staticmethod
    def _make_evidence(
        key: str, value: float | int | str, threshold: float | int | str, unit: str | None = None
    ) -> Evidence:
        return Evidence(key=key, value=value, threshold=threshold, unit=unit)

    @staticmethod
    def _compute_risk_score(raw_score: float) -> int:
        """Map a 0.0-1.0 raw score to 0-100 risk score.

        Scores below 0.1 map to 0 (no finding level).
        Logarithmic boost at low end for sensitivity.
        """
        if raw_score <= 0.0:
            return 0
        clamped = min(max(raw_score, 0.0), 1.0)
        return min(int(clamped * 100), 100)

    @staticmethod
    def _risk_score_to_severity(risk_score: int) -> Severity:
        if risk_score >= 76:
            return Severity.CRITICAL
        if risk_score >= 51:
            return Severity.HIGH
        if risk_score >= 26:
            return Severity.MEDIUM
        if risk_score >= 1:
            return Severity.LOW
        return Severity.INFORMATIONAL

    @staticmethod
    def _compute_confidence(indicator_count: int, total_indicators: int) -> Confidence:
        """Confidence based on fraction of indicators that fired."""
        if total_indicators == 0:
            return Confidence.LOW
        ratio = indicator_count / total_indicators
        if ratio >= 0.8:
            return Confidence.HIGH
        if ratio >= 0.4:
            return Confidence.MEDIUM
        return Confidence.LOW

    @staticmethod
    def _severity_weight(severity: Severity) -> int:
        return severity.value  # INFORMATIONAL=1 … CRITICAL=5
