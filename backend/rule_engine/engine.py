"""RuleEngine orchestrator — runs all rules and aggregates findings."""

import logging
from uuid import UUID

from backend.contracts.enums import RiskLabel, Severity
from backend.contracts.features import AggregatedFeatures
from backend.contracts.findings import Finding, OverallRiskScore

from .registry import RuleRegistry
from .rules import (
    BeaconingRule,
    CleartextCredentialsRule,
    DNSTunnelingRule,
    FTPBruteForceRule,
    HTTPAnomalyRule,
    ICMPFloodRule,
    LargeOutboundRule,
    PortScanRule,
    SMTPAbuseRule,
    SYNFloodRule,
    TopTalkerRule,
)

logger = logging.getLogger("netmind.rule_engine")


class RuleEngine:
    """Orchestrates detection rules against AggregatedFeatures.

    Typical usage::

        engine = RuleEngine()
        findings, overall = engine.analyze(features)
    """

    def __init__(self, registry: RuleRegistry | None = None) -> None:
        self._registry = registry or self._default_registry()

    @staticmethod
    def _default_registry() -> RuleRegistry:
        reg = RuleRegistry()
        # CV/demo default: expose the full built-in detection surface.
        reg.register(PortScanRule())
        reg.register(DNSTunnelingRule())
        reg.register(FTPBruteForceRule())
        reg.register(SMTPAbuseRule())
        reg.register(SYNFloodRule())
        reg.register(ICMPFloodRule())
        reg.register(HTTPAnomalyRule())
        reg.register(TopTalkerRule())
        reg.register(BeaconingRule())
        reg.register(CleartextCredentialsRule())
        reg.register(LargeOutboundRule())
        return reg

    @property
    def registry(self) -> RuleRegistry:
        return self._registry

    def analyze(
        self,
        features: AggregatedFeatures,
    ) -> tuple[list[Finding], OverallRiskScore]:
        """Run all registered rules against features.

        Returns (findings, overall_risk_score).
        """
        all_findings: list[Finding] = []
        failed_rules: list[str] = []

        for rule in self._registry.get_all():
            try:
                rule_findings = rule.evaluate(features)
                all_findings.extend(rule_findings)
            except Exception:
                logger.exception(
                    "Rule %s (%s) failed during evaluate()", rule.rule_id, rule.rule_name
                )
                failed_rules.append(rule.rule_id)
                # Isolate rule failure — one broken rule does not
                # block the rest. The caller can inspect the partial
                # result via OverallRiskScore.failed_rules.

        overall = self._compute_overall_risk(all_findings, failed_rules, features.pcap_id)
        return all_findings, overall

    @staticmethod
    def _compute_overall_risk(
        findings: list[Finding],
        failed_rules: list[str],
        pcap_id: UUID,
    ) -> OverallRiskScore:
        if not findings:
            return OverallRiskScore(
                max_score=0,
                weighted_score=0,
                severity_label=RiskLabel.INFORMATIONAL,
                total_findings=0,
                findings_by_severity={},
                top_finding_ids=[],
                failed_rules=failed_rules,
            )

        # Max individual score
        max_score = max(f.risk_score for f in findings)

        # Weighted — higher severity findings count more
        total_weight = 0
        weighted_sum = 0
        for f in findings:
            w = _severity_weight(f.severity)
            total_weight += w
            weighted_sum += f.risk_score * w
        weighted_score = weighted_sum // total_weight if total_weight > 0 else 0

        # Severity label
        severity_label = _score_to_label(weighted_score)

        # Severity breakdown
        by_severity: dict[str, int] = {}
        for f in findings:
            key = f.severity.name  # CRITICAL, HIGH, etc.
            by_severity[key] = by_severity.get(key, 0) + 1

        # Top findings (sorted by risk_score desc)
        sorted_findings = sorted(findings, key=lambda f: f.risk_score, reverse=True)
        top_ids = [f.id for f in sorted_findings[:5]]

        return OverallRiskScore(
            max_score=max_score,
            weighted_score=weighted_score,
            severity_label=severity_label,
            total_findings=len(findings),
            findings_by_severity=by_severity,
            top_finding_ids=top_ids,
            failed_rules=failed_rules,
        )


def _severity_weight(s: Severity) -> int:
    return s.value  # 1–5


def _score_to_label(score: int) -> RiskLabel:
    if score >= 76:
        return RiskLabel.CRITICAL
    if score >= 51:
        return RiskLabel.HIGH
    if score >= 26:
        return RiskLabel.MEDIUM
    if score >= 1:
        return RiskLabel.LOW
    return RiskLabel.INFORMATIONAL
