"""NetMind AI Rule Engine — Phase 3 of the detection pipeline.

Converts AggregatedFeatures from the Feature Extractor into
a list of Finding objects with severity, confidence, evidence,
recommendation, and risk score.

Built-in rules:
    - PortScanRule (NET-001)
    - DNSTunnelingRule (NET-002)
    - FTPBruteForceRule (NET-003)
    - SMTPAbuseRule (NET-004)

Usage::

    from rule_engine import RuleEngine
    from contracts.features import AggregatedFeatures

    engine = RuleEngine()
    findings, overall_risk = engine.analyze(features)
"""

from .base_rule import BaseDetectionRule
from .engine import RuleEngine
from .registry import RuleRegistry
from .rules import (
    DNSTunnelingRule,
    FTPBruteForceRule,
    PortScanRule,
    SMTPAbuseRule,
)

__all__ = [
    "BaseDetectionRule",
    "DNSTunnelingRule",
    "FTPBruteForceRule",
    "PortScanRule",
    "RuleEngine",
    "RuleRegistry",
    "SMTPAbuseRule",
]
