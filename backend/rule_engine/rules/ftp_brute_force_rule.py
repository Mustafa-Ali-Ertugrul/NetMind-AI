"""FTP Brute Force Detection Rule."""

from backend.contracts.enums import Severity
from backend.contracts.features import AggregatedFeatures, FTPFlow
from backend.contracts.findings import Finding

from ..base_rule import BaseDetectionRule
from ..thresholds import (
    FTP_AUTH_RATE_HIGH,
    FTP_AUTH_RATE_SUSPECT,
    FTP_FAILED_AUTH_COUNT_MIN,
    FTP_FAILED_AUTH_RATIO_SUSPECT,
)


class FTPBruteForceRule(BaseDetectionRule):
    """Detect FTP brute-force authentication attempts.

    Fires when a source IP shows:
    - High failed_auth_ratio (>0.7), AND
    - At least FTP_FAILED_AUTH_COUNT_MIN failed attempts, AND
    - Elevated auth rate (attempts/sec).
    """

    rule_id = "NET-003"
    rule_name = "FTP Brute Force Detection"
    rule_version = "1.0.0"

    def _evaluate(self, features: AggregatedFeatures) -> list[Finding]:
        findings: list[Finding] = []

        for flow in features.ftp_flows:
            f = self._eval_flow(flow, features)
            if f is not None:
                findings.append(f)

        return findings

    def _eval_flow(
        self,
        flow: FTPFlow,
        features: AggregatedFeatures,
    ) -> Finding | None:
        if flow.failed_auth_count < FTP_FAILED_AUTH_COUNT_MIN:
            return None
        if flow.failed_auth_ratio < FTP_FAILED_AUTH_RATIO_SUSPECT:
            return None

        # --- indicators ---
        high_ratio = flow.failed_auth_ratio >= FTP_FAILED_AUTH_RATIO_SUSPECT
        high_rate = (
            flow.auth_rate_per_second is not None
            and flow.auth_rate_per_second >= FTP_AUTH_RATE_SUSPECT
        )
        very_high_rate = (
            flow.auth_rate_per_second is not None
            and flow.auth_rate_per_second >= FTP_AUTH_RATE_HIGH
        )
        many_failures = flow.failed_auth_count >= FTP_FAILED_AUTH_COUNT_MIN * 3

        indicator_count = sum([high_ratio, high_rate or very_high_rate, many_failures])

        # --- evidence ---
        evidences = [
            self._make_evidence(
                "failed_auth_ratio",
                round(flow.failed_auth_ratio, 4),
                f"{FTP_FAILED_AUTH_RATIO_SUSPECT}+",
                unit="ratio",
            ),
            self._make_evidence(
                "failed_auth_count",
                flow.failed_auth_count,
                f"{FTP_FAILED_AUTH_COUNT_MIN}+",
                unit="attempts",
            ),
            self._make_evidence(
                "auth_rate_per_second",
                round(flow.auth_rate_per_second or 0.0, 4),
                f"{FTP_AUTH_RATE_SUSPECT}+",
                unit="attempts/sec",
            ),
            self._make_evidence(
                "success_auth_count",
                flow.success_auth_count,
                "N/A",
                unit="attempts",
            ),
        ]

        # --- scoring ---
        ratio_score = min(flow.failed_auth_ratio / 1.0, 1.0)
        rate_score = min((flow.auth_rate_per_second or 0.0) / FTP_AUTH_RATE_HIGH, 1.0)
        count_score = min(flow.failed_auth_count / 30.0, 1.0)

        raw_score = 0.4 * ratio_score + 0.3 * rate_score + 0.3 * count_score
        risk_score = self._compute_risk_score(raw_score)
        severity = self._severity_from_score(raw_score, very_high_rate, many_failures)
        confidence = self._compute_confidence(indicator_count, 3)

        src = str(flow.src_ip)
        title = f"FTP brute force detected from {src}"
        description = (
            f"Source {src} performed {flow.failed_auth_count} failed FTP "
            f"authentications ({flow.failed_auth_ratio:.0%} failure rate) "
            f"at {flow.auth_rate_per_second or 0:.2f} attempts/sec. "
            f"This is consistent with credential stuffing or brute-force attack."
        )
        recommendation = (
            f"Block or rate-limit FTP connections from {src}. "
            f"Enable account lockout policies and review logs for "
            f"compromised credentials. Consider moving to key-based or "
            f"multi-factor authentication."
        )

        return Finding(
            pcap_id=features.pcap_id,
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            rule_version=self.rule_version,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            title=title,
            description=description,
            recommendation=recommendation,
            evidences=evidences,
            affected_entities=[src],
            timestamp_start=features.time_window_start,
            timestamp_end=features.time_window_end,
            raw_score=round(raw_score, 4),
            feature_snapshot={
                "failed_auth_ratio": flow.failed_auth_ratio,
                "failed_auth_count": float(flow.failed_auth_count),
                "auth_rate_per_second": flow.auth_rate_per_second or 0.0,
                "success_auth_count": float(flow.success_auth_count),
                "total_commands": float(flow.total_commands),
            },
        )

    @staticmethod
    def _severity_from_score(
        raw_score: float, very_high_rate: bool, many_failures: bool
    ) -> Severity:
        if raw_score >= 0.7 or (very_high_rate and many_failures):
            return Severity.CRITICAL
        if raw_score >= 0.5 or very_high_rate:
            return Severity.HIGH
        if raw_score >= 0.3:
            return Severity.MEDIUM
        return Severity.LOW
