"""NET-006 — HTTP Anomaly Detection Rule.

Flags suspicious HTTP behavior: high error ratios, malicious
user-agents, and single-URI scanning patterns.
"""

from backend.contracts.enums import Confidence, Severity
from backend.contracts.features import AggregatedFeatures
from backend.contracts.findings import Evidence, Finding
from backend.rule_engine.base_rule import BaseDetectionRule
from backend.rule_engine.thresholds import (
    HTTP_ERROR_RATIO_SUSPECT,
    HTTP_SCAN_UA_PATTERNS,
    HTTP_SINGLE_URI_SHARE_SUSPECT,
)


class HTTPAnomalyRule(BaseDetectionRule):
    """NET-006: HTTP Anomaly Detection."""

    rule_id = "NET-006"
    rule_name = "HTTP Anomaly"
    description = "Detects suspicious HTTP behavior (errors, malicious UAs, unusual ports)"

    def _evaluate(self, features: AggregatedFeatures) -> list[Finding]:
        if not features.http_top_uris:
            return []

        evidences: list[Evidence] = []
        fired = 0
        total = 3
        error_ratio = 0.0
        uri_share = 0.0

        # 1. HTTP error ratio (4xx + 5xx)
        total_status = sum(features.http_status_counts.values())
        error_status = sum(
            count for code, count in features.http_status_counts.items() if code >= 400
        )
        if total_status > 0:
            error_ratio = error_status / total_status
            if error_ratio >= HTTP_ERROR_RATIO_SUSPECT:
                evidences.append(
                    self._make_evidence(
                        "http_error_ratio", round(error_ratio, 3), HTTP_ERROR_RATIO_SUSPECT
                    )
                )
                fired += 1

        # 2. Suspicious User-Agents
        suspicious_ua_count = sum(
            1
            for ua in features.http_user_agents
            if any(pattern.lower() in ua.lower() for pattern in HTTP_SCAN_UA_PATTERNS)
        )
        if suspicious_ua_count >= 1:
            evidences.append(self._make_evidence("suspicious_ua_count", suspicious_ua_count, 1))
            fired += 1

        # 3. Single URI dominance
        if features.http_top_uris:
            top_uri, top_count = features.http_top_uris[0]
            total_uris = sum(c for _, c in features.http_top_uris)
            if total_uris > 0:
                uri_share = top_count / total_uris
                if uri_share >= HTTP_SINGLE_URI_SHARE_SUSPECT:
                    evidences.append(
                        self._make_evidence(
                            "single_uri_share", round(uri_share, 3), HTTP_SINGLE_URI_SHARE_SUSPECT
                        )
                    )
                    fired += 1

        if not evidences:
            return []

        raw_score = 0.3 + (0.5 * error_ratio)
        if suspicious_ua_count >= 1:
            raw_score += 0.2
        raw_score = min(raw_score, 1.0)

        risk = self._compute_risk_score(raw_score)

        return [
            Finding(
                pcap_id=features.pcap_id,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                rule_version=self.rule_version,
                severity=self._risk_score_to_severity(risk),
                confidence=self._compute_confidence(fired, total),
                risk_score=risk,
                evidences=evidences,
                affected_entities=[],
                timestamp_start=features.time_window_start,
                timestamp_end=features.time_window_end,
                raw_score=raw_score,
                title="HTTP Anomaly Detected",
                description=self.description,
                recommendation="Review HTTP traffic for scanners, bots, or misconfigured applications",
                feature_snapshot={
                    "error_ratio": round(error_ratio, 3),
                    "suspicious_ua_count": suspicious_ua_count,
                    "single_uri_share": round(uri_share, 3),
                },
            )
        ]
