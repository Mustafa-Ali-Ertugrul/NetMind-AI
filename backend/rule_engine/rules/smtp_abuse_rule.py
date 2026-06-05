"""SMTP Abuse Detection Rule."""

from contracts.enums import Confidence, Severity
from contracts.features import AggregatedFeatures, SMTPFlow
from contracts.findings import Finding

from ..base_rule import BaseDetectionRule
from ..thresholds import (
    SMTP_FAILED_AUTH_COUNT_SUSPECT,
    SMTP_MESSAGE_COUNT_HIGH,
    SMTP_MESSAGE_COUNT_SUSPECT,
    SMTP_UNIQUE_RECIPIENTS_HIGH,
    SMTP_UNIQUE_RECIPIENTS_SUSPECT,
)


class SMTPAbuseRule(BaseDetectionRule):
    """Detect SMTP abuse — spam campaigns, credential stuffing, relay abuse.

    Fires when a source IP shows elevated patterns across:
    - Many unique recipients (spam campaign)
    - Many messages from one source
    - Failed auth attempts (credential stuffing)
    """

    rule_id = "NET-004"
    rule_name = "SMTP Abuse Detection"
    rule_version = "1.0.0"

    def _evaluate(self, features: AggregatedFeatures) -> list[Finding]:
        findings: list[Finding] = []

        for flow in features.smtp_flows:
            f = self._eval_flow(flow, features)
            if f is not None:
                findings.append(f)

        return findings

    def _eval_flow(
        self,
        flow: SMTPFlow,
        features: AggregatedFeatures,
    ) -> Finding | None:
        # --- indicator checks ---
        many_recipients_suspect = flow.unique_recipients >= SMTP_UNIQUE_RECIPIENTS_SUSPECT
        many_recipients_high = flow.unique_recipients >= SMTP_UNIQUE_RECIPIENTS_HIGH
        many_messages_suspect = flow.message_count >= SMTP_MESSAGE_COUNT_SUSPECT
        many_messages_high = flow.message_count >= SMTP_MESSAGE_COUNT_HIGH
        failed_auth_suspect = flow.failed_auth_count >= SMTP_FAILED_AUTH_COUNT_SUSPECT

        # At least one indicator must be strong
        strong = many_recipients_high or many_messages_high
        weak = many_recipients_suspect or many_messages_suspect or failed_auth_suspect

        if not strong and not weak:
            return None

        indicator_count = sum([many_recipients_suspect, many_messages_suspect, failed_auth_suspect])
        total_indicators = 3

        # --- evidence ---
        evidences = [
            self._make_evidence(
                "unique_recipients",
                flow.unique_recipients,
                f"{SMTP_UNIQUE_RECIPIENTS_SUSPECT}+",
                unit="recipients",
            ),
            self._make_evidence(
                "message_count",
                flow.message_count,
                f"{SMTP_MESSAGE_COUNT_SUSPECT}+",
                unit="messages",
            ),
            self._make_evidence(
                "failed_auth_count",
                flow.failed_auth_count,
                f"{SMTP_FAILED_AUTH_COUNT_SUSPECT}+",
                unit="attempts",
            ),
            self._make_evidence(
                "total_connections",
                flow.total_connections,
                "N/A",
                unit="connections",
            ),
        ]

        # --- scoring ---
        recip_score = min(flow.unique_recipients / SMTP_UNIQUE_RECIPIENTS_HIGH, 1.0)
        msg_score = min(flow.message_count / SMTP_MESSAGE_COUNT_HIGH, 1.0)
        auth_score = min(flow.failed_auth_count / (SMTP_FAILED_AUTH_COUNT_SUSPECT * 3), 1.0)

        # Weight for scenario type
        if many_recipients_high and not many_messages_high:
            # Likely relay / spam — low auth weight
            raw_score = 0.5 * recip_score + 0.2 * msg_score + 0.1 * auth_score
        elif many_messages_high and many_recipients_high:
            # Mass mailing from authenticated source
            raw_score = 0.4 * recip_score + 0.4 * msg_score + 0.1 * auth_score
        elif failed_auth_suspect and many_recipients_suspect:
            # Credential stuffing + spam
            raw_score = 0.3 * recip_score + 0.2 * msg_score + 0.4 * auth_score
        else:
            # Balanced default
            raw_score = 0.3 * recip_score + 0.3 * msg_score + 0.3 * auth_score

        raw_score = min(raw_score + 0.1 * (1 if strong else 0), 1.0)
        risk_score = self._compute_risk_score(raw_score)
        severity = self._severity_from_score(raw_score, strong, failed_auth_suspect)
        confidence = self._compute_confidence(indicator_count, total_indicators)

        src = str(flow.src_ip)
        title = f"SMTP abuse detected from {src}"
        description = (
            f"Source {src} sent {flow.message_count} messages to "
            f"{flow.unique_recipients} unique recipients "
            f"({flow.failed_auth_count} failed auths, "
            f"{flow.total_connections} connections). "
        )
        if many_recipients_high:
            description += "The high recipient count suggests a spam or phishing campaign."
        elif failed_auth_suspect:
            description += "The elevated auth failures suggest credential stuffing activity."
        else:
            description += "This may indicate unauthorized relay or compromised account use."

        recommendation = (
            f"Review SMTP relay logs for source {src}. "
            f"Consider blocking if unauthorized. Implement rate limiting, "
            f"SPF/DKIM/DMARC, and ensure relay is restricted to authenticated users."
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
                "unique_recipients": float(flow.unique_recipients),
                "message_count": float(flow.message_count),
                "failed_auth_count": float(flow.failed_auth_count),
                "total_connections": float(flow.total_connections),
            },
        )

    @staticmethod
    def _severity_from_score(raw_score: float, strong: bool, failed_auth: bool) -> Severity:
        if raw_score >= 0.7 or (strong and failed_auth):
            return Severity.CRITICAL
        if raw_score >= 0.5 or strong:
            return Severity.HIGH
        if raw_score >= 0.3:
            return Severity.MEDIUM
        return Severity.LOW
