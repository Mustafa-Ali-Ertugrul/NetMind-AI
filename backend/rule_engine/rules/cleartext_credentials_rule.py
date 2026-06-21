"""NET-010 — Cleartext Credentials Detection Rule.

Detects credentials transmitted over cleartext (non-TLS) protocols:
  - FTP authentication (plaintext USER/PASS)
  - SMTP AUTH PLAIN / AUTH LOGIN (base64-encoded, cleartext-equivalent)
  - HTTP login pages served over plain HTTP (no TLS)
"""


from backend.contracts.features import AggregatedFeatures
from backend.contracts.findings import Evidence, Finding
from backend.rule_engine.base_rule import BaseDetectionRule
from backend.rule_engine.thresholds import (
    CLEARTEXT_LOGIN_URI_KEYWORDS,
)


class CleartextCredentialsRule(BaseDetectionRule):
    """NET-010: Cleartext Credentials Detection."""

    rule_id = "NET-010"
    rule_name = "Cleartext Credentials"
    description = "Detects credentials transmitted over cleartext (non-TLS) protocols"

    def _evaluate(self, features: AggregatedFeatures) -> list[Finding]:
        findings: list[Finding] = []
        affected_hosts: set[str] = set()
        evidences: list[Evidence] = []
        fired = 0
        total = 3  # FTP + SMTP + HTTP

        # ── FTP cleartext auth ───────────────────────────────────────
        ftp_auth_ips: set[str] = set()
        for ftp in features.ftp_flows:
            total_auth = ftp.failed_auth_count + ftp.success_auth_count
            if total_auth > 0:
                ftp_auth_ips.add(str(ftp.src_ip))
                fired += 1
        if ftp_auth_ips:
            affected_hosts.update(ftp_auth_ips)
            evidences.append(
                self._make_evidence(
                    "ftp_cleartext_auth",
                    len(ftp_auth_ips),
                    0,
                    unit="hosts",
                )
            )

        # ── SMTP cleartext auth ──────────────────────────────────────
        smtp_auth_ips: set[str] = set()
        for smtp in features.smtp_flows:
            if smtp.failed_auth_count > 0:
                smtp_auth_ips.add(str(smtp.src_ip))
                fired += 1
        if smtp_auth_ips:
            affected_hosts.update(smtp_auth_ips)
            evidences.append(
                self._make_evidence(
                    "smtp_cleartext_auth",
                    len(smtp_auth_ips),
                    0,
                    unit="hosts",
                )
            )

        # ── HTTP login pages over plaintext ──────────────────────────
        http_login_uris: list[str] = []
        for uri, _count in features.http_top_uris:
            lower = uri.lower()
            if any(kw in lower for kw in CLEARTEXT_LOGIN_URI_KEYWORDS):
                http_login_uris.append(uri)
                fired += 1
        if http_login_uris:
            evidences.append(
                self._make_evidence(
                    "http_cleartext_login",
                    len(http_login_uris),
                    0,
                    unit="URIs",
                )
            )

        if fired == 0:
            return findings

        raw_score = min(0.3 + (0.25 * fired / total), 1.0)
        risk = self._compute_risk_score(raw_score)
        affected_list = sorted(affected_hosts) if affected_hosts else ["unknown"]

        findings.append(
            Finding(
                pcap_id=features.pcap_id,
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                rule_version=self.rule_version,
                severity=self._risk_score_to_severity(risk),
                confidence=self._compute_confidence(fired, total),
                risk_score=risk,
                evidences=evidences,
                affected_entities=affected_list,
                timestamp_start=features.time_window_start,
                timestamp_end=features.time_window_end,
                raw_score=raw_score,
                title=(f"Cleartext credentials detected on {len(affected_list)} host(s)"),
                description=self.description,
                recommendation="Enforce TLS for all authentication traffic (HTTPS, FTPS, SMTPS). "
                "Disable plaintext auth mechanisms.",
                feature_snapshot={
                    "ftp_auth_hosts": len(ftp_auth_ips),
                    "smtp_auth_hosts": len(smtp_auth_ips),
                    "http_login_uris": len(http_login_uris),
                },
            )
        )

        return findings
