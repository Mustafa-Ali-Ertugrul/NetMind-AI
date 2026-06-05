"""DNS Tunneling Detection Rule."""

from contracts.enums import Confidence, Severity
from contracts.features import AggregatedFeatures, DNSProfile
from contracts.findings import Finding

from ..base_rule import BaseDetectionRule
from ..thresholds import (
    DNS_BASE64_RATIO_HIGH,
    DNS_BASE64_RATIO_SUSPECT,
    DNS_ENTROPY_HIGH,
    DNS_ENTROPY_SUSPECT,
    DNS_QUERY_FREQ_PER_DOMAIN_HIGH,
    DNS_QUERY_FREQ_PER_DOMAIN_SUSPECT,
    DNS_QUERY_FREQ_PER_IP_SUSPECT,
    DNS_SUBDOMAIN_COUNT_HIGH,
    DNS_SUBDOMAIN_COUNT_SUSPECT,
)


class DNSTunnelingRule(BaseDetectionRule):
    """Detect DNS tunneling from DNSProfile features.

    Combines up to 5 indicators:
    1. base64_ratio — encoded payload in subdomains
    2. unique_subdomain_count — many distinct subdomains
    3. subdomain_entropy — high randomness
    4. query_frequency_per_domain — high query rate to domain
    5. query_frequency_per_ip — high query rate from specific source
    """

    rule_id = "NET-002"
    rule_name = "DNS Tunneling Detection"
    rule_version = "1.0.0"

    def _evaluate(self, features: AggregatedFeatures) -> list[Finding]:
        findings: list[Finding] = []

        for profile in features.dns_profiles:
            f = self._eval_profile(profile, features)
            if f is not None:
                findings.append(f)

        return findings

    def _eval_profile(
        self,
        profile: DNSProfile,
        features: AggregatedFeatures,
    ) -> Finding | None:
        # --- indicator checks ---
        indicators = {
            "base64_high": profile.base64_ratio >= DNS_BASE64_RATIO_HIGH,
            "base64_suspect": DNS_BASE64_RATIO_SUSPECT
            <= profile.base64_ratio
            < DNS_BASE64_RATIO_HIGH,
            "subdomains_high": profile.unique_subdomain_count >= DNS_SUBDOMAIN_COUNT_HIGH,
            "subdomains_suspect": DNS_SUBDOMAIN_COUNT_SUSPECT
            <= profile.unique_subdomain_count
            < DNS_SUBDOMAIN_COUNT_HIGH,
            "entropy_high": profile.subdomain_entropy >= DNS_ENTROPY_HIGH,
            "entropy_suspect": DNS_ENTROPY_SUSPECT <= profile.subdomain_entropy < DNS_ENTROPY_HIGH,
            "freq_domain_high": profile.query_frequency_per_domain
            >= DNS_QUERY_FREQ_PER_DOMAIN_HIGH,
            "freq_domain_suspect": DNS_QUERY_FREQ_PER_DOMAIN_SUSPECT
            <= profile.query_frequency_per_domain
            < DNS_QUERY_FREQ_PER_DOMAIN_HIGH,
            "freq_ip_suspect": any(
                qf >= DNS_QUERY_FREQ_PER_IP_SUSPECT
                for qf in profile.query_frequency_per_ip.values()
            ),
        }

        # At least one strong indicator or two weak ones needed
        strong_count = sum(1 for k, v in indicators.items() if k.endswith("_high") and v)
        weak_count = sum(1 for k, v in indicators.items() if k.endswith("_suspect") and v)
        total_fired = strong_count + weak_count

        if strong_count == 0 and weak_count < 2:
            return None

        # --- evidence ---
        evidences = [
            self._make_evidence(
                "base64_ratio",
                round(profile.base64_ratio, 4),
                f"{DNS_BASE64_RATIO_SUSPECT}+",
                unit="ratio",
            ),
            self._make_evidence(
                "unique_subdomain_count",
                profile.unique_subdomain_count,
                f"{DNS_SUBDOMAIN_COUNT_SUSPECT}+",
                unit="subdomains",
            ),
            self._make_evidence(
                "subdomain_entropy",
                round(profile.subdomain_entropy, 4),
                f"{DNS_ENTROPY_SUSPECT}+",
                unit="bits",
            ),
            self._make_evidence(
                "query_frequency_per_domain",
                round(profile.query_frequency_per_domain, 2),
                f"{DNS_QUERY_FREQ_PER_DOMAIN_SUSPECT}+",
                unit="qpm",
            ),
        ]

        # --- score & severity ---
        raw_score = self._compute_raw_score(profile, indicators)
        risk_score = self._compute_risk_score(raw_score)
        severity = self._severity_from_score(raw_score, strong_count)
        confidence = self._compute_confidence(total_fired, 5)

        qname = profile.qname
        top_src = (
            max(
                profile.query_frequency_per_ip.items(),
                key=lambda kv: kv[1],
            )[0]
            if profile.query_frequency_per_ip
            else "unknown"
        )

        title = f"Potential DNS tunneling detected: {qname}"
        description = (
            f"Domain {qname} exhibits {strong_count + weak_count}/5 DNS-tunneling "
            f"indicators: base64_ratio={profile.base64_ratio:.2%}, "
            f"subdomains={profile.unique_subdomain_count}, "
            f"entropy={profile.subdomain_entropy:.2f}, "
            f"query_rate={profile.query_frequency_per_domain:.1f}/min. "
            f"This pattern is consistent with data exfiltration or "
            f"C2 communication over DNS."
        )
        recommendation = (
            f"Review DNS queries to {qname} originating from {top_src}. "
            f"Consider blocking or sinkholing the domain if confirmed "
            f"malicious. Inspect subdomain payloads for encoded data."
        )

        src_ips = profile.src_ips[:10]  # limit to top 10

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
            affected_entities=[qname, top_src, *src_ips],
            timestamp_start=features.time_window_start,
            timestamp_end=features.time_window_end,
            raw_score=round(raw_score, 4),
            feature_snapshot={
                "base64_ratio": profile.base64_ratio,
                "unique_subdomain_count": float(profile.unique_subdomain_count),
                "subdomain_entropy": profile.subdomain_entropy,
                "query_frequency_per_domain": profile.query_frequency_per_domain,
                "query_count": float(profile.query_count),
                "response_success_rate": profile.response_success_rate,
            },
        )

    @staticmethod
    def _compute_raw_score(
        profile: DNSProfile,
        indicators: dict[str, bool],
    ) -> float:
        """Compute 0.0-1.0 raw score from all indicators."""
        base = 0.0
        weights = {
            "base64_high": 0.30,
            "subdomains_high": 0.20,
            "entropy_high": 0.20,
            "freq_domain_high": 0.15,
            "base64_suspect": 0.15,
            "subdomains_suspect": 0.10,
            "entropy_suspect": 0.10,
            "freq_domain_suspect": 0.08,
            "freq_ip_suspect": 0.07,
        }

        # Clamp maximum continuous values for proportional contribution
        ratio_progress = min(profile.base64_ratio / 1.0, 1.0) * 0.10
        sub_progress = min(profile.unique_subdomain_count / 100, 1.0) * 0.10
        ent_progress = min(profile.subdomain_entropy / 8.0, 1.0) * 0.10
        freq_progress = min(profile.query_frequency_per_domain / 200, 1.0) * 0.10

        continuous = ratio_progress + sub_progress + ent_progress + freq_progress

        discrete = sum(w for key, w in weights.items() if indicators.get(key, False))

        return min(base + discrete + continuous, 1.0)

    @staticmethod
    def _severity_from_score(raw_score: float, strong_count: int) -> Severity:
        if raw_score >= 0.7 or strong_count >= 3:
            return Severity.CRITICAL
        if raw_score >= 0.5 or strong_count >= 2:
            return Severity.HIGH
        if raw_score >= 0.3 or strong_count >= 1:
            return Severity.MEDIUM
        return Severity.LOW
