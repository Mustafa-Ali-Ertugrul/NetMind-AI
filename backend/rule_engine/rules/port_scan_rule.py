"""Port Scan Detection Rule."""

from backend.contracts.enums import Confidence, Severity
from backend.contracts.features import AggregatedFeatures, ConnectionProfile
from backend.contracts.findings import Finding

from ..base_rule import BaseDetectionRule
from ..thresholds import (
    PORT_SCAN_CPM_HIGH,
    PORT_SCAN_CPM_LOW,
    PORT_SCAN_CPM_MEDIUM,
    PORT_SCAN_PORTS_CRITICAL,
    PORT_SCAN_PORTS_HIGH,
    PORT_SCAN_PORTS_MEDIUM,
    PORT_SCAN_SUSPECT_RATIO_MIN,
)


class PortScanRule(BaseDetectionRule):
    """Detect port-scan behavior from ConnectionProfile features.

    Fires on profiles where:
    1. port_scan_suspect is True, AND
    2. Connections-per-minute exceeds a threshold.

    Severity scales with unique_dst_ports count.
    """

    rule_id = "NET-001"
    rule_name = "Port Scan Detection"
    rule_version = "1.0.0"

    def _evaluate(self, features: AggregatedFeatures) -> list[Finding]:
        findings: list[Finding] = []

        for profile in features.connection_profiles:
            f = self._eval_profile(profile, features)
            if f is not None:
                findings.append(f)

        return findings

    def _eval_profile(
        self,
        profile: ConnectionProfile,
        features: AggregatedFeatures,
    ) -> Finding | None:
        if not profile.port_scan_suspect:
            return None

        # --- evidence collection ---
        evidences = [
            self._make_evidence(
                "unique_dst_ports",
                profile.unique_dst_ports,
                str(PORT_SCAN_PORTS_MEDIUM),
                unit="ports",
            ),
            self._make_evidence(
                "failed_connection_ratio",
                round(profile.failed_connection_ratio, 4),
                str(PORT_SCAN_SUSPECT_RATIO_MIN),
                unit="ratio",
            ),
            self._make_evidence(
                "connections_per_minute",
                round(profile.connections_per_minute, 2),
                f"{PORT_SCAN_CPM_LOW}+",
                unit="cpm",
            ),
            self._make_evidence(
                "unique_dst_ips",
                profile.unique_dst_ips,
                "N/A",
                unit="hosts",
            ),
            self._make_evidence(
                "unique_dst_ports_per_host",
                round(profile.unique_dst_ports_per_host, 2),
                "N/A",
                unit="ports/host",
            ),
        ]

        # --- score & severity ---
        ports = profile.unique_dst_ports
        ports_per_host = profile.unique_dst_ports_per_host
        cpm = profile.connections_per_minute
        ratio = profile.failed_connection_ratio

        # raw_score 0.0-1.0 based on multiple axes
        port_score = min(ports / PORT_SCAN_PORTS_CRITICAL, 1.0)
        ports_per_host_score = min(ports_per_host / 50.0, 1.0) * 0.5  # 0-0.5 bonus
        cpm_score = min(cpm / PORT_SCAN_CPM_HIGH, 1.0)
        ratio_score = min(ratio / 1.0, 1.0)
        raw_score = (
            0.5 * port_score + 0.3 * cpm_score + 0.2 * ratio_score + 0.1 * ports_per_host_score
        )

        risk_score = self._compute_risk_score(raw_score)
        severity = self._severity_from_ports(ports, cpm, ratio)
        confidence = self._compute_confidence(
            indicator_count=(1 if ports >= PORT_SCAN_PORTS_MEDIUM else 0)
            + (1 if cpm >= PORT_SCAN_CPM_MEDIUM else 0)
            + (1 if ratio >= PORT_SCAN_SUSPECT_RATIO_MIN else 0)
            + (1 if ports_per_host >= 10 else 0),
            total_indicators=4,
        )

        src = str(profile.src_ip)
        title = f"Port scan detected from {src}"

        # classify scan type
        if ports_per_host >= 10 and profile.unique_dst_ips <= 3:
            scan_type = "vertical scan (many ports on few targets)"
        elif ports_per_host <= 3 and profile.unique_dst_ips > 10:
            scan_type = "horizontal scan (few ports across many targets)"
        else:
            scan_type = "reconnaissance activity"

        description = (
            f"Source {src} connected to {profile.unique_dst_ports} distinct "
            f"ports across {profile.unique_dst_ips} hosts "
            f"({profile.connections_per_minute:.1f} connections/min, "
            f"failed ratio {profile.failed_connection_ratio:.0%}, "
            f"{ports_per_host:.1f} ports/host). "
            f"Pattern: {scan_type}. "
            f"This is indicative of reconnaissance or port-scanning activity."
        )
        recommendation = (
            f"Investigate host {src} for malicious scanning activity. "
            f"Consider rate-limiting inbound connections or deploying "
            f"an IPS/IDS to block automated scanners."
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
            timestamp_start=profile.first_seen,
            timestamp_end=profile.last_seen,
            raw_score=round(raw_score, 4),
            feature_snapshot={
                "unique_dst_ports": float(ports),
                "connections_per_minute": cpm,
                "failed_connection_ratio": ratio,
                "unique_dst_ips": float(profile.unique_dst_ips),
                "port_scan_suspect": 1.0,
            },
        )

    @staticmethod
    def _severity_from_ports(ports: int, cpm: float, ratio: float) -> Severity:
        if ports >= PORT_SCAN_PORTS_CRITICAL or cpm >= PORT_SCAN_CPM_HIGH:
            return Severity.CRITICAL
        if ports >= PORT_SCAN_PORTS_HIGH or cpm >= PORT_SCAN_CPM_MEDIUM:
            return Severity.HIGH
        if ports >= PORT_SCAN_PORTS_MEDIUM or cpm >= PORT_SCAN_CPM_LOW:
            return Severity.MEDIUM
        return Severity.LOW
