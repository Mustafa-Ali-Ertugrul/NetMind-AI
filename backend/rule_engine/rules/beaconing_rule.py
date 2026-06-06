"""NET-009 — Beaconing Detection Rule.

Detects periodic beaconing behavior by low coefficient of
variation in inter-packet intervals, combined with small
packet sizes and sufficient packet counts.
"""

from ipaddress import IPv4Address, IPv6Address

from backend.contracts.enums import Confidence, Severity
from backend.contracts.features import AggregatedFeatures
from backend.contracts.findings import Evidence, Finding
from backend.rule_engine.base_rule import BaseDetectionRule
from backend.rule_engine.thresholds import (
    BEACON_AVG_PKT_SIZE_MAX,
    BEACON_DURATION_MIN_MS,
    BEACON_PACKET_COUNT_MIN,
    BEACON_VARIANCE_RATIO_HIGH,
    BEACON_VARIANCE_RATIO_SUSPECT,
)


class BeaconingRule(BaseDetectionRule):
    """NET-009: Beaconing Detection."""

    rule_id = "NET-009"
    rule_name = "Beaconing"
    description = (
        "Detects periodic beaconing traffic by low interval variance and small packet sizes"
    )

    def _evaluate(self, features: AggregatedFeatures) -> list[Finding]:
        findings: list[Finding] = []
        for flow in features.flows:
            pkt_count = flow.packets_total
            duration_ms = max(flow.duration_ms, 1.0)

            if pkt_count < BEACON_PACKET_COUNT_MIN:
                continue
            if duration_ms < BEACON_DURATION_MIN_MS:
                continue

            avg_size = flow.bytes_total / max(pkt_count, 1)
            if avg_size >= BEACON_AVG_PKT_SIZE_MAX:
                continue

            mean = flow.inter_packet_interval_ms
            variance = flow.inter_packet_interval_variance_ms
            if mean <= 0:
                continue
            cv = (variance**0.5) / mean
            if cv >= BEACON_VARIANCE_RATIO_SUSPECT:
                continue

            evidences: list[Evidence] = []
            fired = 0
            total = 3

            if pkt_count >= BEACON_PACKET_COUNT_MIN:
                evidences.append(
                    self._make_evidence("beacon_pkt_count", pkt_count, BEACON_PACKET_COUNT_MIN)
                )
                fired += 1

            if avg_size < BEACON_AVG_PKT_SIZE_MAX:
                evidences.append(
                    self._make_evidence(
                        "beacon_avg_size", round(avg_size, 1), BEACON_AVG_PKT_SIZE_MAX, unit="B"
                    )
                )
                fired += 1

            if cv < BEACON_VARIANCE_RATIO_SUSPECT:
                evidences.append(
                    self._make_evidence("beacon_cv", round(cv, 3), BEACON_VARIANCE_RATIO_SUSPECT)
                )
                fired += 1

            raw_score = 0.3 + (0.5 * (1 - min(cv / BEACON_VARIANCE_RATIO_SUSPECT, 1)))
            if avg_size < BEACON_AVG_PKT_SIZE_MAX / 2:
                raw_score += 0.1
            if cv < BEACON_VARIANCE_RATIO_HIGH:
                raw_score += 0.2
            raw_score = min(raw_score, 1.0)

            risk = self._compute_risk_score(raw_score)
            src_ip = str(flow.src_ip)
            dst_ip = str(flow.dst_ip)
            src_addr = IPv4Address(src_ip) if "." in src_ip else IPv6Address(src_ip)

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
                    affected_entities=[src_ip, dst_ip],
                    timestamp_start=flow.start_time,
                    timestamp_end=flow.end_time,
                    raw_score=raw_score,
                    title=f"Beaconing {src_ip} → {dst_ip}",
                    description=self.description,
                    recommendation="Investigate periodic outbound connections for C2 beaconing or telemetry exfiltration",
                    feature_snapshot={
                        "pkt_count": pkt_count,
                        "avg_size": round(avg_size, 1),
                        "cv": round(cv, 4),
                        "interval_ms": round(mean, 1),
                        "interval_variance_ms": round(variance, 1),
                    },
                )
            )

        return findings
