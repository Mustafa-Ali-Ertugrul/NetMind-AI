"""NET-005 — SYN Flood Detection Rule.

Detects TCP SYN floods where a source sends many SYN packets
without completing handshakes (low ACK ratio).
"""

from ipaddress import IPv4Address, IPv6Address

from backend.contracts.enums import Confidence, Severity
from backend.contracts.features import AggregatedFeatures
from backend.contracts.findings import Evidence, Finding
from backend.rule_engine.base_rule import BaseDetectionRule
from backend.rule_engine.thresholds import (
    SYN_FLOOD_ACK_RATIO_MIN,
    SYN_FLOOD_DURATION_MS_MAX,
    SYN_FLOOD_SYN_COUNT_HIGH,
    SYN_FLOOD_SYN_COUNT_SUSPECT,
)


class SYNFloodRule(BaseDetectionRule):
    """NET-005: SYN Flood Detection."""

    rule_id = "NET-005"
    rule_name = "SYN Flood"
    description = "Detects TCP SYN flood attacks by high SYN counts with low ACK ratios"

    def _evaluate(self, features: AggregatedFeatures) -> list[Finding]:
        findings: list[Finding] = []
        for flow in features.flows:
            if flow.protocol.lower() != "tcp":
                continue

            syn_count = flow.syn_count
            ack_count = flow.ack_count
            duration_ms = max(flow.duration_ms, 1.0)
            pkt_count = flow.packets_total
            src_ip = str(flow.src_ip)
            dst_ip = str(flow.dst_ip)

            if syn_count < SYN_FLOOD_SYN_COUNT_SUSPECT:
                continue

            ack_ratio = ack_count / max(syn_count, 1)
            evidences: list[Evidence] = []
            fired = 0
            total = 2  # two indicators: ack_ratio, burst_rate

            if ack_ratio < SYN_FLOOD_ACK_RATIO_MIN:
                evidences.append(
                    self._make_evidence(
                        "syn_ack_ratio", round(ack_ratio, 2), SYN_FLOOD_ACK_RATIO_MIN
                    )
                )
                fired += 1

            if duration_ms < SYN_FLOOD_DURATION_MS_MAX and syn_count >= SYN_FLOOD_SYN_COUNT_HIGH:
                pps = pkt_count / (duration_ms / 1000.0)
                evidences.append(
                    self._make_evidence(
                        "syn_pps", round(pps, 1), SYN_FLOOD_SYN_COUNT_HIGH, unit="pps"
                    )
                )
                fired += 1

            if not evidences:
                continue

            raw_score = 0.3 + (0.5 * (syn_count / max(SYN_FLOOD_SYN_COUNT_HIGH, 1)))
            if ack_ratio < SYN_FLOOD_ACK_RATIO_MIN:
                raw_score += 0.3
            if syn_count >= SYN_FLOOD_SYN_COUNT_HIGH:
                raw_score += 0.2

            raw_score = min(raw_score, 1.0)
            risk = self._compute_risk_score(raw_score)
            confidence = self._compute_confidence(fired, total)

            src_addr = IPv4Address(src_ip) if "." in src_ip else IPv6Address(src_ip)
            dst_addr = IPv4Address(dst_ip) if "." in dst_ip else IPv6Address(dst_ip)

            findings.append(
                Finding(
                    pcap_id=features.pcap_id,
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    rule_version=self.rule_version,
                    severity=self._risk_score_to_severity(risk),
                    confidence=confidence,
                    risk_score=risk,
                    evidences=evidences,
                    affected_entities=[src_ip, dst_ip],
                    timestamp_start=flow.start_time,
                    timestamp_end=flow.end_time,
                    raw_score=raw_score,
                    title=f"SYN Flood from {src_ip}",
                    description=self.description,
                    recommendation="Block source IP or rate-limit TCP SYN packets; enable SYN cookies on edge firewalls",
                    feature_snapshot={
                        "syn_count": syn_count,
                        "ack_count": ack_count,
                        "ack_ratio": round(ack_ratio, 2),
                        "pps": round(pkt_count / (duration_ms / 1000.0), 1),
                    },
                )
            )

        return findings
