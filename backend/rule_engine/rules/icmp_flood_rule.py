"""NET-007 — ICMP Flood Detection Rule.

Detects ICMP flood attacks by high packet counts / rates
on ICMP flows.
"""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from backend.contracts.enums import Confidence, Severity
from backend.contracts.features import AggregatedFeatures
from backend.contracts.findings import Evidence, Finding
from backend.rule_engine.base_rule import BaseDetectionRule
from backend.rule_engine.thresholds import (
    ICMP_FLOOD_PPS_HIGH,
    ICMP_FLOOD_PPS_SUSPECT,
    ICMP_FLOOD_TOTAL_PKTS_SUSPECT,
)


class ICMPFloodRule(BaseDetectionRule):
    """NET-007: ICMP Flood Detection."""

    rule_id = "NET-007"
    rule_name = "ICMP Flood"
    description = "Detects ICMP flood attacks by high packet rates or burst volumes"

    def _evaluate(self, features: AggregatedFeatures) -> list[Finding]:
        findings: list[Finding] = []
        for flow in features.flows:
            if flow.protocol.lower() != "icmp":
                continue

            pkt_count = flow.packets_total
            duration_ms = max(flow.duration_ms, 1.0)
            pps = pkt_count / (duration_ms / 1000.0)
            src_ip = str(flow.src_ip)
            dst_ip = str(flow.dst_ip)

            if pkt_count < ICMP_FLOOD_TOTAL_PKTS_SUSPECT and pps < ICMP_FLOOD_PPS_SUSPECT:
                continue

            evidences: list[Evidence] = []
            fired = 0
            total = 2

            if pps >= ICMP_FLOOD_PPS_SUSPECT:
                evidences.append(
                    self._make_evidence(
                        "icmp_pps", round(pps, 1), ICMP_FLOOD_PPS_SUSPECT, unit="pps"
                    )
                )
                fired += 1

            if pkt_count >= ICMP_FLOOD_TOTAL_PKTS_SUSPECT:
                evidences.append(
                    self._make_evidence("icmp_total_pkts", pkt_count, ICMP_FLOOD_TOTAL_PKTS_SUSPECT)
                )
                fired += 1

            raw_score = 0.2 + (0.6 * min(pkt_count / max(ICMP_FLOOD_TOTAL_PKTS_SUSPECT, 1), 1.0))
            if pps >= ICMP_FLOOD_PPS_HIGH:
                raw_score += 0.2

            raw_score = min(raw_score, 1.0)
            risk = self._compute_risk_score(raw_score)

            src_addr = IPv4Address(src_ip) if "." in src_ip else IPv6Address(src_ip)
            dst_addr = IPv4Address(dst_ip) if "." in dst_ip else IPv6Address(dst_ip)

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
                    title=f"ICMP Flood from {src_ip}",
                    description=self.description,
                    recommendation="Block source IP if unsolicited ICMP; enable ICMP rate-limiting on edge routers",
                    feature_snapshot={
                        "total_pkts": pkt_count,
                        "pps": round(pps, 1),
                        "duration_ms": round(duration_ms, 1),
                    },
                )
            )

        return findings
