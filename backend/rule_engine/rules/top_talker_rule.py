"""NET-008 — Top Talker Detection Rule.

Flags individual flows that consume an outsized share of total traffic.
"""

from ipaddress import IPv4Address, IPv6Address

from backend.contracts.enums import Confidence, Severity
from backend.contracts.features import AggregatedFeatures
from backend.contracts.findings import Evidence, Finding
from backend.rule_engine.base_rule import BaseDetectionRule
from backend.rule_engine.thresholds import (
    TOP_TALKER_BPS_RATIO_HIGH,
    TOP_TALKER_BPS_RATIO_SUSPECT,
    TOP_TALKER_SHARE_OF_TRAFFIC_SUSPECT,
    TOP_TALKER_TOTAL_BYTES_SUSPECT,
)


class TopTalkerRule(BaseDetectionRule):
    """NET-008: Top Talker Detection."""

    rule_id = "NET-008"
    rule_name = "Top Talker"
    description = "Detects flows consuming an outsized share of total traffic"

    def _evaluate(self, features: AggregatedFeatures) -> list[Finding]:
        findings: list[Finding] = []
        total_bytes = max(features.traffic_baseline.total_bytes, 1)
        duration_sec = max(features.traffic_baseline.duration_seconds, 1.0)

        for flow in features.flows:
            share = flow.bytes_total / total_bytes
            bps = flow.bytes_total / duration_sec
            src_ip = str(flow.src_ip)
            dst_ip = str(flow.dst_ip)

            if share < TOP_TALKER_SHARE_OF_TRAFFIC_SUSPECT:
                continue

            evidences: list[Evidence] = []
            fired = 0
            total = 3

            if share >= TOP_TALKER_SHARE_OF_TRAFFIC_SUSPECT:
                evidences.append(
                    self._make_evidence(
                        "traffic_share", round(share, 3), TOP_TALKER_SHARE_OF_TRAFFIC_SUSPECT
                    )
                )
                fired += 1

            if flow.bytes_total >= TOP_TALKER_TOTAL_BYTES_SUSPECT:
                evidences.append(
                    self._make_evidence(
                        "total_bytes", flow.bytes_total, TOP_TALKER_TOTAL_BYTES_SUSPECT, unit="B"
                    )
                )
                fired += 1

            if bps >= TOP_TALKER_BPS_RATIO_SUSPECT:
                evidences.append(
                    self._make_evidence(
                        "bytes_per_sec", round(bps, 1), TOP_TALKER_BPS_RATIO_SUSPECT, unit="B/s"
                    )
                )
                fired += 1

            raw_score = min(0.4 + (share * 0.6), 1.0)
            if bps >= TOP_TALKER_BPS_RATIO_HIGH:
                raw_score = min(raw_score + 0.2, 1.0)

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
                    title=f"Top Talker: {src_ip} → {dst_ip}",
                    description=self.description,
                    recommendation="Investigate source IP for data exfiltration or misconfigured application",
                    feature_snapshot={
                        "bytes_total": flow.bytes_total,
                        "traffic_share": round(share, 4),
                        "bytes_per_sec": round(bps, 1),
                        "packets_total": flow.packets_total,
                    },
                )
            )

        return findings
