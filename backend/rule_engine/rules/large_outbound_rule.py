"""NET-011 — Large Outbound Transfer Detection Rule.

Detects single flows exceeding a size threshold to non-RFC1918
destinations — a common data exfiltration / DLP indicator.
"""

from ipaddress import IPv4Address, IPv6Address

from backend.contracts.enums import Confidence
from backend.contracts.features import AggregatedFeatures
from backend.contracts.findings import Finding
from backend.rule_engine.base_rule import BaseDetectionRule
from backend.rule_engine.thresholds import (
    LARGE_OUTBOUND_MIN_BYTES,
    LARGE_OUTBOUND_MIN_DURATION_SEC,
    LARGE_OUTBOUND_SRC_BYTES_RATIO,
)


def _is_rfc1918(addr: IPv4Address | IPv6Address) -> bool:
    """Return True if *addr* is a private / link-local / loopback address."""
    if isinstance(addr, IPv4Address):
        return addr.is_private or addr.is_loopback or addr.is_link_local
    return addr.is_private or addr.is_loopback or addr.is_link_local


class LargeOutboundRule(BaseDetectionRule):
    """NET-011: Large Outbound Transfer Detection."""

    rule_id = "NET-011"
    rule_name = "Large Outbound Transfer"
    description = "Detects large data transfers to external (non-RFC1918) destinations"

    def _evaluate(self, features: AggregatedFeatures) -> list[Finding]:
        findings: list[Finding] = []

        for flow in features.flows:
            duration_sec = flow.duration_ms / 1000.0
            if duration_sec < LARGE_OUTBOUND_MIN_DURATION_SEC:
                continue

            if flow.bytes_total < LARGE_OUTBOUND_MIN_BYTES:
                continue

            dst = flow.dst_ip
            if _is_rfc1918(dst):
                continue

            # Determine direction: outbound means src is internal
            src_is_internal = _is_rfc1918(flow.src_ip)
            if not src_is_internal:
                continue

            upload_ratio = flow.src_bytes / max(flow.bytes_total, 1)
            raw_score = 0.4  # base
            if upload_ratio > LARGE_OUTBOUND_SRC_BYTES_RATIO:
                raw_score += 0.3  # upload-dominated → higher risk
            if flow.dst_port in (80, 443, 8080):
                raw_score += 0.1  # web port
            if flow.protocol.upper() == "TCP":
                raw_score += 0.1
            raw_score = min(raw_score, 1.0)

            risk = self._compute_risk_score(raw_score)
            src_ip = str(flow.src_ip)
            dst_ip = str(flow.dst_ip)

            findings.append(
                Finding(
                    pcap_id=features.pcap_id,
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    rule_version=self.rule_version,
                    severity=self._risk_score_to_severity(risk),
                    confidence=Confidence.HIGH
                    if upload_ratio > LARGE_OUTBOUND_SRC_BYTES_RATIO
                    else Confidence.MEDIUM,
                    risk_score=risk,
                    evidences=[
                        self._make_evidence(
                            "outbound_bytes",
                            flow.bytes_total,
                            LARGE_OUTBOUND_MIN_BYTES,
                            unit="B",
                        ),
                        self._make_evidence(
                            "upload_ratio",
                            round(upload_ratio, 3),
                            LARGE_OUTBOUND_SRC_BYTES_RATIO,
                        ),
                        self._make_evidence(
                            "duration_sec",
                            round(duration_sec, 1),
                            LARGE_OUTBOUND_MIN_DURATION_SEC,
                            unit="s",
                        ),
                    ],
                    affected_entities=[src_ip, dst_ip],
                    timestamp_start=flow.start_time,
                    timestamp_end=flow.end_time,
                    raw_score=raw_score,
                    title=f"Large outbound transfer {src_ip} → {dst_ip}: {flow.bytes_total:,} B",
                    description=self.description,
                    recommendation="Investigate the source host for data exfiltration. "
                    "Review destination IP reputation and block if malicious.",
                    feature_snapshot={
                        "bytes_total": flow.bytes_total,
                        "src_bytes": flow.src_bytes,
                        "upload_ratio": round(upload_ratio, 3),
                        "duration_sec": round(duration_sec, 1),
                        "dst_port": flow.dst_port,
                    },
                )
            )

        return findings
