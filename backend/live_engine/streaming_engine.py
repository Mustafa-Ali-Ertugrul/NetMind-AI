"""Streaming Rule Engine: FlowEvent → Findings.

``StreamingRuleEngine`` wraps the batch ``RuleEngine`` and feeds it
with ``AggregatedFeatures`` built incrementally from a stream of
``FlowEvent`` objects.  Every time ``flush()`` is called a fresh
mini-batch of features is computed from the events seen since the
last flush and passed to ``RuleEngine.analyze()``.

Typical usage::

    engine = StreamingRuleEngine()
    engine.process_event(event)
    engine.process_event(event)
    findings, overall = engine.flush()

For periodic auto-flushing see ``live_engine.window.SlidingWindow``
(Step 4).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from backend.contracts.enums import RiskLabel, Severity
from backend.contracts.features import (
    AggregatedFeatures,
    ConnectionProfile,
    FlowRecord,
    TrafficBaseline,
    TrafficDeviation,
)
from backend.contracts.findings import Finding, OverallRiskScore
from backend.contracts.parser_output import ParsedDNS, ParsedHTTP
from backend.feature_extractor import constants as _fx_const
from backend.feature_extractor.dns_profiles import DNSProfileBuilder
from backend.feature_extractor.http_summary import HTTPSummaryBuilder
from backend.ingestion.event import FlowEvent
from backend.ingestion.flow_aggregator import StreamingFlowAggregator
from backend.rule_engine.engine import RuleEngine
from backend.rule_engine.base_rule import BaseDetectionRule
from backend.live_engine.adaptive_threshold import AdaptiveThresholdTracker

if TYPE_CHECKING:
    from backend.storage.live_alert_writer import LiveAlertWriter
    from backend.storage.rule_stats_writer import RuleStatsWriter

logger = logging.getLogger("netmind.live_engine.streaming")


def _compute_baseline_from_flows(
    flows: list[FlowRecord],
    window_duration: float,
) -> TrafficBaseline:
    """Streaming baseline: no per-packet data, compute from flows."""
    total_bytes = sum(f.bytes_total for f in flows)
    total_packets = sum(f.packets_total for f in flows)
    duration = max(window_duration, 0.001)

    src_ips = {str(f.src_ip) for f in flows}
    dst_ips = {str(f.dst_ip) for f in flows}

    proto_counts: dict[str, int] = {}
    for f in flows:
        proto_counts[f.protocol] = proto_counts.get(f.protocol, 0) + f.packets_total
    total = max(sum(proto_counts.values()), 1)
    proto_pcts = {k: round(v / total * 100, 2) for k, v in proto_counts.items()}

    return TrafficBaseline(
        expected_bytes_per_second=round(total_bytes / duration, 2),
        expected_packets_per_second=round(total_packets / duration, 2),
        total_bytes=total_bytes,
        total_packets=total_packets,
        duration_seconds=round(duration, 4),
        unique_src_ips=len(src_ips),
        unique_dst_ips=len(dst_ips),
        protocol_percentages=proto_pcts,
    )


def _compute_deviations_from_flows(
    flows: list[FlowRecord],
    baseline: TrafficBaseline,
) -> list[TrafficDeviation]:
    """Mirror of TrafficBaselineComputer.compute_deviations for flows."""
    if not flows:
        return []

    top_flows = sorted(flows, key=lambda f: f.bytes_total, reverse=True)[
        : _fx_const.TOP_FLOW_DEVIATIONS
    ]
    deviations: list[TrafficDeviation] = []
    expected_bps = max(baseline.expected_bytes_per_second, 0.001)

    for flow in top_flows:
        flow_duration = max(flow.duration_ms / 1000.0, 0.001)
        flow_bps = flow.bytes_total / flow_duration
        flow_pps = flow.packets_total / flow_duration
        pct_exceeded = round(((flow_bps / expected_bps) - 1) * 100, 2)
        is_upload = flow.src_bytes > flow.dst_bytes

        deviations.append(
            TrafficDeviation(
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                bytes_exceeded_pct=pct_exceeded,
                packets_per_second=round(flow_pps, 2),
                bytes_per_second=round(flow_bps, 2),
                is_upload_dominated=is_upload,
            )
        )
    return deviations


def _build_connection_profiles(flows: list[FlowRecord]) -> list[ConnectionProfile]:
    """Build ConnectionProfile list from FlowRecords (streaming mode)."""
    by_src: dict[str, list[FlowRecord]] = defaultdict(list)
    by_pair: dict[tuple[str, str], set[int]] = defaultdict(set)
    protocols_by_src: dict[str, set[str]] = defaultdict(set)

    for flow in flows:
        src_key = str(flow.src_ip)
        by_src[src_key].append(flow)
        pair = (src_key, str(flow.dst_ip))
        if flow.dst_port is not None:
            by_pair[pair].add(flow.dst_port)
        protocols_by_src[src_key].add(flow.protocol)

    profiles: list[ConnectionProfile] = []
    for src_key, src_flows in by_src.items():
        dst_ips = {str(f.dst_ip) for f in src_flows}
        all_ports = {f.dst_port for f in src_flows if f.dst_port is not None}
        total_bytes = sum(f.bytes_total for f in src_flows)
        total_packets = sum(f.packets_total for f in src_flows)

        timestamps = [f.start_time for f in src_flows if f.start_time is not None]
        first_seen = min(timestamps) if timestamps else datetime.now(timezone.utc)
        last_seen = max(timestamps) if timestamps else datetime.now(timezone.utc)

        total_connections = len(src_flows)
        failed_connections = sum(
            1
            for f in src_flows
            if f.rst_count > 0 and f.bytes_total <= _fx_const.FAILURE_PAYLOAD_BYTES_THRESHOLD
        )
        success_connections = max(0, total_connections - failed_connections)
        failed_ratio = failed_connections / total_connections if total_connections > 0 else 0.0

        # Port-scan detection
        max_ports_to_single_dst = 0
        suspect_pairs = 0
        total_pairs = 0
        for pair_key, ports in by_pair.items():
            if pair_key[0] != src_key:
                continue
            total_pairs += 1
            port_count = len(ports)
            if port_count > max_ports_to_single_dst:
                max_ports_to_single_dst = port_count
            if port_count >= _fx_const.PORT_SCAN_PORT_THRESHOLD:
                suspect_pairs += 1

        port_scan_suspect = (
            total_pairs > 0 and suspect_pairs / total_pairs >= _fx_const.PORT_SCAN_RATIO_THRESHOLD
        )

        duration_minutes = max((last_seen - first_seen).total_seconds() / 60.0, 1 / 60.0)
        connections_per_minute = round(total_connections / duration_minutes, 4)

        profiles.append(
            ConnectionProfile(
                src_ip=src_flows[0].src_ip,
                unique_dst_ips=len(dst_ips),
                unique_dst_ports=len(all_ports),
                total_connections=total_connections,
                failed_connections=failed_connections,
                success_connections=success_connections,
                total_bytes_sent=total_bytes,
                total_packets_sent=total_packets,
                first_seen=first_seen,
                last_seen=last_seen,
                distinct_protocols=sorted(protocols_by_src[src_key]),
                failed_connection_ratio=round(failed_ratio, 4),
                port_scan_suspect=port_scan_suspect,
                unique_dst_ports_per_host=max_ports_to_single_dst,
                connections_per_minute=connections_per_minute,
            )
        )

    profiles.sort(key=lambda p: str(p.src_ip))
    return profiles


class _StreamingFeatureBuilder:
    """Incremental AggregatedFeatures builder from FlowEvent stream.

    Wraps the same builders used by batch ``FeatureExtractor`` but
    accepts ``FlowEvent`` (streaming protocol) instead of
    ``ParsedPacket`` / ``ParsedProtocols``.
    """

    def __init__(self, session_id: UUID) -> None:
        self._session_id = session_id
        self._flow_agg = StreamingFlowAggregator()
        self._http_builder = HTTPSummaryBuilder()
        self._dns_builder = DNSProfileBuilder()
        self._start_time: datetime | None = None
        self._end_time: datetime | None = None

    def add_event(self, event: FlowEvent) -> None:
        """Ingest a single FlowEvent."""
        self._flow_agg.add_event(event)

        if self._start_time is None or event.ts < self._start_time:
            self._start_time = event.ts
        if self._end_time is None or event.ts > self._end_time:
            self._end_time = event.ts

        # ----- HTTP ---------------------------------------------------
        if event.http_method:
            self._http_builder.add_request(
                ParsedHTTP(
                    pcap_id=self._session_id,
                    timestamp=event.ts,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    method=event.http_method,
                    host=event.http_host or str(event.dst_ip),
                    uri=event.http_uri or "/",
                    status_code=event.http_status,
                    user_agent=event.http_user_agent,
                )
            )

        # ----- DNS ----------------------------------------------------
        if event.dns_qname:
            self._dns_builder.add_query(
                ParsedDNS(
                    pcap_id=self._session_id,
                    timestamp=event.ts,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    qname=event.dns_qname,
                    qtype=event.dns_qtype or "A",
                )
            )

    def finalize(self) -> AggregatedFeatures:
        """Build AggregatedFeatures from accumulated events and reset."""
        flows = self._flow_agg.flush()

        # Streaming-aware connection profiles
        connection_profiles = _build_connection_profiles(flows)

        # HTTP / DNS
        http_summary = self._http_builder.finalize()
        dns_profiles = self._dns_builder.finalize()

        # Baseline & deviations
        window_duration = 0.0
        if self._start_time and self._end_time:
            window_duration = (self._end_time - self._start_time).total_seconds()
        baseline = _compute_baseline_from_flows(flows, window_duration)
        deviations = _compute_deviations_from_flows(flows, baseline)

        now = datetime.utcnow()
        return AggregatedFeatures(
            pcap_id=self._session_id,
            capture_duration_seconds=round(window_duration, 4),
            time_window_start=self._start_time or now,
            time_window_end=self._end_time or now,
            traffic_baseline=baseline,
            traffic_deviations=deviations,
            connection_profiles=connection_profiles,
            flows=flows,
            dns_profiles=dns_profiles,
            ftp_flows=[],
            smtp_flows=[],
            http_method_counts=http_summary.get("http_method_counts", {}),
            http_status_counts={
                int(k): v for k, v in http_summary.get("http_status_counts", {}).items()
            },
            http_top_uris=http_summary.get("http_top_uris", []),
            http_user_agents=http_summary.get("http_user_agents", []),
            extractor_version="streaming-1.0.0",
            extraction_duration_ms=0,
        )


class StreamingRuleEngine:
    """Real-time engine: accumulate FlowEvents, emit findings on flush.

    ``analyze()`` is **not** overridden — this class only adds the
    streaming surface.  Backward compatibility is guaranteed because
    ``RuleEngine.analyze()`` remains untouched.
    """

    def __init__(
        self,
        rule_engine: RuleEngine | None = None,
        session_id: UUID | None = None,
        alert_writer: LiveAlertWriter | None = None,
        stats_writer: RuleStatsWriter | None = None,
        adaptive: AdaptiveThresholdTracker | None = None,
    ) -> None:
        self._session_id = session_id or uuid4()
        self._rule_engine = rule_engine or RuleEngine()
        self._feature_builder = _StreamingFeatureBuilder(self._session_id)
        self._alert_writer = alert_writer
        self._stats_writer = stats_writer
        self._adaptive = adaptive
        self._alerts_generated = 0

    @property
    def session_id(self) -> UUID:
        return self._session_id

    @property
    def rule_engine(self) -> RuleEngine:
        return self._rule_engine

    @property
    def alerts_generated(self) -> int:
        return self._alerts_generated

    def process_event(self, event: FlowEvent) -> None:
        """Feed a single event into the engine (non-blocking)."""
        self._feature_builder.add_event(event)

    def flush(self) -> tuple[list[Finding], OverallRiskScore]:
        """Finalize current micro-batch and run all rules.

        Returns ``(findings, overall_risk_score)`` exactly like
        ``RuleEngine.analyze()``.
        """
        features = self._feature_builder.finalize()
        findings, overall = self._rule_engine.analyze(features)

        # ── Adaptive threshold calibration ────────────────────────────
        if self._adaptive is not None:
            # Pass 1: adapt scores using baselines built from previous windows
            for finding in findings:
                original_raw = float(finding.raw_score)
                adapted_raw = float(self._adaptive.adapt(finding.rule_id, original_raw))
                adapted_raw = min(max(adapted_raw, 0.0), 1.0)
                finding.raw_score = adapted_raw
                finding.risk_score = self._compute_risk_score_from_raw(adapted_raw)
                finding.severity = self._risk_score_to_severity(finding.risk_score)

            # Pass 2: record originals so next window does not self-bias
            for finding in findings:
                self._adaptive.record(finding.rule_id, float(finding.raw_score))

            # Recompute overall risk after adaptation
            overall = self._recompute_overall(findings)

        self._alerts_generated += len(findings)

        # ── Alert writer hook (optional) ────────────────────────────
        if self._alert_writer is not None:
            self._alert_writer.write_alerts(findings)

        # ── Rule stats writer hook (optional) ───────────────────────
        if self._stats_writer is not None:
            # Build rule-level outcome lookup from findings
            rule_findings: dict[str, list[float]] = {}
            for finding in findings:
                rule_findings.setdefault(finding.rule_id, []).append(float(finding.risk_score))

            for rule in self._rule_engine.registry.get_all():
                scores = rule_findings.get(rule.rule_id, [])
                triggered = len(scores) > 0
                max_risk = max(scores) if scores else 0.0
                self._stats_writer.record_evaluation(
                    rule.rule_id,
                    triggered=triggered,
                    risk_score=max_risk,
                    session_id=self._session_id,
                )

        return findings, overall

    # ------------------------------------------------------------------
    # Adaptive helpers (mirrors BaseDetectionRule statics)
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_risk_score_from_raw(raw_score: float) -> int:
        if raw_score <= 0.0:
            return 0
        clamped = min(max(raw_score, 0.0), 1.0)
        return min(int(clamped * 100), 100)

    @staticmethod
    def _score_to_label(score: int) -> RiskLabel:
        if score >= 76:
            return RiskLabel.CRITICAL
        if score >= 51:
            return RiskLabel.HIGH
        if score >= 26:
            return RiskLabel.MEDIUM
        if score >= 1:
            return RiskLabel.LOW
        return RiskLabel.INFORMATIONAL

    @staticmethod
    def _risk_score_to_severity(risk_score: int) -> Severity:
        if risk_score >= 76:
            return Severity.CRITICAL
        if risk_score >= 51:
            return Severity.HIGH
        if risk_score >= 26:
            return Severity.MEDIUM
        if risk_score >= 1:
            return Severity.LOW
        return Severity.INFORMATIONAL

    @staticmethod
    def _recompute_overall(findings: list[Finding]) -> OverallRiskScore:
        if not findings:
            return OverallRiskScore(
                max_score=0,
                weighted_score=0,
                severity_label=RiskLabel.INFORMATIONAL,
                total_findings=0,
                findings_by_severity={},
                top_finding_ids=[],
                failed_rules=[],
            )
        max_score = max(f.risk_score for f in findings)
        total_weight = 0
        weighted_sum = 0
        by_severity: dict[str, int] = {}
        for f in findings:
            w = f.severity.value
            total_weight += w
            weighted_sum += f.risk_score * w
            by_severity[f.severity.name] = by_severity.get(f.severity.name, 0) + 1
        weighted_score = weighted_sum // total_weight if total_weight > 0 else 0
        severity_label = StreamingRuleEngine._score_to_label(weighted_score)
        top_finding_ids = sorted(
            (f.id for f in findings),
            key=lambda fid: max((f.risk_score for f in findings if f.id == fid), default=0),
            reverse=True,
        )[:5]
        failed_rules = []
        return OverallRiskScore(
            max_score=max_score,
            weighted_score=weighted_score,
            severity_label=severity_label,
            total_findings=len(findings),
            findings_by_severity=by_severity,
            top_finding_ids=top_finding_ids,
            failed_rules=failed_rules,
        )

    def reset(self) -> None:
        """Reset internal state (useful between sessions or tests)."""
        self._feature_builder = _StreamingFeatureBuilder(self._session_id)
