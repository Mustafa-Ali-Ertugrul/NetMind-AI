"""FeatureExtractor orchestrator: converts ParsedProtocols to AggregatedFeatures.

Single-pass orchestration:
    1. FlowBuilder aggregates packets into flows
    2. ConnectionProfileBuilder builds per-IP profiles
    3. DNSProfileBuilder builds per-domain analysis
    4. HTTPSummaryBuilder builds HTTP aggregates
    5. FTPSummaryBuilder builds per-IP FTP summaries
    6. SMTPSummaryBuilder builds per-IP SMTP summaries
    7. TrafficBaselineComputer computes baseline + deviations
    8. Assembler produces the final AggregatedFeatures
"""

import time
from datetime import datetime, timezone
from typing import Any

from backend.contracts.features import AggregatedFeatures
from backend.contracts.parser_output import ParsedProtocols

from .constants import EXTRACTOR_VERSION
from .flow_builder import FlowBuilder
from .connection_profiles import ConnectionProfileBuilder
from .dns_profiles import DNSProfileBuilder
from .http_summary import HTTPSummaryBuilder
from .ftp_summary import FTPSummaryBuilder
from .smtp_summary import SMTPSummaryBuilder
from .traffic_baseline import TrafficBaselineComputer


class FeatureExtractor:
    """Orchestrates feature extraction from parsed protocol data.

    Typical usage:
        extractor = FeatureExtractor()
        features = extractor.extract(parsed_protocols)
    """

    def extract(self, parsed: ParsedProtocols) -> AggregatedFeatures:
        """Convert ParsedProtocols into AggregatedFeatures.

        Args:
            parsed: Output of the ProtocolParser stage.

        Returns:
            AggregatedFeatures ready for Rule Engine consumption.
        """
        start_time = time.monotonic()

        pcap_id = parsed.pcap_id
        pkt_count = len(parsed.packets)

        # 1. Time window from packets
        timestamps = [p.timestamp for p in parsed.packets if p.timestamp is not None]
        if timestamps:
            time_window_start = min(timestamps)
            time_window_end = max(timestamps)
            capture_duration = (time_window_end - time_window_start).total_seconds()
        else:
            now = datetime.now(timezone.utc)
            time_window_start = now
            time_window_end = now
            capture_duration = 0.0

        # 2. Build flows from packets
        flow_builder = FlowBuilder()
        for pkt in parsed.packets:
            flow_builder.add_packet(pkt)
        flows = flow_builder.finalize()

        # 3. Build connection profiles (from packets + flows)
        profile_builder = ConnectionProfileBuilder()
        for pkt in parsed.packets:
            profile_builder.add_packet(pkt)
        # Register flows for failure counting (pass flow objects)
        for flow in flows:
            profile_builder.add_flow(flow.src_ip, flow)
        connection_profiles = profile_builder.finalize()

        # 4. Build DNS profiles
        dns_builder = DNSProfileBuilder()
        for dns in parsed.dns_queries:
            dns_builder.add_query(dns)
        dns_profiles = dns_builder.finalize()

        # 5. Build HTTP summary
        http_builder = HTTPSummaryBuilder()
        for http in parsed.http_requests:
            http_builder.add_request(http)
        http_summary = http_builder.finalize()

        # 6. Build FTP summaries
        ftp_builder = FTPSummaryBuilder()
        for ftp in parsed.ftp_sessions:
            ftp_builder.add_ftp(ftp)
        ftp_flows = ftp_builder.finalize()

        # 7. Build SMTP summaries
        smtp_builder = SMTPSummaryBuilder()
        for smtp in parsed.smtp_messages:
            smtp_builder.add_smtp(smtp)
        smtp_flows = smtp_builder.finalize()

        # 8. Compute traffic baseline + deviations
        baseline_computer = TrafficBaselineComputer()
        traffic_baseline = baseline_computer.compute_baseline(parsed.packets, flows)
        traffic_deviations = baseline_computer.compute_deviations(flows, traffic_baseline)

        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        return AggregatedFeatures(
            pcap_id=pcap_id,
            capture_duration_seconds=round(capture_duration, 4),
            time_window_start=time_window_start,
            time_window_end=time_window_end,
            traffic_baseline=traffic_baseline,
            traffic_deviations=traffic_deviations,
            connection_profiles=connection_profiles,
            flows=flows,
            dns_profiles=dns_profiles,
            ftp_flows=ftp_flows,
            smtp_flows=smtp_flows,
            http_method_counts=http_summary["http_method_counts"],
            http_status_counts=http_summary["http_status_counts"],
            http_top_uris=http_summary["http_top_uris"],
            http_user_agents=http_summary["http_user_agents"],
            extractor_version=EXTRACTOR_VERSION,
            extraction_duration_ms=elapsed_ms,
        )


def extract_features(parsed: ParsedProtocols) -> AggregatedFeatures:
    """Convenience function: create extractor and run in one call.

    Args:
        parsed: ParsedProtocols from the parser stage.

    Returns:
        AggregatedFeatures ready for Rule Engine.
    """
    return FeatureExtractor().extract(parsed)
