"""Traffic baseline and deviation computer.

Computes:
    - TrafficBaseline: global per-pcap expected bytes/sec, packets/sec
    - TrafficDeviation: per-flow deviation from baseline for top talkers
"""


from backend.contracts.features import FlowRecord, TrafficBaseline, TrafficDeviation
from backend.contracts.parser_output import ParsedPacket

from .constants import TOP_FLOW_DEVIATIONS


class TrafficBaselineComputer:
    """Compute TrafficBaseline and TrafficDeviation from packets and flows."""

    def compute_baseline(
        self,
        packets: list[ParsedPacket],
        flows: list[FlowRecord],
    ) -> TrafficBaseline:
        """Compute global traffic baseline from all packets."""
        total_packets = len(packets)
        total_bytes = sum(p.length or 0 for p in packets)

        timestamps = [p.timestamp for p in packets if p.timestamp is not None]
        if len(timestamps) < 2:
            duration = 0.0
        else:
            duration = (max(timestamps) - min(timestamps)).total_seconds()
        if duration <= 0:
            duration = 1.0  # avoid division by zero

        bps = total_bytes / duration
        pps = total_packets / duration

        # IP uniqueness
        src_ips: set[str] = set()
        dst_ips: set[str] = set()
        for p in packets:
            src_ips.add(str(p.src_ip))
            dst_ips.add(str(p.dst_ip))

        # Protocol percentages
        proto_counts: dict[str, int] = {}
        for p in packets:
            proto_counts[p.protocol.value] = proto_counts.get(p.protocol.value, 0) + 1
        total = max(sum(proto_counts.values()), 1)
        proto_pcts = {k: round(v / total * 100, 2) for k, v in proto_counts.items()}

        return TrafficBaseline(
            expected_bytes_per_second=round(bps, 2),
            expected_packets_per_second=round(pps, 2),
            total_bytes=total_bytes,
            total_packets=total_packets,
            duration_seconds=round(duration, 4),
            unique_src_ips=len(src_ips),
            unique_dst_ips=len(dst_ips),
            protocol_percentages=proto_pcts,
        )

    def compute_deviations(
        self,
        flows: list[FlowRecord],
        baseline: TrafficBaseline,
    ) -> list[TrafficDeviation]:
        """Compute per-flow deviations for top talkers by bytes."""
        if not flows:
            return []

        # Sort by bytes descending, take top N
        top_flows = sorted(flows, key=lambda f: f.bytes_total, reverse=True)[:TOP_FLOW_DEVIATIONS]

        deviations: list[TrafficDeviation] = []
        for flow in top_flows:
            flow_duration = max(flow.duration_ms / 1000.0, 0.001)
            flow_bps = flow.bytes_total / flow_duration
            flow_pps = flow.packets_total / flow_duration

            expected_bps = max(baseline.expected_bytes_per_second, 0.001)
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
