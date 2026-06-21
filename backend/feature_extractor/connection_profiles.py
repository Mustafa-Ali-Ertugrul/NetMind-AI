"""ConnectionProfile builder: per-source-IP behavioral profiles.

Aggregates packets and flows to compute:
    - unique destination IPs and ports
    - failure/success ratios
    - port-scan suspicion flags
"""

from collections import defaultdict
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address

from backend.contracts.features import ConnectionProfile
from backend.contracts.parser_output import ParsedPacket

from .constants import PORT_SCAN_PORT_THRESHOLD, PORT_SCAN_RATIO_THRESHOLD


class ConnectionProfileBuilder:
    """Build per-source-IP ConnectionProfile from a list of flows and packets."""

    def __init__(self) -> None:
        self._packets_by_src: dict[str, list[ParsedPacket]] = defaultdict(list)
        self._flows_by_src: dict[str, list[tuple]] = defaultdict(list)
        self._dst_ports_by_pair: dict[tuple, set[int]] = defaultdict(set)
        self._protocols_by_src: dict[str, set[str]] = defaultdict(set)

    def add_packet(self, packet: ParsedPacket) -> None:
        """Ingest a parsed packet and accumulate per-IP stats."""
        src_key = str(packet.src_ip)
        self._packets_by_src[src_key].append(packet)
        self._protocols_by_src[src_key].add(packet.protocol.value)
        # Track (src_ip, dst_ip) -> set of dst_ports for port-scan detection
        pair = (src_key, str(packet.dst_ip))
        if packet.dst_port is not None:
            self._dst_ports_by_pair[pair].add(packet.dst_port)

    def add_flow(self, flow_src_ip: IPv4Address | IPv6Address, flow) -> None:
        """Register a flow record for per-IP success/failure counting."""
        src_key = str(flow_src_ip)
        self._flows_by_src[src_key].append(flow)

    def finalize(self) -> list[ConnectionProfile]:
        """Build sorted list of ConnectionProfile from accumulated data."""
        profiles = []
        for src_key, packets in self._packets_by_src.items():
            src_ip = packets[0].src_ip
            # Unique destination IPs
            dst_ips: set[str] = set()
            # Unique destination ports across any dst
            all_ports: set[int] = set()
            # Total bytes sent
            total_bytes = sum(p.length or 0 for p in packets)
            # Timestamps
            timestamps = [p.timestamp for p in packets if p.timestamp is not None]
            first_seen = (
                min(timestamps) if timestamps else datetime.min.replace(tzinfo=UTC)
            )
            last_seen = max(timestamps) if timestamps else datetime.min.replace(tzinfo=UTC)

            for p in packets:
                dst_ips.add(str(p.dst_ip))
                if p.dst_port is not None:
                    all_ports.add(p.dst_port)

            # Connection counts from flow records
            flows = self._flows_by_src.get(src_key, [])
            total_connections = len(flows)
            failed_connections = sum(1 for f in flows if getattr(f, "is_failed_flow", False))
            success_connections = max(0, total_connections - failed_connections)

            # Failed connection ratio
            failed_ratio = 0.0
            if total_connections > 0:
                failed_ratio = failed_connections / total_connections

            # Port-scan detection per (src_ip, dst_ip) pair
            max_ports_to_single_dst = 0
            suspect_pairs = 0
            total_pairs = 0
            for pair_key, ports in self._dst_ports_by_pair.items():
                if pair_key[0] != src_key:
                    continue
                total_pairs += 1
                port_count = len(ports)
                if port_count > max_ports_to_single_dst:
                    max_ports_to_single_dst = port_count
                if port_count >= PORT_SCAN_PORT_THRESHOLD:
                    suspect_pairs += 1

            port_scan_suspect = (
                total_pairs > 0 and suspect_pairs / total_pairs >= PORT_SCAN_RATIO_THRESHOLD
            )

            # Connections per minute
            duration_minutes = max((last_seen - first_seen).total_seconds() / 60.0, 1 / 60.0)
            connections_per_minute = round(total_connections / duration_minutes, 4)

            profiles.append(
                ConnectionProfile(
                    src_ip=src_ip,
                    unique_dst_ips=len(dst_ips),
                    unique_dst_ports=len(all_ports),
                    total_connections=total_connections,
                    failed_connections=failed_connections,
                    success_connections=success_connections,
                    total_bytes_sent=total_bytes,
                    total_packets_sent=len(packets),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    distinct_protocols=sorted(self._protocols_by_src[src_key]),
                    failed_connection_ratio=round(failed_ratio, 4),
                    port_scan_suspect=port_scan_suspect,
                    unique_dst_ports_per_host=max_ports_to_single_dst,
                    connections_per_minute=connections_per_minute,
                )
            )

        profiles.sort(key=lambda p: str(p.src_ip))
        return profiles
