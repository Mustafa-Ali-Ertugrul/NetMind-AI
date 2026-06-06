"""Flow Builder: groups packets into bidirectional 5-tuple flows.

Canonical flow key normalizes (src_ip, src_port, dst_ip, dst_port, protocol)
so that A->B and B->A traffic merge into a single bidirectional flow record.
"""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from backend.contracts.parser_output import ParsedPacket
from backend.contracts.enums import Protocol
from backend.contracts.features import FlowRecord

from .constants import FAILURE_PAYLOAD_BYTES_THRESHOLD


def _flow_key(packet: ParsedPacket) -> tuple:
    """Canonical bidirectional 5-tuple key.

    For TCP/UDP: sorts the (ip, port) pairs so src/dst are order-independent.
    For ICMP (no ports): uses a 3-tuple (src_ip, dst_ip, protocol).
    """
    if packet.protocol in (Protocol.TCP, Protocol.UDP):
        a = (packet.src_ip, packet.src_port)
        b = (packet.dst_ip, packet.dst_port)
        left, right = sorted([a, b], key=lambda x: (str(x[0]), x[1] or 0))
        return (left[0], left[1], right[0], right[1], packet.protocol.value)
    return (packet.src_ip, None, packet.dst_ip, None, packet.protocol.value)


class _FlowAccumulator:
    """Mutable per-flow state accumulated across packets."""

    __slots__ = (
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "packets_total",
        "bytes_total",
        "src_bytes",
        "dst_bytes",
        "syn_count",
        "rst_count",
        "ack_count",
        "start_time",
        "end_time",
        "_last_timestamp",
        "_interval_mean",
        "_interval_m2",
        "_interval_count",
    )

    def __init__(self, packet: ParsedPacket) -> None:
        self.src_ip = packet.src_ip
        self.dst_ip = packet.dst_ip
        self.src_port = packet.src_port
        self.dst_port = packet.dst_port
        self.protocol = packet.protocol.value
        self.packets_total = 1
        self.bytes_total = packet.length or 0
        self.src_bytes = packet.length or 0
        self.dst_bytes = 0
        self.syn_count = 0
        self.rst_count = 0
        self.ack_count = 0
        self._update_flags(packet)
        ts = packet.timestamp or datetime.min
        self.start_time = ts
        self.end_time = ts
        self._last_timestamp = ts
        self._interval_mean = 0.0
        self._interval_m2 = 0.0
        self._interval_count = 0

    def add(self, packet: ParsedPacket) -> None:
        """Accumulate one more packet into this flow."""
        self.packets_total += 1
        length = packet.length or 0
        self.bytes_total += length
        if packet.src_ip == self.src_ip and packet.src_port == self.src_port:
            self.src_bytes += length
        else:
            self.dst_bytes += length
        ts = packet.timestamp
        if ts:
            if ts < self.start_time:
                self.start_time = ts
            if ts > self.end_time:
                self.end_time = ts
            if self._last_timestamp and self._last_timestamp != datetime.min:
                interval_ms = (ts - self._last_timestamp).total_seconds() * 1000.0
                self._interval_count += 1
                delta = interval_ms - self._interval_mean
                self._interval_mean += delta / self._interval_count
                delta2 = interval_ms - self._interval_mean
                self._interval_m2 += delta * delta2
            self._last_timestamp = ts
        self._update_flags(packet)

    def _update_flags(self, packet: ParsedPacket) -> None:
        if packet.tcp_flags:
            try:
                bits = int(packet.tcp_flags, 16)
            except (ValueError, TypeError):
                return
            if bits & 0x002:
                self.syn_count += 1
            if bits & 0x004:
                self.rst_count += 1
            if bits & 0x010:
                self.ack_count += 1

    @property
    def duration_ms(self) -> float:
        delta = (self.end_time - self.start_time).total_seconds()
        return delta * 1000.0

    @property
    def is_failed_flow(self) -> bool:
        if self.protocol != Protocol.TCP.value:
            return False
        if self.rst_count > 0 and self.bytes_total <= FAILURE_PAYLOAD_BYTES_THRESHOLD:
            return True
        return False

    def to_flow_record(self) -> FlowRecord:
        if self._interval_count > 0:
            inter_avg = self._interval_mean
            inter_var = (
                self._interval_m2 / (self._interval_count - 1) if self._interval_count > 1 else 0.0
            )
        else:
            inter_avg = (
                self.duration_ms / (self.packets_total - 1) if self.packets_total > 1 else 0.0
            )
            inter_var = 0.0
        return FlowRecord(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port or 0,
            dst_port=self.dst_port or 0,
            protocol=self.protocol,
            packets_total=self.packets_total,
            bytes_total=self.bytes_total,
            duration_ms=self.duration_ms,
            start_time=self.start_time,
            end_time=self.end_time,
            src_bytes=self.src_bytes,
            dst_bytes=self.dst_bytes,
            syn_count=self.syn_count,
            rst_count=self.rst_count,
            ack_count=self.ack_count,
            inter_packet_interval_ms=round(inter_avg, 4),
            inter_packet_interval_variance_ms=round(inter_var, 4),
        )


class FlowBuilder:
    """Accumulates parsed packets into bidirectional flows."""

    def __init__(self) -> None:
        self._flows: dict[tuple, _FlowAccumulator] = {}

    def add_packet(self, packet: ParsedPacket) -> None:
        """Ingest a single parsed packet."""
        if packet.protocol not in (Protocol.TCP, Protocol.UDP, Protocol.ICMP):
            return
        key = _flow_key(packet)
        acc = self._flows.get(key)
        if acc is None:
            self._flows[key] = _FlowAccumulator(packet)
        else:
            acc.add(packet)

    def finalize(self) -> list[FlowRecord]:
        """Return sorted FlowRecord list from all accumulated flows."""
        records = [acc.to_flow_record() for acc in self._flows.values()]
        records.sort(key=lambda r: r.start_time)
        return records

    @property
    def failed_flow_count(self) -> int:
        return sum(1 for acc in self._flows.values() if acc.is_failed_flow)

    @property
    def total_flow_count(self) -> int:
        return len(self._flows)
