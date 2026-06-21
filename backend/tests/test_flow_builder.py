"""Tests for the FlowBuilder."""

from ipaddress import IPv4Address
from uuid import UUID

import pytest

from backend.contracts.enums import Protocol
from backend.feature_extractor.flow_builder import FlowBuilder, _flow_key

from .fixtures import make_parsed_packet

TEST_PCAP = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")


class TestFlowBuilder:
    """Tests for FlowBuilder flow aggregation."""

    def test_empty(self):
        """Should produce no flows for empty input."""
        fb = FlowBuilder()
        flows = fb.finalize()
        assert flows == []

    def test_single_packet(self):
        """A single TCP packet produces one flow."""
        pkt = make_parsed_packet(pcap_id=TEST_PCAP)
        fb = FlowBuilder()
        fb.add_packet(pkt)
        flows = fb.finalize()
        assert len(flows) == 1
        f = flows[0]
        assert f.src_ip == IPv4Address("10.0.0.1")
        assert f.dst_ip == IPv4Address("10.0.0.2")
        assert f.packets_total == 1
        assert f.bytes_total == 100
        assert f.protocol == "TCP"

    def test_bidirectional_merge(self):
        """Packets in both directions merge into one flow record."""
        pkt_a = make_parsed_packet(
            pcap_id=TEST_PCAP,
            packet_number=1,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=80,
            length=100,
            timestamp="2024-01-01T00:00:00+00:00",
        )
        pkt_b = make_parsed_packet(
            pcap_id=TEST_PCAP,
            packet_number=2,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.1",
            src_port=80,
            dst_port=12345,
            length=200,
            timestamp="2024-01-01T00:00:01+00:00",
        )
        fb = FlowBuilder()
        fb.add_packet(pkt_a)
        fb.add_packet(pkt_b)
        flows = fb.finalize()
        assert len(flows) == 1
        f = flows[0]
        assert f.packets_total == 2
        assert f.bytes_total == 300
        assert f.src_bytes == 100
        assert f.dst_bytes == 200
        assert f.duration_ms == 1000.0

    def test_multiple_flows(self):
        """Packets with different 5-tuples produce separate flows."""
        pkt1 = make_parsed_packet(pcap_id=TEST_PCAP, dst_ip="10.0.0.2", dst_port=80)
        pkt2 = make_parsed_packet(pcap_id=TEST_PCAP, dst_ip="10.0.0.3", dst_port=443)
        fb = FlowBuilder()
        fb.add_packet(pkt1)
        fb.add_packet(pkt2)
        assert fb.total_flow_count == 2

    def test_icmp_flow(self):
        """ICMP packets produce a flow with no ports."""
        pkt = make_parsed_packet(
            pcap_id=TEST_PCAP,
            protocol=Protocol.ICMP,
            src_port=None,
            dst_port=None,
        )
        fb = FlowBuilder()
        fb.add_packet(pkt)
        flows = fb.finalize()
        assert len(flows) == 1
        assert flows[0].protocol == "ICMP"
        assert flows[0].src_port == 0
        assert flows[0].dst_port == 0

    def test_syn_count(self):
        """TCP SYN flags increment syn_count."""
        pkt = make_parsed_packet(
            pcap_id=TEST_PCAP,
            tcp_flags="0x002",  # SYN
        )
        fb = FlowBuilder()
        fb.add_packet(pkt)
        flows = fb.finalize()
        assert flows[0].syn_count == 1
        assert flows[0].rst_count == 0

    def test_rst_count(self):
        """TCP RST flags increment rst_count."""
        pkt = make_parsed_packet(
            pcap_id=TEST_PCAP,
            tcp_flags="0x004",  # RST
        )
        fb = FlowBuilder()
        fb.add_packet(pkt)
        flows = fb.finalize()
        assert flows[0].rst_count == 1

    def test_syn_and_rst(self):
        """Multiple flags are counted correctly."""
        pkt1 = make_parsed_packet(
            pcap_id=TEST_PCAP,
            packet_number=1,
            tcp_flags="0x002",  # SYN
        )
        pkt2 = make_parsed_packet(
            pcap_id=TEST_PCAP,
            packet_number=2,
            tcp_flags="0x012",  # SYN-ACK
        )
        pkt3 = make_parsed_packet(
            pcap_id=TEST_PCAP,
            packet_number=3,
            tcp_flags="0x004",  # RST
        )
        fb = FlowBuilder()
        fb.add_packet(pkt1)
        fb.add_packet(pkt2)
        fb.add_packet(pkt3)
        flows = fb.finalize()
        assert flows[0].syn_count == 2
        assert flows[0].rst_count == 1

    def test_failed_flow_detection(self):
        """RST + low bytes = failed flow."""
        pkt_syn = make_parsed_packet(
            pcap_id=TEST_PCAP,
            packet_number=1,
            tcp_flags="0x002",
            length=60,  # SYN
        )
        pkt_rst = make_parsed_packet(
            pcap_id=TEST_PCAP,
            packet_number=2,
            tcp_flags="0x004",
            length=60,  # RST
        )
        fb = FlowBuilder()
        fb.add_packet(pkt_syn)
        fb.add_packet(pkt_rst)
        # Total bytes = 120, below FAILURE_PAYLOAD_BYTES_THRESHOLD (200)
        assert fb.failed_flow_count == 1

    def test_successful_flow(self):
        """No RST or high bytes = not failed."""
        pkt = make_parsed_packet(
            pcap_id=TEST_PCAP,
            tcp_flags="0x010",  # ACK only, no RST
            length=500,  # high bytes
        )
        fb = FlowBuilder()
        fb.add_packet(pkt)
        assert fb.failed_flow_count == 0

    def test_flow_key_symmetry(self):
        """Flow key should be symmetric for A->B and B->A."""
        pkt_a = make_parsed_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1000,
            dst_port=2000,
        )
        pkt_b = make_parsed_packet(
            src_ip="10.0.0.2",
            dst_ip="10.0.0.1",
            src_port=2000,
            dst_port=1000,
        )
        assert _flow_key(pkt_a) == _flow_key(pkt_b)

    def test_udp_no_failure_flag(self):
        """UDP flows are never marked as failed."""
        pkt = make_parsed_packet(
            pcap_id=TEST_PCAP,
            protocol=Protocol.UDP,
            length=50,
        )
        fb = FlowBuilder()
        fb.add_packet(pkt)
        assert fb.failed_flow_count == 0

    def test_duration_single_packet(self):
        """Single packet flow should have 0 ms duration."""
        pkt = make_parsed_packet(pcap_id=TEST_PCAP)
        fb = FlowBuilder()
        fb.add_packet(pkt)
        flows = fb.finalize()
        assert flows[0].duration_ms == 0.0

    def test_inter_packet_interval_multi_packet(self):
        """Multi-packet flow computes average inter-packet interval."""
        pkt1 = make_parsed_packet(
            pcap_id=TEST_PCAP,
            packet_number=1,
            timestamp="2024-01-01T00:00:00+00:00",
        )
        pkt2 = make_parsed_packet(
            pcap_id=TEST_PCAP,
            packet_number=2,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.1",
            src_port=80,
            dst_port=12345,
            timestamp="2024-01-01T00:00:01+00:00",
        )
        fb = FlowBuilder()
        fb.add_packet(pkt1)
        fb.add_packet(pkt2)
        flows = fb.finalize()
        assert len(flows) == 1
        # 2 packets, 2 second gap → avg interval = 1000 ms
        assert flows[0].inter_packet_interval_ms == pytest.approx(1000.0, rel=0.1)

    def test_inter_packet_interval_single_packet(self):
        """Single packet flow should have 0 inter-packet interval."""
        pkt = make_parsed_packet(pcap_id=TEST_PCAP)
        fb = FlowBuilder()
        fb.add_packet(pkt)
        flows = fb.finalize()
        assert flows[0].inter_packet_interval_ms == 0.0

    def test_non_parsed_protocol_skipped(self):
        """Packets with unknown protocol are skipped."""
        pkt = make_parsed_packet(pcap_id=TEST_PCAP)
        # Override to a fake protocol value not in the set
        fb = FlowBuilder()
        fb.add_packet(pkt)  # TCP, should be included
        assert fb.total_flow_count == 1

    def test_info_unavailable(self):
        """FlowBuilder does not crash if timestamp is None."""
        pkt = make_parsed_packet(pcap_id=TEST_PCAP, timestamp=None)
        fb = FlowBuilder()
        fb.add_packet(pkt)
        flows = fb.finalize()
        assert len(flows) == 1
