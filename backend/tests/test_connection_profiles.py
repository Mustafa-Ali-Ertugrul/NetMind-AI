"""Tests for ConnectionProfileBuilder."""

from ipaddress import IPv4Address

import pytest

from backend.feature_extractor.connection_profiles import ConnectionProfileBuilder

from .fixtures import make_parsed_packet

TEST_PCAP = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


class TestConnectionProfileBuilder:
    """Tests for per-IP connection profile aggregation."""

    def test_empty(self):
        """Should return empty list with no packets."""
        cpb = ConnectionProfileBuilder()
        profiles = cpb.finalize()
        assert profiles == []

    def test_single_ip(self):
        """One source IP should produce one profile."""
        pkt = make_parsed_packet(pcap_id=TEST_PCAP)
        cpb = ConnectionProfileBuilder()
        cpb.add_packet(pkt)
        profiles = cpb.finalize()
        assert len(profiles) == 1
        assert profiles[0].src_ip == IPv4Address("10.0.0.1")

    def test_multiple_ips(self):
        """Multiple source IPs produce multiple profiles."""
        pkt1 = make_parsed_packet(pcap_id=TEST_PCAP, src_ip="10.0.0.1", dst_ip="10.0.0.2")
        pkt2 = make_parsed_packet(pcap_id=TEST_PCAP, src_ip="10.0.0.3", dst_ip="10.0.0.4")
        cpb = ConnectionProfileBuilder()
        cpb.add_packet(pkt1)
        cpb.add_packet(pkt2)
        profiles = cpb.finalize()
        assert len(profiles) == 2

    def test_unique_dst_ips(self):
        """Should count unique destination IPs."""
        pkt1 = make_parsed_packet(pcap_id=TEST_PCAP, dst_ip="10.0.0.2")
        pkt2 = make_parsed_packet(pcap_id=TEST_PCAP, dst_ip="10.0.0.3")
        cpb = ConnectionProfileBuilder()
        cpb.add_packet(pkt1)
        cpb.add_packet(pkt2)
        profiles = cpb.finalize()
        assert profiles[0].unique_dst_ips == 2

    def test_unique_dst_ports(self):
        """Should count unique destination ports."""
        pkt1 = make_parsed_packet(pcap_id=TEST_PCAP, dst_port=80)
        pkt2 = make_parsed_packet(pcap_id=TEST_PCAP, dst_port=443)
        cpb = ConnectionProfileBuilder()
        cpb.add_packet(pkt1)
        cpb.add_packet(pkt2)
        profiles = cpb.finalize()
        assert profiles[0].unique_dst_ports == 2

    def test_total_bytes_and_packets(self):
        """Should correctly sum bytes and packets."""
        pkt1 = make_parsed_packet(pcap_id=TEST_PCAP, length=150)
        pkt2 = make_parsed_packet(pcap_id=TEST_PCAP, length=250)
        cpb = ConnectionProfileBuilder()
        cpb.add_packet(pkt1)
        cpb.add_packet(pkt2)
        profiles = cpb.finalize()
        assert profiles[0].total_packets_sent == 2
        assert profiles[0].total_bytes_sent == 400

    def test_distinct_protocols(self):
        """Should track distinct protocol values."""
        pkt1 = make_parsed_packet(pcap_id=TEST_PCAP)  # TCP
        pkt2 = make_parsed_packet(pcap_id=TEST_PCAP, protocol="UDP", src_port=1000, dst_port=53)
        pkt3 = make_parsed_packet(pcap_id=TEST_PCAP, protocol="ICMP", src_port=None, dst_port=None)
        cpb = ConnectionProfileBuilder()
        cpb.add_packet(pkt1)
        cpb.add_packet(pkt2)
        cpb.add_packet(pkt3)
        profiles = cpb.finalize()
        assert "TCP" in profiles[0].distinct_protocols
        assert "UDP" in profiles[0].distinct_protocols
        assert "ICMP" in profiles[0].distinct_protocols

    def test_port_scan_flag_triggered(self):
        """High distinct ports to one dst should set port_scan_suspect."""
        cpb = ConnectionProfileBuilder()
        # 25 distinct ports to the same dst
        for port in range(1, 26):
            pkt = make_parsed_packet(
                pcap_id=TEST_PCAP,
                dst_ip="10.0.0.2",
                dst_port=port,
            )
            cpb.add_packet(pkt)
        profiles = cpb.finalize()
        assert len(profiles) == 1
        assert profiles[0].port_scan_suspect is True
        assert profiles[0].unique_dst_ports_per_host >= 25

    def test_port_scan_flag_not_triggered(self):
        """Few distinct ports should NOT set port_scan_suspect."""
        cpb = ConnectionProfileBuilder()
        for port in [80, 443, 22]:
            pkt = make_parsed_packet(
                pcap_id=TEST_PCAP,
                dst_ip="10.0.0.2",
                dst_port=port,
            )
            cpb.add_packet(pkt)
        profiles = cpb.finalize()
        assert profiles[0].port_scan_suspect is False

    def test_failed_connection_ratio(self):
        """Should compute failed_connection_ratio from added flows."""
        cpb = ConnectionProfileBuilder()
        pkt = make_parsed_packet(pcap_id=TEST_PCAP)
        cpb.add_packet(pkt)

        # Mock a flow with is_failed_flow = True
        class FakeFailedFlow:
            is_failed_flow = True
            src_ip = IPv4Address("10.0.0.1")

        cpb.add_flow(FakeFailedFlow.src_ip, FakeFailedFlow())

        profiles = cpb.finalize()
        assert profiles[0].total_connections == 1
        assert profiles[0].failed_connections == 1
        assert profiles[0].failed_connection_ratio == 1.0

    def test_zero_connections_ratio(self):
        """When no flows, failed_connection_ratio should be 0.0."""
        cpb = ConnectionProfileBuilder()
        pkt = make_parsed_packet(pcap_id=TEST_PCAP)
        cpb.add_packet(pkt)
        profiles = cpb.finalize()
        assert profiles[0].failed_connection_ratio == 0.0

    def test_connections_per_minute(self):
        """Should compute connections per minute from flows and duration."""
        cpb = ConnectionProfileBuilder()
        # 2 packets 30 seconds apart = 0.5 minute duration
        pkt1 = make_parsed_packet(
            pcap_id=TEST_PCAP,
            packet_number=1,
            timestamp="2024-01-01T00:00:00+00:00",
        )
        pkt2 = make_parsed_packet(
            pcap_id=TEST_PCAP,
            packet_number=2,
            timestamp="2024-01-01T00:00:30+00:00",
        )
        cpb.add_packet(pkt1)
        cpb.add_packet(pkt2)

        # Mock 3 flows
        class FakeFlow:
            def __init__(self, is_failed):
                self.is_failed_flow = is_failed
                self.src_ip = IPv4Address("10.0.0.1")

        cpb.add_flow(FakeFlow(False).src_ip, FakeFlow(False))
        cpb.add_flow(FakeFlow(False).src_ip, FakeFlow(False))
        cpb.add_flow(FakeFlow(True).src_ip, FakeFlow(True))

        profiles = cpb.finalize()
        # 3 connections in 0.5 minutes = 6.0 connections/min
        assert profiles[0].connections_per_minute == pytest.approx(6.0, rel=0.1)
        assert profiles[0].total_connections == 3
