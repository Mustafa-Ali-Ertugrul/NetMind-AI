"""Tests for packet_writer module."""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import IPv4Address
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest

from backend.contracts.enums import Protocol
from backend.contracts.parser_output import ParsedPacket, ParsedProtocols
from backend.storage.models import Packet
from backend.storage.packet_writer import write_packets

TEST_PCAP = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")


def _make_parsed_packet(**kwargs) -> ParsedPacket:
    defaults = dict(
        pcap_id=TEST_PCAP,
        packet_number=1,
        timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        src_ip=IPv4Address("10.0.0.1"),
        dst_ip=IPv4Address("10.0.0.2"),
        src_port=12345,
        dst_port=80,
        protocol=Protocol.TCP,
        length=100,
        tcp_flags="0x010",
        info="Test packet",
    )
    defaults.update(kwargs)
    return ParsedPacket(**defaults)


class TestPacketWriter:
    """Tests for write_packets."""

    def test_empty_packets(self):
        """Should return 0 when no packets exist."""
        db = MagicMock()
        parsed = ParsedProtocols(
            pcap_id=TEST_PCAP,
            packets=[],
            parser_version="test",
            parse_duration_ms=0,
        )
        assert write_packets(db, pcap_id=TEST_PCAP, parsed=parsed) == 0
        db.add_all.assert_not_called()

    def test_single_packet(self):
        """Should insert one Packet row per ParsedPacket."""
        db = MagicMock()
        pkt = _make_parsed_packet()
        parsed = ParsedProtocols(
            pcap_id=TEST_PCAP,
            packets=[pkt],
            parser_version="test",
            parse_duration_ms=0,
        )
        assert write_packets(db, pcap_id=TEST_PCAP, parsed=parsed) == 1
        db.add_all.assert_called_once()
        added = db.add_all.call_args[0][0]
        assert len(added) == 1
        assert isinstance(added[0], Packet)
        assert added[0].pcap_id == TEST_PCAP
        assert added[0].packet_number == 1
        assert added[0].src_ip == IPv4Address("10.0.0.1")
        assert added[0].dst_port == 80
        assert added[0].protocol == "TCP"
        assert added[0].length == 100
        assert added[0].tcp_flags == "0x010"

    def test_batching(self):
        """Should batch inserts when packet count exceeds batch_size."""
        db = MagicMock()
        packets = [_make_parsed_packet(packet_number=i) for i in range(1, 12001)]
        parsed = ParsedProtocols(
            pcap_id=TEST_PCAP,
            packets=packets,
            parser_version="test",
            parse_duration_ms=0,
        )
        assert write_packets(db, pcap_id=TEST_PCAP, parsed=parsed, batch_size=5000) == 12000
        assert db.add_all.call_count == 3
        batches = [c[0][0] for c in db.add_all.call_args_list]
        assert len(batches[0]) == 5000
        assert len(batches[1]) == 5000
        assert len(batches[2]) == 2000

    def test_protocol_uppercase(self):
        """Protocol should be upper-cased before insert."""
        db = MagicMock()
        pkt = _make_parsed_packet(protocol=Protocol.UDP)
        parsed = ParsedProtocols(
            pcap_id=TEST_PCAP,
            packets=[pkt],
            parser_version="test",
            parse_duration_ms=0,
        )
        write_packets(db, pcap_id=TEST_PCAP, parsed=parsed)
        added = db.add_all.call_args[0][0]
        assert added[0].protocol == "UDP"

    def test_nullable_fields(self):
        """Should handle None src_port, dst_port, tcp_flags, info."""
        db = MagicMock()
        pkt = _make_parsed_packet(
            src_port=None,
            dst_port=None,
            tcp_flags=None,
            info=None,
        )
        parsed = ParsedProtocols(
            pcap_id=TEST_PCAP,
            packets=[pkt],
            parser_version="test",
            parse_duration_ms=0,
        )
        write_packets(db, pcap_id=TEST_PCAP, parsed=parsed)
        added = db.add_all.call_args[0][0]
        assert added[0].src_port is None
        assert added[0].dst_port is None
        assert added[0].tcp_flags is None
        assert added[0].info is None
