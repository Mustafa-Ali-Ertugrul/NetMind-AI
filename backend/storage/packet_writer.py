"""Persist parsed packets to the packets table.

Bridges the Pydantic ``ParsedPacket`` contract from the ProtocolParser
layer into the SQLAlchemy ``Packet`` model.  Uses batched insert for
efficiency on large captures.
"""

from __future__ import annotations

import logging
from uuid import UUID

from sqlalchemy.orm import Session

from backend.contracts.parser_output import ParsedProtocols
from backend.storage.models import Packet

logger = logging.getLogger("netmind.storage.packets")


def write_packets(
    db: Session,
    *,
    pcap_id: UUID,
    parsed: ParsedProtocols,
    batch_size: int = 5000,
) -> int:
    """Bulk insert parsed packets into the ``packets`` table.

    Args:
        db: Active sync SQLAlchemy session.
        pcap_id: The PcapFile these packets belong to.
        parsed: Output of ``ProtocolParser.parse_pcap()``.
        batch_size: Number of rows to insert per batch.  Default 5000.

    Returns:
        Number of Packet rows written.
    """
    if not parsed.packets:
        logger.info("No packets to persist for pcap %s", pcap_id)
        return 0

    total = 0
    batch: list[Packet] = []
    for pkt in parsed.packets:
        batch.append(
            Packet(
                pcap_id=pcap_id,
                packet_number=pkt.packet_number,
                timestamp=pkt.timestamp,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                protocol=pkt.protocol.value.upper(),
                length=pkt.length,
                tcp_flags=pkt.tcp_flags,
                info=pkt.info,
            )
        )
        if len(batch) >= batch_size:
            db.add_all(batch)
            db.flush()
            total += len(batch)
            batch = []

    if batch:
        db.add_all(batch)
        db.flush()
        total += len(batch)

    logger.info(
        "Persisted %d packet(s) for pcap %s",
        total,
        pcap_id,
    )
    return total
