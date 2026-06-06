"""Persist Flow features to the flows table.

Bridges the Pydantic ``FlowRecord`` contract from the FeatureExtractor
layer into the SQLAlchemy ``Flow`` model.  Uses batched insert for
efficiency on large captures.
"""

from __future__ import annotations

import logging
from uuid import UUID

from sqlalchemy.orm import Session

from backend.contracts.features import AggregatedFeatures, FlowRecord
from backend.storage.models import Flow

logger = logging.getLogger("netmind.storage.flows")


def _to_db_flow(pcap_id: UUID, record: FlowRecord) -> Flow:
    """Map a single FlowRecord to an ORM Flow row."""
    return Flow(
        pcap_id=pcap_id,
        src_ip=record.src_ip,
        dst_ip=record.dst_ip,
        src_port=record.src_port if record.src_port else None,
        dst_port=record.dst_port if record.dst_port else None,
        protocol=record.protocol.upper(),
        bytes_sent=record.src_bytes,
        bytes_recv=record.dst_bytes,
        packets_count=record.packets_total,
        start_time=record.start_time,
        end_time=record.end_time,
        duration_ms=record.duration_ms,
        inter_packet_interval_ms=record.inter_packet_interval_ms or None,
        inter_packet_interval_variance_ms=record.inter_packet_interval_variance_ms or None,
        ack_count=record.ack_count,
    )


def write_flows_from_features(
    db: Session,
    *,
    pcap_id: UUID,
    features: AggregatedFeatures,
    batch_size: int = 1000,
) -> int:
    """Persist FlowBuilder output to the ``flows`` table.

    Args:
        db: Active sync SQLAlchemy session.
        pcap_id: The PcapFile these flows belong to.
        features: Output of ``FeatureExtractor.extract()``.
        batch_size: Number of rows to insert per batch.  Default 1000.

    Returns:
        Number of Flow rows written.
    """
    if not features.flows:
        logger.info("No flows to persist for pcap %s", pcap_id)
        return 0

    total = 0
    batch: list[Flow] = []
    for record in features.flows:
        batch.append(_to_db_flow(pcap_id, record))
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
        "Persisted %d flow(s) for pcap %s",
        total,
        pcap_id,
    )
    return total
