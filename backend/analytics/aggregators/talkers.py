"""Top-talker aggregator — per-PCAP top-N src/dst IP, port, protocol."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.analytics.base import BaseAggregator
from backend.analytics.schemas import TopTalkerItem, TopTalkersResult
from backend.storage.models import Flow


class TopTalkerAggregator(BaseAggregator):
    """Aggregate top talkers for a single PCAP."""

    def aggregate(
        self,
        db: Session,
        pcap_id: UUID,
        limit: int = 10,
    ) -> TopTalkersResult:
        """Return top-N src IPs, dst IPs, dst ports, and protocols.

        Args:
            db: Active SQLAlchemy session.
            pcap_id: UUID of the PCAP to analyse.
            limit: Number of top items per dimension (default 10).
        """
        # Top src IPs
        src_rows = db.execute(
            select(
                Flow.src_ip,
                func.sum(Flow.packets_count).label("packets"),
                (func.sum(Flow.bytes_sent) + func.sum(Flow.bytes_recv)).label("bytes"),
            )
            .where(Flow.pcap_id == pcap_id)
            .group_by(Flow.src_ip)
            .order_by((func.sum(Flow.bytes_sent) + func.sum(Flow.bytes_recv)).desc())
            .limit(limit)
        ).all()

        # Top dst IPs
        dst_rows = db.execute(
            select(
                Flow.dst_ip,
                func.sum(Flow.packets_count).label("packets"),
                (func.sum(Flow.bytes_sent) + func.sum(Flow.bytes_recv)).label("bytes"),
            )
            .where(Flow.pcap_id == pcap_id)
            .group_by(Flow.dst_ip)
            .order_by((func.sum(Flow.bytes_sent) + func.sum(Flow.bytes_recv)).desc())
            .limit(limit)
        ).all()

        # Top dst ports (exclude None/0)
        port_rows = db.execute(
            select(
                Flow.dst_port,
                func.sum(Flow.packets_count).label("packets"),
                (func.sum(Flow.bytes_sent) + func.sum(Flow.bytes_recv)).label("bytes"),
            )
            .where(Flow.pcap_id == pcap_id, Flow.dst_port.isnot(None))
            .group_by(Flow.dst_port)
            .order_by((func.sum(Flow.bytes_sent) + func.sum(Flow.bytes_recv)).desc())
            .limit(limit)
        ).all()

        # Top protocols
        proto_rows = db.execute(
            select(
                Flow.protocol,
                func.sum(Flow.packets_count).label("packets"),
                (func.sum(Flow.bytes_sent) + func.sum(Flow.bytes_recv)).label("bytes"),
            )
            .where(Flow.pcap_id == pcap_id)
            .group_by(Flow.protocol)
            .order_by((func.sum(Flow.bytes_sent) + func.sum(Flow.bytes_recv)).desc())
            .limit(limit)
        ).all()

        return TopTalkersResult(
            src_ips=[
                TopTalkerItem(key=str(r.src_ip), packets=r.packets, bytes=r.bytes) for r in src_rows
            ],
            dst_ips=[
                TopTalkerItem(key=str(r.dst_ip), packets=r.packets, bytes=r.bytes) for r in dst_rows
            ],
            dst_ports=[
                TopTalkerItem(
                    key=str(r.dst_port) if r.dst_port else "0",
                    packets=r.packets,
                    bytes=r.bytes,
                )
                for r in port_rows
            ],
            protocols=[
                TopTalkerItem(key=r.protocol, packets=r.packets, bytes=r.bytes) for r in proto_rows
            ],
        )
