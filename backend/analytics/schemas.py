"""Shared analytics schemas — typed results for all aggregators."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TopTalkerItem(BaseModel):
    """A single item in a top-talkers list."""

    key: str
    packets: int
    bytes: int


class TopTalkersResult(BaseModel):
    """Aggregate of all top-talker dimensions for one PCAP."""

    src_ips: list[TopTalkerItem] = Field(default_factory=list)
    dst_ips: list[TopTalkerItem] = Field(default_factory=list)
    dst_ports: list[TopTalkerItem] = Field(default_factory=list)
    protocols: list[TopTalkerItem] = Field(default_factory=list)


class TimelineBucket(BaseModel):
    """One time-slice in a traffic timeline."""

    bucket_start: str  # ISO timestamp
    packets: int
    bytes: int
    flows: int


class TimelineResult(BaseModel):
    """Traffic timeline for a PCAP."""

    buckets: list[TimelineBucket] = Field(default_factory=list)
    bucket_duration_seconds: int


class ProtocolStat(BaseModel):
    """One protocol slice in a distribution."""

    protocol: str
    packets: int
    bytes: int
    percentage: float


class ProtocolDistributionResult(BaseModel):
    """Protocol distribution for a PCAP."""

    protocols: list[ProtocolStat] = Field(default_factory=list)


class HeatmapCell(BaseModel):
    """One cell in an IP-vs-hour matrix."""

    ip: str
    hour: int  # 0-23
    packets: int
    bytes: int


class HeatmapResult(BaseModel):
    """Traffic heatmap for a PCAP."""

    cells: list[HeatmapCell] = Field(default_factory=list)


class TopIPGlobalItem(BaseModel):
    """One IP in the global top-IP list (dashboard widget)."""

    ip: str
    total_bytes: int
    total_packets: int
    pcap_count: int


class TopIPGlobalResult(BaseModel):
    """Global top-IP aggregation across all PCAPs."""

    items: list[TopIPGlobalItem] = Field(default_factory=list)
