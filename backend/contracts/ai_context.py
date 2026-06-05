"""Rule Engine -> AI Assessor context contract."""

from pydantic import BaseModel


class CaptureInfo(BaseModel):
    """Minimal capture metadata for LLM context."""

    filename: str
    file_size_mb: float
    duration_seconds: float
    total_packets: int
    total_bytes: int
    unique_ips: int


class ProtocolSummary(BaseModel):
    """Top-N protocol distribution for LLM context."""

    top_protocols: list[dict]
    top_talkers: list[dict]
    total_domains_queried: int
    total_http_requests: int


class AIContext(BaseModel):
    """Complete context sent to the AI Assessor."""

    capture_info: CaptureInfo
    protocol_summary: ProtocolSummary
    findings: list[dict]
    overall_risk: dict
    feature_summary: dict
