"""Rule Engine -> AI Assessor / DB / API contract."""

from datetime import datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from .enums import Confidence, RiskLabel, Severity


class Evidence(BaseModel):
    """Specific feature values that triggered a rule."""

    key: str
    value: float | int | str
    threshold: float | int | str
    unit: str | None = None


class Finding(BaseModel):
    """A single detection result from a rule."""

    id: UUID = Field(default_factory=uuid4)
    pcap_id: UUID

    rule_id: str
    rule_name: str
    rule_version: str

    severity: Severity
    confidence: Confidence
    risk_score: int

    title: str
    description: str
    recommendation: str

    evidences: list[Evidence] = Field(default_factory=list)
    affected_entities: list[str] = Field(default_factory=list)

    timestamp_start: datetime
    timestamp_end: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)

    raw_score: float
    feature_snapshot: dict[str, float] = Field(default_factory=dict)


class OverallRiskScore(BaseModel):
    """Aggregated risk score for the entire analysis."""

    max_score: int
    weighted_score: int
    severity_label: RiskLabel
    total_findings: int
    findings_by_severity: dict[str, int]
    top_finding_ids: list[UUID]
    failed_rules: list[str] = Field(default_factory=list)
