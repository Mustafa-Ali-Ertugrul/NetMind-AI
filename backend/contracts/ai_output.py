"""AI Assessor -> Storage / API contract."""

from datetime import datetime

from pydantic import BaseModel, Field


class AIFinding(BaseModel):
    """Finding as represented in AI output (simplified)."""

    severity: str
    title: str
    evidence_summary: str | None = None


class FindingRationale(BaseModel):
    """LLM explanation for a single finding."""

    finding_id: str
    explanation: str
    confidence_qualifier: str  # "high" | "medium" | "low"
    false_positive_likelihood: float  # 0.0–1.0


class RemediationStep(BaseModel):
    """Actionable remediation for detected issues."""

    priority: int  # 1–5 (1 = highest)
    action: str
    reason: str
    reference: str | None = None


class AIAssessment(BaseModel):
    """LLM-enriched assessment of rule engine results."""

    executive_summary: str
    finding_rationales: list[FindingRationale]
    remediation_steps: list[RemediationStep]
    provider: str
    model: str
    generation_time_ms: int
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    fallback_used: bool = False


class SecurityReport(BaseModel):
    """Output from the AI Assessor."""

    risk_score: int
    risk_label: str
    executive_summary: str
    key_findings: list[AIFinding]
    recommendations: list[str]
    model_confidence: float
    technical_context: str | None = None

    model_name: str
    model_version: str | None = None
    generation_time_ms: int
    prompt_token_count: int
    generated_at: datetime = Field(default_factory=datetime.utcnow)

    ai_assessment: AIAssessment | None = None
