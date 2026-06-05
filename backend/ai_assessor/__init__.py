"""NetMind AI Assessor — Phase 4A of the detection pipeline.

Enriches validated Rule Engine findings with LLM-generated
explanations, remediation steps, and an executive summary.

The AIAssessor is a *post-processing layer* that sits on top of
NET-001 through NET-004 results. It never modifies findings or
overall risk scores — only attaches readable context.

Usage::

    from ai_assessor import AIAssessor
    from ai_assessor.config import AssessorConfig

    assessor = AIAssessor(config=AssessorConfig())
    report = assessor.assess(findings, overall)

    # report.ai_assessment will be:
    #   AIAssessment instance    (LLM succeeded)
    #   AIAssessment (fallback)  (LLM down)
    #   None                     (ai disabled via env var)
"""

from backend.ai_assessor.assessor import AIAssessor
from backend.ai_assessor.config import AssessorConfig

__all__ = [
    "AIAssessor",
    "AssessorConfig",
]
