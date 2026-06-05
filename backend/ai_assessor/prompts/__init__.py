"""Prompt templates for the AI Assessor.

MVP uses a *single LLM call* that receives all findings and the
overall risk score at once, returning a complete assessment JSON.
"""

from backend.ai_assessor.prompts.assess_prompt import build_assessment_prompt

__all__ = [
    "build_assessment_prompt",
]
