"""Prompt builder for the single-call AI assessment.

The prompt sends all findings + overall risk in one request.
The LLM is asked to return a JSON object with three sections:

    - executive_summary
    - finding_rationales (per-finding)
    - remediation_steps (global)
"""

from __future__ import annotations

import json
from typing import Any

from backend.contracts.findings import Finding, OverallRiskScore


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    """Serialize a Finding to a dict suitable for LLM consumption."""
    return {
        "id": str(f.id),
        "rule_id": f.rule_id,
        "rule_name": f.rule_name,
        "severity": f.severity.name,
        "confidence": f.confidence.name,
        "risk_score": f.risk_score,
        "title": f.title,
        "description": f.description,
        "recommendation": f.recommendation,
        "evidences": [
            {
                "key": e.key,
                "value": e.value,
                "threshold": e.threshold,
                "unit": e.unit,
            }
            for e in f.evidences
        ],
        "affected_entities": f.affected_entities,
        "raw_score": f.raw_score,
    }


def _collect_affected_hosts(findings: list[Finding]) -> list[str]:
    """Gather unique IPs from affected_entities across all findings."""
    hosts: set[str] = set()
    for f in findings:
        for entity in f.affected_entities:
            hosts.add(entity)
    return sorted(hosts)


def _overall_to_dict(overall: OverallRiskScore) -> dict[str, Any]:
    """Serialize OverallRiskScore for the prompt."""
    return {
        "max_score": overall.max_score,
        "weighted_score": overall.weighted_score,
        "severity_label": overall.severity_label.value,
        "total_findings": overall.total_findings,
        "findings_by_severity": overall.findings_by_severity,
        "failed_rules": overall.failed_rules,
    }


SYSTEM_PROMPT = """You are a senior SOC analyst reviewing network detection results.
Return a **valid JSON object only** — no markdown fences, no commentary outside the JSON.

Output schema:
{
  "executive_summary": "<3-5 sentences for a C-level reader: total findings, max severity, how many hosts affected, what the top concern is, no jargon>",
  "finding_rationales": [
    {
      "finding_id": "<same id from input>",
      "explanation": "<2-4 sentences explaining why this triggered and what it likely means>",
      "confidence_qualifier": "high" | "medium" | "low",
      "false_positive_likelihood": <0.0 to 1.0>
    }
  ],
  "remediation_steps": [
    {
      "priority": <1-5, 1=highest>,
      "action": "<what to do, e.g. 'Block source IP at firewall'>",
      "reason": "<why this step addresses the threat>",
      "reference": "<optional CVE, CWE, or documentation URL>"
    }
  ]
}"""


def build_assessment_prompt(
    findings: list[Finding],
    overall: OverallRiskScore,
) -> tuple[str, str]:
    """Build the system prompt and user prompt for a single LLM call.

    Returns:
        (system_prompt, user_prompt) pair.
    """
    affected_hosts = _collect_affected_hosts(findings)

    user_prompt_parts: list[str] = [
        "## Overall Risk",
        json.dumps(_overall_to_dict(overall), indent=2),
        "",
        f"## Detected Findings ({len(findings)} total)",
    ]

    for f in findings:
        user_prompt_parts.append(json.dumps(_finding_to_dict(f), indent=2))

    if affected_hosts:
        user_prompt_parts.append("")
        user_prompt_parts.append("## Affected Hosts")
        user_prompt_parts.append("\n".join(affected_hosts))

    user_prompt = "\n".join(user_prompt_parts)

    return SYSTEM_PROMPT, user_prompt
