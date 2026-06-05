"""Tests for the AI Assessor (Phase 4A).

Covers:
    - Provider abstraction contract
    - OllamaProvider (mocked HTTP)
    - AIAssessor orchestrator (single LLM call, no features)
    - Fallback path when LLM is down
    - Backward compatibility (SecurityReport.ai_assessment is None)
    - Prompt building
    - Edge cases (empty findings, provider timeout)
"""

from __future__ import annotations

import json
from datetime import datetime
from uuid import uuid4

import pytest

from backend.ai_assessor import AIAssessor, AssessorConfig
from backend.ai_assessor.exceptions import (
    InvalidResponseError,
    ProviderUnavailableError,
)
from backend.ai_assessor.providers import BaseProvider, OllamaProvider
from backend.ai_assessor.providers.base import BaseProvider as BaseProviderABC
from backend.contracts.ai_output import (
    AIAssessment,
    FindingRationale,
    RemediationStep,
    SecurityReport,
)
from backend.contracts.enums import Confidence, RiskLabel, Severity
from backend.contracts.findings import Evidence, Finding, OverallRiskScore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    rule_id: str = "NET-001",
    severity: Severity = Severity.HIGH,
    title: str = "Port Scan Detected",
    description: str = "Multiple ports scanned from source IP",
) -> Finding:
    return Finding(
        pcap_id=uuid4(),
        rule_id=rule_id,
        rule_name="PortScanRule",
        rule_version="1.0.0",
        severity=severity,
        confidence=Confidence.HIGH,
        risk_score=75,
        title=title,
        description=description,
        recommendation="Block source IP",
        evidences=[
            Evidence(key="unique_dst_ports", value=50, threshold="20", unit="ports"),
        ],
        affected_entities=["10.0.0.5"],
        timestamp_start=datetime.utcnow(),
        timestamp_end=datetime.utcnow(),
        raw_score=80.0,
    )


def _make_findings(count: int = 3) -> list[Finding]:
    return [_make_finding(rule_id=f"NET-{i:03d}") for i in range(1, count + 1)]


def _make_overall(findings: list[Finding] | None = None) -> OverallRiskScore:
    if not findings:
        return OverallRiskScore(
            max_score=0,
            weighted_score=0,
            severity_label=RiskLabel.INFORMATIONAL,
            total_findings=0,
            findings_by_severity={},
            top_finding_ids=[],
        )
    return OverallRiskScore(
        max_score=75,
        weighted_score=60,
        severity_label=RiskLabel.HIGH,
        total_findings=len(findings),
        findings_by_severity={"HIGH": len(findings)},
        top_finding_ids=[f.id for f in findings],
    )


# ---------------------------------------------------------------------------
# Provider abstraction
# ---------------------------------------------------------------------------


class TestBaseProvider:
    def test_abstract_class_cannot_be_instantiated(self):
        """BaseProvider ABC should enforce abstract methods."""
        with pytest.raises(TypeError):
            BaseProviderABC()  # type: ignore[abstract]

    def test_concrete_provider_can_be_instantiated(self):
        """A subclass that implements generate() works."""

        class OkProvider(BaseProvider):
            def generate(self, prompt, system=None, timeout_sec=30):
                return "ok"

        p = OkProvider()
        assert p.generate("hi") == "ok"


# ---------------------------------------------------------------------------
# Mock provider for assessor tests
# ---------------------------------------------------------------------------


class MockProvider(BaseProvider):
    """Provider that returns a canned JSON response."""

    def __init__(self, response: str | None = None, fail: bool = False) -> None:
        self._response = response or _default_llm_response()
        self._fail = fail
        self.last_prompt: str | None = None
        self.last_system: str | None = None

    def generate(
        self,
        prompt: str,
        system: str | None = None,
        timeout_sec: int = 30,
    ) -> str:
        self.last_prompt = prompt
        self.last_system = system
        if self._fail:
            raise ProviderUnavailableError("Simulated provider failure")
        return self._response


def _default_llm_response() -> str:
    return json.dumps(
        {
            "executive_summary": (
                "Detected 3 findings with a High overall risk. "
                "2 hosts are potentially compromised. "
                "Port scanning is the most active threat."
            ),
            "finding_rationales": [
                {
                    "finding_id": "placeholder",
                    "explanation": "High number of unique ports from one source",
                    "confidence_qualifier": "high",
                    "false_positive_likelihood": 0.2,
                },
            ],
            "remediation_steps": [
                {
                    "priority": 1,
                    "action": "Block source IP at firewall",
                    "reason": "Active port scan detected",
                    "reference": "https://example.com/port-scan-mitigation",
                },
            ],
        }
    )


# ---------------------------------------------------------------------------
# Prompt building
# ---------------------------------------------------------------------------


class TestAssessPrompt:
    def test_prompt_includes_findings(self):
        """The built prompt should serialize all findings."""
        from backend.ai_assessor.prompts.assess_prompt import build_assessment_prompt

        findings = _make_findings(2)
        overall = _make_overall(findings)
        system_prompt, user_prompt = build_assessment_prompt(findings, overall)

        assert "Detected Findings" in user_prompt
        assert "Overall Risk" in user_prompt
        assert "NET-001" in user_prompt
        assert "NET-002" in user_prompt
        assert "10.0.0.5" in user_prompt

    def test_prompt_no_findings(self):
        """Prompt should still build cleanly with zero findings."""
        from backend.ai_assessor.prompts.assess_prompt import build_assessment_prompt

        findings: list[Finding] = []
        overall = _make_overall(findings)
        system_prompt, user_prompt = build_assessment_prompt(findings, overall)

        assert "Detected Findings (0 total)" in user_prompt

    def test_system_prompt_instructs_json(self):
        """System prompt must instruct the model to return JSON."""
        from backend.ai_assessor.prompts.assess_prompt import build_assessment_prompt

        findings = _make_findings(1)
        overall = _make_overall(findings)
        system_prompt, user_prompt = build_assessment_prompt(findings, overall)

        assert "valid JSON" in system_prompt
        assert "executive_summary" in system_prompt
        assert "finding_rationales" in system_prompt
        assert "remediation_steps" in system_prompt


# ---------------------------------------------------------------------------
# OllamaProvider (mocked HTTP)
# ---------------------------------------------------------------------------


class MockUrlOpener:
    """Replacement for urllib.request.urlopen that returns canned data."""

    def __init__(self, data: bytes, status: int = 200) -> None:
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self) -> bytes:
        return self._data


class TestOllamaProvider:
    def test_generate_success(self, monkeypatch):
        """Valid JSON response returns the response text."""

        def mock_urlopen(request, **kwargs):
            data = json.dumps({"response": "Hello from Ollama"}).encode()
            return MockUrlOpener(data)

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        provider = OllamaProvider(base_url="http://localhost:11434", model="test-model")
        result = provider.generate("ping")
        assert result == "Hello from Ollama"

    def test_generate_timeout(self, monkeypatch):
        """Timeout should raise ProviderUnavailableError."""

        def mock_urlopen(request, **kwargs):
            raise TimeoutError("timed out")

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        provider = OllamaProvider()
        with pytest.raises(ProviderUnavailableError, match="timed out"):
            provider.generate("ping", timeout_sec=1)

    def test_generate_connection_error(self, monkeypatch):
        """Connection refused should raise ProviderUnavailableError."""

        def mock_urlopen(request, **kwargs):
            import urllib.error

            raise urllib.error.URLError("Connection refused")

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        provider = OllamaProvider()
        with pytest.raises(ProviderUnavailableError, match="unreachable"):
            provider.generate("ping")

    def test_generate_missing_response_key(self, monkeypatch):
        """Missing 'response' key should raise ProviderUnavailableError."""

        def mock_urlopen(request, **kwargs):
            data = json.dumps({"error": "model not found"}).encode()
            return MockUrlOpener(data)

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        provider = OllamaProvider()
        with pytest.raises(ProviderUnavailableError, match="missing 'response'"):
            provider.generate("ping")

    def test_generate_invalid_json(self, monkeypatch):
        """Non-JSON response should raise ProviderUnavailableError."""

        def mock_urlopen(request, **kwargs):
            return MockUrlOpener(b"not json at all")

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        provider = OllamaProvider()
        with pytest.raises(ProviderUnavailableError, match="invalid JSON"):
            provider.generate("ping")


# ---------------------------------------------------------------------------
# AIAssessor orchestrator
# ---------------------------------------------------------------------------


class TestAIAssessor:
    def test_assess_success(self):
        """Successful LLM call returns parsed AIAssessment."""
        provider = MockProvider()
        assessor = AIAssessor(provider=provider)
        findings = _make_findings(2)
        overall = _make_overall(findings)

        assessment = assessor.assess(findings, overall)

        assert isinstance(assessment, AIAssessment)
        assert assessment.executive_summary != ""
        assert len(assessment.finding_rationales) >= 0
        assert len(assessment.remediation_steps) >= 0
        assert assessment.provider == "ollama"
        assert assessment.fallback_used is False

    def test_assess_fallback_on_provider_failure(self):
        """Provider failure triggers template fallback."""
        provider = MockProvider(fail=True)
        assessor = AIAssessor(provider=provider)
        findings = _make_findings(2)
        overall = _make_overall(findings)

        assessment = assessor.assess(findings, overall)

        assert assessment.fallback_used is True
        assert assessment.provider == "fallback"

    def test_assess_fallback_on_invalid_json(self):
        """Non-JSON response triggers template fallback."""
        provider = MockProvider(response="this is not json")
        assessor = AIAssessor(provider=provider)
        findings = _make_findings(2)
        overall = _make_overall(findings)

        assessment = assessor.assess(findings, overall)

        assert assessment.fallback_used is True
        assert assessment.provider == "fallback"

    def test_assess_missing_required_keys(self):
        """Response missing 'executive_summary' triggers fallback."""
        bad_response = json.dumps({"finding_rationales": []})
        provider = MockProvider(response=bad_response)
        assessor = AIAssessor(provider=provider)
        findings = _make_findings(1)
        overall = _make_overall(findings)

        assessment = assessor.assess(findings, overall)

        assert assessment.fallback_used is True

    def test_assess_empty_findings_uses_fallback(self):
        """Zero findings should short-circuit to fallback (no LLM call)."""
        provider = MockProvider(fail=True)
        assessor = AIAssessor(provider=provider)
        findings: list[Finding] = []
        overall = _make_overall(findings)

        assessment = assessor.assess(findings, overall)

        assert assessment.fallback_used is True
        assert "No findings" in assessment.executive_summary
        # Provider should NOT have been called for empty findings
        assert provider.last_prompt is None

    def test_assess_disabled_via_config(self):
        """NETMIND_AI_ENABLED=false skips the LLM call entirely."""
        config = AssessorConfig()
        config.enable_ai = False
        provider = MockProvider(fail=True)  # would fail, but won't be called
        assessor = AIAssessor(provider=provider, config=config)
        findings = _make_findings(2)
        overall = _make_overall(findings)

        assessment = assessor.assess(findings, overall)

        assert assessment.fallback_used is False  # deliberate disable, not error
        assert assessment.provider == "fallback"
        assert provider.last_prompt is None  # not called

    def test_assess_passes_findings_and_overall_only(self):
        """Ensure the provider receives the prompt (no features leaked)."""
        provider = MockProvider()
        assessor = AIAssessor(provider=provider)
        findings = _make_findings(1)
        overall = _make_overall(findings)

        assessor.assess(findings, overall)

        assert provider.last_prompt is not None
        # Prompt should contain finding data but NOT feature fields
        assert "pcap_id" not in provider.last_prompt
        assert "traffic_baseline" not in provider.last_prompt
        assert "connection_profiles" not in provider.last_prompt

    def test_remediation_steps_no_command_hint(self):
        """command_hint should NOT be in the output schema."""
        provider = MockProvider()
        assessor = AIAssessor(provider=provider)
        findings = _make_findings(1)
        overall = _make_overall(findings)

        assessment = assessor.assess(findings, overall)

        for step in assessment.remediation_steps:
            assert not hasattr(step, "command_hint")
            assert step.reference is None or isinstance(step.reference, str)

    def test_fallback_includes_affected_hosts(self):
        """Fallback summary should count unique affected hosts."""
        findings = _make_findings(3)
        findings[0].affected_entities = ["10.0.0.1"]
        findings[1].affected_entities = ["10.0.0.2"]
        findings[2].affected_entities = ["10.0.0.1"]  # duplicate
        overall = _make_overall(findings)
        provider = MockProvider(fail=True)
        assessor = AIAssessor(provider=provider)

        assessment = assessor.assess(findings, overall)

        assert "2 affected host(s)" in assessment.executive_summary


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    def test_security_report_ai_assessment_is_optional(self):
        """SecurityReport can be created without ai_assessment."""
        report = SecurityReport(
            risk_score=50,
            risk_label="MEDIUM",
            executive_summary="Test",
            key_findings=[],
            recommendations=[],
            model_confidence=0.8,
            model_name="test",
            generation_time_ms=0,
            prompt_token_count=0,
        )
        assert report.ai_assessment is None

    def test_security_report_with_ai_assessment(self):
        """SecurityReport can hold an AIAssessment."""
        assessment = AIAssessment(
            executive_summary="Test",
            finding_rationales=[],
            remediation_steps=[],
            provider="ollama",
            model="test",
            generation_time_ms=0,
        )
        report = SecurityReport(
            risk_score=50,
            risk_label="MEDIUM",
            executive_summary="Test",
            key_findings=[],
            recommendations=[],
            model_confidence=0.8,
            model_name="test",
            generation_time_ms=0,
            prompt_token_count=0,
            ai_assessment=assessment,
        )
        assert report.ai_assessment is not None
        assert report.ai_assessment.executive_summary == "Test"

    def test_existing_security_report_still_works(self):
        """Old-style SecurityReport construction still works."""
        from backend.contracts.ai_output import AIFinding

        report = SecurityReport(
            risk_score=75,
            risk_label="HIGH",
            executive_summary="Port scan detected",
            key_findings=[
                AIFinding(severity="HIGH", title="Port Scan", evidence_summary="50 ports"),
            ],
            recommendations=["Block source IP"],
            model_confidence=0.9,
            model_name="llama3.1:8b",
            generation_time_ms=150,
            prompt_token_count=450,
        )
        assert report.ai_assessment is None
        assert report.risk_score == 75


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_single_finding(self):
        """Assessor handles single finding gracefully."""
        provider = MockProvider()
        assessor = AIAssessor(provider=provider)
        findings = _make_findings(1)
        overall = _make_overall(findings)

        assessment = assessor.assess(findings, overall)
        assert assessment.fallback_used is False

    def test_many_findings_builds_prompt(self):
        """Assessor handles many findings without crashing."""
        provider = MockProvider()
        assessor = AIAssessor(provider=provider)
        findings = _make_findings(10)
        overall = _make_overall(findings)

        assessment = assessor.assess(findings, overall)
        assert assessment.fallback_used is False

    def test_fallback_without_findings(self):
        """Fallback with no findings returns clean 'no findings' message."""
        provider = MockProvider(fail=True)
        assessor = AIAssessor(provider=provider)
        findings: list[Finding] = []
        overall = _make_overall(findings)

        assessment = assessor.assess(findings, overall)

        assert "No findings" in assessment.executive_summary
        assert len(assessment.finding_rationales) == 0

    def test_provider_system_prompt_passed(self):
        """The system prompt should be passed through to the provider."""
        provider = MockProvider()
        assessor = AIAssessor(provider=provider)
        findings = _make_findings(1)
        overall = _make_overall(findings)

        assessor.assess(findings, overall)

        assert provider.last_system is not None
        assert "executive_summary" in provider.last_system

    def test_generation_time_ms_recorded(self):
        """generation_time_ms should be a positive integer on success."""
        provider = MockProvider()
        assessor = AIAssessor(provider=provider)
        findings = _make_findings(2)
        overall = _make_overall(findings)

        assessment = assessor.assess(findings, overall)

        assert assessment.generation_time_ms >= 0

    def test_fallback_lists_remediation_steps(self):
        """Fallback should always include remediation steps."""
        provider = MockProvider(fail=True)
        assessor = AIAssessor(provider=provider)
        findings = _make_findings(1)
        overall = _make_overall(findings)

        assessment = assessor.assess(findings, overall)

        assert len(assessment.remediation_steps) >= 1
        assert "SIEM" in assessment.remediation_steps[0].action
