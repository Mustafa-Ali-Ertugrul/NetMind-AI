"""AIAssessor orchestrator — single LLM call, no features passed."""

from __future__ import annotations

import json
import logging
import hashlib
import time
from datetime import datetime

from backend.ai_assessor.config import AssessorConfig
from backend.ai_assessor.exceptions import (
    AIAssessorError,
    InvalidResponseError,
    ProviderUnavailableError,
)
from backend.ai_assessor.prompts import build_assessment_prompt
from backend.ai_assessor.providers import BaseProvider, OllamaProvider
from backend.contracts.ai_output import AIAssessment, FindingRationale, RemediationStep
from backend.contracts.enums import Severity
from backend.contracts.findings import Finding, OverallRiskScore

logger = logging.getLogger("netmind.ai_assessor")


class AIAssessor:
    """Enriches rule-engine results with LLM-generated context.

    The assessor is a **post-processing layer**:

    - It never modifies findings or overall risk scores.
    - It produces an ``AIAssessment`` attached to ``SecurityReport.ai_assessment``.
    - If the LLM is unavailable or returns garbage, a *template fallback*
      ensures the pipeline never crashes.
    - If AI is disabled (``NETMIND_AI_ENABLED=false``), ``ai_assessment``
      is set to ``None``.
    """

    def __init__(
        self,
        provider: BaseProvider | None = None,
        config: AssessorConfig | None = None,
    ) -> None:
        self._config = config or AssessorConfig()
        if provider is not None:
            self._provider = provider
        else:
            self._provider = self._default_provider()
        self._model_name: str = self._config.ollama_model

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def assess(
        self,
        findings: list[Finding],
        overall: OverallRiskScore,
    ) -> AIAssessment:
        """Run the AI assessment on the given rule-engine output.

        Only findings at or above ``self._config.min_severity`` are sent
        to the LLM. Lower-severity findings are silently dropped to
        control token use and focus the LLM on high-impact events.

        Args:
            findings: Rule-engine findings (zero or more).
            overall: Aggregated risk score.

        Returns:
            An ``AIAssessment`` instance — either LLM-generated or
            a template fallback if the provider is unavailable.
        """
        if not self._config.enable_ai:
            logger.info("AI Assessor disabled via NETMIND_AI_ENABLED=false")
            return self._fallback_assessment(findings, overall, fallback_used=False)

        filtered = self._filter_by_severity(findings)
        if not filtered:
            logger.info(
                "No findings at or above NETMIND_AI_MIN_SEVERITY=%s; skipping LLM call",
                self._config.min_severity,
            )
            return self._fallback_assessment(findings, overall, fallback_used=True)

        t0 = time.perf_counter()
        system_prompt, user_prompt = build_assessment_prompt(filtered, overall)
        cache_key = self._cache_key(system_prompt, user_prompt)
        cached = self._read_cached_assessment(cache_key)
        if cached is not None:
            return cached

        try:
            raw = self._provider.generate(
                prompt=user_prompt,
                system=system_prompt,
                timeout_sec=self._config.request_timeout_sec,
            )
        except (AIAssessorError, ProviderUnavailableError) as exc:
            logger.warning("LLM call failed, using fallback: %s", exc)
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            return self._fallback_assessment(
                filtered, overall, fallback_used=True, generation_time_ms=elapsed_ms
            )

        elapsed_ms = int((time.perf_counter() - t0) * 1000)

        try:
            assessment = self._parse_assessment(
                raw, filtered, overall, elapsed_ms, fallback_used=False
            )
            self._write_cached_assessment(cache_key, assessment)
            return assessment
        except InvalidResponseError as exc:
            logger.warning("LLM response invalid, using fallback: %s", exc)
            return self._fallback_assessment(
                filtered, overall, fallback_used=True, generation_time_ms=elapsed_ms
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _filter_by_severity(self, findings: list[Finding]) -> list[Finding]:
        """Keep only findings at or above ``self._config.min_severity``."""
        try:
            floor = Severity[self._config.min_severity.upper()].value
        except KeyError:
            logger.warning(
                "Unknown min_severity=%r; defaulting to HIGH",
                self._config.min_severity,
            )
            floor = Severity.HIGH.value
        return [f for f in findings if f.severity.value >= floor]

    def _default_provider(self) -> BaseProvider:
        return OllamaProvider(
            base_url=self._config.ollama_url,
            model=self._config.ollama_model,
        )

    def _cache_key(self, system_prompt: str, user_prompt: str) -> str:
        payload = json.dumps(
            {
                "model": self._model_name,
                "min_severity": self._config.min_severity.upper(),
                "system": system_prompt,
                "prompt": user_prompt,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return f"netmind:ai_assessment:{digest}"

    def _read_cached_assessment(self, cache_key: str) -> AIAssessment | None:
        if not self._config.cache_enabled:
            return None
        try:
            import redis

            client = redis.Redis.from_url(self._config.cache_redis_url)
            raw = client.get(cache_key)
            if raw is None:
                return None
            data = json.loads(raw)
            assessment = AIAssessment.model_validate(data)
            assessment.generated_at = datetime.utcnow()
            assessment.generation_time_ms = 0
            logger.info("AI assessment cache hit for key %s", cache_key)
            return assessment
        except Exception as exc:  # noqa: BLE001
            logger.warning("AI assessment cache read skipped: %s", exc)
            return None

    def _write_cached_assessment(self, cache_key: str, assessment: AIAssessment) -> None:
        if not self._config.cache_enabled or assessment.fallback_used:
            return
        try:
            import redis

            client = redis.Redis.from_url(self._config.cache_redis_url)
            client.setex(
                cache_key,
                self._config.cache_ttl_seconds,
                assessment.model_dump_json(),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("AI assessment cache write skipped: %s", exc)

    def _parse_assessment(
        self,
        raw: str,
        findings: list[Finding],
        overall: OverallRiskScore,
        generation_time_ms: int,
        fallback_used: bool,
    ) -> AIAssessment:
        """Parse the LLM JSON response into an AIAssessment."""
        # Strip markdown fences if the LLM wraps the JSON
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            # Remove optional language tag after ```
            first_newline = cleaned.find("\n")
            if first_newline != -1:
                cleaned = cleaned[first_newline:]
            # Strip closing fences
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3].strip()

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise InvalidResponseError(f"LLM returned non-JSON: {exc}. Raw: {raw[:300]}") from exc

        if not isinstance(data, dict):
            raise InvalidResponseError(f"LLM returned a {type(data).__name__}, expected dict")

        # Required top-level keys
        if "executive_summary" not in data:
            raise InvalidResponseError("Missing 'executive_summary' in LLM response")

        # Parse finding rationales
        rationales: list[FindingRationale] = []
        for entry in data.get("finding_rationales", []):
            try:
                rationales.append(
                    FindingRationale(
                        finding_id=str(entry["finding_id"]),
                        explanation=str(entry.get("explanation", "")),
                        confidence_qualifier=str(entry.get("confidence_qualifier", "medium")),
                        false_positive_likelihood=min(
                            max(float(entry.get("false_positive_likelihood", 0.5)), 0.0),
                            1.0,
                        ),
                    )
                )
            except (KeyError, ValueError, TypeError) as exc:
                logger.warning("Skipping malformed rationale entry: %s", exc)

        # Parse remediation steps
        steps: list[RemediationStep] = []
        for entry in data.get("remediation_steps", []):
            try:
                steps.append(
                    RemediationStep(
                        priority=int(entry.get("priority", 3)),
                        action=str(entry.get("action", "")),
                        reason=str(entry.get("reason", "")),
                        reference=str(entry.get("reference")) if entry.get("reference") else None,
                    )
                )
            except (KeyError, ValueError, TypeError) as exc:
                logger.warning("Skipping malformed remediation entry: %s", exc)

        return AIAssessment(
            executive_summary=str(data["executive_summary"]),
            finding_rationales=rationales,
            remediation_steps=steps,
            provider=self._config.provider,
            model=self._model_name,
            generation_time_ms=generation_time_ms,
            generated_at=datetime.utcnow(),
            fallback_used=fallback_used,
        )

    def _fallback_assessment(
        self,
        findings: list[Finding],
        overall: OverallRiskScore,
        fallback_used: bool = True,
        generation_time_ms: int = 0,
    ) -> AIAssessment:
        """Template-based fallback when the LLM is unavailable."""
        return AIAssessment(
            executive_summary=self._fallback_summary(findings, overall),
            finding_rationales=self._fallback_rationales(findings),
            remediation_steps=self._fallback_steps(findings),
            provider="fallback",
            model="template",
            generation_time_ms=generation_time_ms,
            generated_at=datetime.utcnow(),
            fallback_used=fallback_used,
        )

    @staticmethod
    def _fallback_summary(
        findings: list[Finding],
        overall: OverallRiskScore,
    ) -> str:
        if not findings:
            return "No findings were detected. The network appears clean."

        affected_hosts: set[str] = set()
        for f in findings:
            affected_hosts.update(f.affected_entities)
        host_count = len(affected_hosts)

        top_severity = overall.severity_label.value

        return (
            f"Detected {overall.total_findings} finding(s) "
            f"across {host_count} affected host(s). "
            f"Overall risk is {top_severity} "
            f"(weighted score: {overall.weighted_score}). "
            f"The top concern is {findings[0].title} ({findings[0].rule_id}). "
            "Investigate the source IPs in your SIEM and "
            "apply recommended remediation steps."
        )

    @staticmethod
    def _fallback_rationales(findings: list[Finding]) -> list[FindingRationale]:
        return [
            FindingRationale(
                finding_id=str(f.id),
                explanation=f.description,
                confidence_qualifier="medium",
                false_positive_likelihood=0.3,
            )
            for f in findings
        ]

    @staticmethod
    def _fallback_steps(findings: list[Finding]) -> list[RemediationStep]:
        return [
            RemediationStep(
                priority=1,
                action="Investigate the source IPs in your SIEM",
                reason="Multiple findings detected — correlation needed",
                reference=None,
            ),
            RemediationStep(
                priority=2,
                action="Review firewall rules for affected hosts",
                reason="Detection rules indicate suspicious network activity",
                reference=None,
            ),
        ]
