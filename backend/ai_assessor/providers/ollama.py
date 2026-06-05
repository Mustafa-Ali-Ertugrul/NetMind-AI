"""Ollama LLM provider — local inference via the Ollama REST API."""

import json
import logging
import urllib.error
import urllib.request

from backend.ai_assessor.exceptions import ProviderUnavailableError
from backend.ai_assessor.providers.base import BaseProvider

logger = logging.getLogger("netmind.ai_assessor.ollama")


class OllamaProvider(BaseProvider):
    """Provider that calls a local Ollama instance via its REST API.

    Expects Ollama to be running at *base_url* (default
    http://localhost:11434).  Set ``NETMIND_OLLAMA_URL`` and
    ``NETMIND_OLLAMA_MODEL`` to override.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.1:8b",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        prompt: str,
        system: str | None = None,
        timeout_sec: int = 30,
    ) -> str:
        """Call ``/api/generate`` on the Ollama server and return the
        full response text."""
        payload: dict = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
        }
        if system is not None:
            payload["system"] = system

        body = json.dumps(payload).encode("utf-8")
        url = f"{self._base_url}/api/generate"

        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise ProviderUnavailableError(
                f"Ollama at {self._base_url} unreachable: {exc}"
            ) from exc
        except TimeoutError as exc:
            raise ProviderUnavailableError(
                f"Ollama request timed out after {timeout_sec}s"
            ) from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProviderUnavailableError(f"Ollama returned invalid JSON: {exc}") from exc

        if "response" not in data:
            raise ProviderUnavailableError(f"Ollama response missing 'response' key: {raw[:200]}")

        return data["response"].strip()
