"""LLM provider abstraction for the AI Assessor.

MVP ships with only the Ollama provider. The BaseProvider
abstract class allows third-party providers to be added later
without changing the assessor orchestration.
"""

from backend.ai_assessor.providers.base import BaseProvider
from backend.ai_assessor.providers.ollama import OllamaProvider

__all__ = [
    "BaseProvider",
    "OllamaProvider",
]
