"""Abstract base class for LLM providers."""

from abc import ABC, abstractmethod


class BaseProvider(ABC):
    """Interface that every LLM provider must implement."""

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system: str | None = None,
        timeout_sec: int = 30,
    ) -> str:
        """Send a prompt to the LLM and return the text response.

        Args:
            prompt: User / assistant prompt content.
            system: Optional system-level instruction.
            timeout_sec: Maximum seconds to wait for a response.

        Returns:
            Raw response text from the LLM.

        Raises:
            ProviderUnavailableError: If the provider is unreachable
                or returns an error status.
        """
        ...
