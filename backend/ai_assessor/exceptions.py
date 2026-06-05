"""AIAssessor-specific exceptions."""


class AIAssessorError(Exception):
    """Base exception for AI Assessor failures."""


class ProviderUnavailableError(AIAssessorError):
    """The LLM provider could not be reached or returned an error."""


class InvalidResponseError(AIAssessorError):
    """The LLM response was malformed or failed schema validation."""
