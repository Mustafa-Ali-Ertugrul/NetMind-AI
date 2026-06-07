"""AIAssessor configuration via environment variables."""

import os


class AssessorConfig:
    """Configuration for the AI Assessor.

    Reads from environment variables with sensible defaults.
    Set NETMIND_AI_ENABLED=false to disable the assessor entirely.
    """

    def __init__(self) -> None:
        self.provider: str = os.getenv("NETMIND_PROVIDER", "ollama")
        self.ollama_url: str = os.getenv("NETMIND_OLLAMA_URL", "http://localhost:11434")
        self.ollama_model: str = os.getenv("NETMIND_OLLAMA_MODEL", "llama3.1:8b")
        self.request_timeout_sec: int = int(os.getenv("NETMIND_AI_TIMEOUT", "30"))
        self.enable_ai: bool = os.getenv("NETMIND_AI_ENABLED", "true").lower() == "true"
        self.min_severity: str = os.getenv("NETMIND_AI_MIN_SEVERITY", "HIGH")
        self.cache_enabled: bool = (
            os.getenv("NETMIND_AI_CACHE_ENABLED", "true").lower() == "true"
        )
        self.cache_ttl_seconds: int = int(os.getenv("NETMIND_AI_CACHE_TTL_SECONDS", "86400"))
        self.cache_redis_url: str = os.getenv(
            "NETMIND_AI_CACHE_REDIS_URL",
            os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/2"),
        )
