"""Application configuration loaded from environment variables.

All values can be overridden via a .env file at the project root or
the BACKEND_ROOT environment variable. Use pydantic-settings for
validation and type coercion.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """NetMind AI backend settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "NetMind AI"
    app_version: str = "0.1.0"
    environment: str = Field(default="development")
    log_level: str = Field(default="INFO")

    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_prefix: str = Field(default="/api/v1")
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])

    database_url: str = Field(default="postgresql+asyncpg://netmind:netmind@db:5432/netmind")
    database_echo: bool = Field(default=False)
    database_pool_size: int = Field(default=5)
    database_max_overflow: int = Field(default=10)

    upload_dir: Path = Field(default=Path("/var/lib/netmind/pcaps"))
    upload_max_size_mb: int = Field(default=100)
    upload_allowed_extensions: list[str] = Field(default_factory=lambda: [".pcap", ".pcapng"])
    storage_retention_days: int = Field(default=7)
    storage_cleanup_enabled: bool = Field(default=True)
    storage_cleanup_schedule_seconds: int = Field(default=3600)

    celery_broker_url: str = Field(default="redis://localhost:6379/0")
    celery_result_backend: str = Field(default="redis://localhost:6379/1")
    celery_task_acks_late: bool = Field(default=True)
    celery_task_time_limit_sec: int = Field(default=600)
    celery_task_soft_time_limit_sec: int = Field(default=540)

    enable_docs: bool = Field(default=True)

    @property
    def upload_max_size_bytes(self) -> int:
        return self.upload_max_size_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    """Return cached Settings instance."""
    return Settings()
