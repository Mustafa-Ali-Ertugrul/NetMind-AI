"""Application configuration loaded from environment variables.

All values can be overridden via a .env file at the project root or
the BACKEND_ROOT environment variable. Use pydantic-settings for
validation and type coercion.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

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

    # Storage lifecycle
    storage_retention_days: int = Field(default=7)
    storage_cleanup_enabled: bool = Field(default=True)
    storage_cleanup_schedule_seconds: int = Field(default=3600)  # dev: 1h → 6h production
    artifact_storage_path: Path = Field(default=Path("/var/lib/netmind/artifacts"))
    disk_usage_threshold_pct: float = Field(default=85.0)
    artifact_retention_hours: int = Field(default=168)  # 7 days

    celery_broker_url: str = Field(default="redis://localhost:6379/0")
    celery_result_backend: str = Field(default="redis://localhost:6379/1")
    celery_task_acks_late: bool = Field(default=True)
    celery_task_time_limit_sec: int = Field(default=600)
    celery_task_soft_time_limit_sec: int = Field(default=540)

    enable_docs: bool = Field(default=True)

    # Packet storage: none = skip DB write, sample = evenly-spaced subset,
    # all = every packet (legacy / debug).
    store_packets: Literal["none", "sample", "all"] = Field(default="sample")
    store_packets_sample_limit: int = Field(default=1000)

    # Object storage backend (local = disk, s3 = minio/s3-compatible)
    object_store_backend: Literal["local", "s3"] = Field(default="local")
    s3_endpoint_url: str | None = Field(default=None)
    s3_bucket: str = Field(default="netmind-pcaps")
    s3_access_key: str | None = Field(default=None)
    s3_secret_key: str | None = Field(default=None)
    s3_region: str = Field(default="us-east-1")

    @property
    def upload_max_size_bytes(self) -> int:
        return self.upload_max_size_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    """Return cached Settings instance."""
    return Settings()
