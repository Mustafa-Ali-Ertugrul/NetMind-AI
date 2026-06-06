"""Object storage abstraction for PCAP blobs and artifacts.

Supports two backends:
- *local*  → writes to ``upload_dir`` on local disk (default, backward-compatible).
- *s3*     → writes to a MinIO / S3-compatible bucket.

The ``storage_key`` semantic is preserved across backends: a relative path
such as ``ab/cd1234….pcap`` becomes a file path under ``upload_dir`` in local
mode, and an object key in the bucket in S3 mode.
"""

from __future__ import annotations

import logging
import tempfile
from io import BytesIO
from pathlib import Path
from typing import Protocol

from backend.config import Settings

logger = logging.getLogger("netmind.storage.object_store")


class ObjectStore(Protocol):
    """Minimal object-store contract used by the PCAP pipeline."""

    def put(self, key: str, data: bytes) -> None:
        """Persist *data* under *key*."""
        ...

    def get(self, key: str) -> bytes:
        """Return the raw bytes stored under *key*."""
        ...

    def get_as_path(self, key: str) -> Path:
        """Return a local filesystem path readable by external tools (e.g. tshark).

        For S3 backends this writes the object to a temporary file.
        The caller is responsible for cleaning up the temp file.
        """
        ...

    def delete(self, key: str) -> None:
        """Remove the object if it exists."""
        ...

    def exists(self, key: str) -> bool:
        """Return True when the object is present."""
        ...


class LocalObjectStore:
    """Default backend: stores objects under a base directory on local disk."""

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir

    # ------------------------------------------------------------------
    # ObjectStore implementation
    # ------------------------------------------------------------------

    def put(self, key: str, data: bytes) -> None:
        target = self.base_dir / key
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def get(self, key: str) -> bytes:
        target = self.base_dir / key
        if not target.exists():
            raise FileNotFoundError(f"Object not found: {key}")
        return target.read_bytes()

    def get_as_path(self, key: str) -> Path:
        # Already on disk — return directly.
        return self.base_dir / key

    def delete(self, key: str) -> None:
        target = self.base_dir / key
        if target.exists():
            target.unlink()

    def exists(self, key: str) -> bool:
        return (self.base_dir / key).exists()


class S3ObjectStore:
    """S3-compatible backend using the MinIO Python client."""

    def __init__(
        self,
        *,
        endpoint_url: str,
        bucket: str,
        access_key: str | None,
        secret_key: str | None,
        region: str = "us-east-1",
        _client=None,
    ) -> None:
        self.bucket = bucket

        if _client is not None:
            self.client = _client
        else:
            try:
                from minio import Minio
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(
                    "minio package is required for S3 backend. Install with: pip install minio>=7.2.0"
                ) from exc

            self.client = Minio(
                endpoint_url,
                access_key=access_key,
                secret_key=secret_key,
                region=region,
                secure=False,  # assume internal / TLS-terminated load balancer
            )

        if not self.client.bucket_exists(bucket):
            logger.info("Creating S3 bucket %s", bucket)
            self.client.make_bucket(bucket, location=region)

    # ------------------------------------------------------------------
    # ObjectStore implementation
    # ------------------------------------------------------------------

    def put(self, key: str, data: bytes) -> None:
        self.client.put_object(self.bucket, key, BytesIO(data), len(data))

    def get(self, key: str) -> bytes:
        response = self.client.get_object(self.bucket, key)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    def get_as_path(self, key: str) -> Path:
        data = self.get(key)
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(data)
        tmp.close()
        return Path(tmp.name)

    def delete(self, key: str) -> None:
        self.client.remove_object(self.bucket, key)

    def exists(self, key: str) -> bool:
        try:
            self.client.stat_object(self.bucket, key)
            return True
        except Exception:  # noqa: BLE001
            return False


# ------------------------------------------------------------------
# Factory
# ------------------------------------------------------------------


def get_object_store(settings: Settings) -> ObjectStore:
    """Return an ObjectStore backend configured from *settings*."""
    if settings.object_store_backend == "local":
        return LocalObjectStore(base_dir=settings.upload_dir)

    if settings.object_store_backend == "s3":
        return S3ObjectStore(
            endpoint_url=settings.s3_endpoint_url or "localhost:9000",
            bucket=settings.s3_bucket,
            access_key=settings.s3_access_key,
            secret_key=settings.s3_secret_key,
            region=settings.s3_region,
        )

    raise ValueError(f"Unknown object_store_backend: {settings.object_store_backend}")
