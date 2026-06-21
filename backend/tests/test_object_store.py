"""Unit tests for the ObjectStore abstraction layer."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from backend.config import Settings
from backend.storage.object_store import (
    LocalObjectStore,
    S3ObjectStore,
    get_object_store,
)


class TestLocalObjectStore:
    """Tests for the default local-disk backend."""

    def test_put_get_roundtrip(self, tmp_path: Path):
        store = LocalObjectStore(base_dir=tmp_path)
        store.put("ab/sample.pcap", b"pcap data")
        assert store.get("ab/sample.pcap") == b"pcap data"

    def test_exists_and_delete(self, tmp_path: Path):
        store = LocalObjectStore(base_dir=tmp_path)
        assert not store.exists("missing.pcap")
        store.put("x/missing.pcap", b"x")
        assert store.exists("x/missing.pcap")
        store.delete("x/missing.pcap")
        assert not store.exists("x/missing.pcap")

    def test_get_missing_raises(self, tmp_path: Path):
        store = LocalObjectStore(base_dir=tmp_path)
        with pytest.raises(FileNotFoundError):
            store.get("not_here.pcap")

    def test_get_as_path(self, tmp_path: Path):
        store = LocalObjectStore(base_dir=tmp_path)
        store.put("a/b.pcap", b"data")
        path = store.get_as_path("a/b.pcap")
        assert path == tmp_path / "a" / "b.pcap"
        assert path.read_bytes() == b"data"

    def test_overwrite(self, tmp_path: Path):
        store = LocalObjectStore(base_dir=tmp_path)
        store.put("file.pcap", b"old")
        store.put("file.pcap", b"new")
        assert store.get("file.pcap") == b"new"

    def test_nested_key(self, tmp_path: Path):
        store = LocalObjectStore(base_dir=tmp_path)
        store.put("deep/nested/key.pcap", b"nested")
        assert (tmp_path / "deep" / "nested" / "key.pcap").exists()


class TestS3ObjectStore:
    """Tests for the S3 backend using mocked MinIO client."""

    def _make_store(self) -> S3ObjectStore:
        """Return an S3ObjectStore with a mocked MinIO client."""
        mock_client = MagicMock()
        mock_client.bucket_exists.return_value = True
        store = S3ObjectStore(
            endpoint_url="localhost:9000",
            bucket="test-bucket",
            access_key="test-key",
            secret_key="test-secret",
            region="us-east-1",
            _client=mock_client,
        )
        store._mock_client = mock_client  # type: ignore[attr-defined]
        return store

    def test_put(self):
        store = self._make_store()
        store.put("a/b.pcap", b"hello")
        store._mock_client.put_object.assert_called_once()
        args = store._mock_client.put_object.call_args[0]
        assert args[0] == "test-bucket"
        assert args[1] == "a/b.pcap"

    def test_get(self):
        store = self._make_store()
        mock_response = MagicMock()
        mock_response.read.return_value = b"pcap bytes"
        store._mock_client.get_object.return_value = mock_response
        data = store.get("a/b.pcap")
        assert data == b"pcap bytes"
        mock_response.close.assert_called_once()
        mock_response.release_conn.assert_called_once()

    def test_exists_true(self):
        store = self._make_store()
        # No exception → exists
        store._mock_client.stat_object.side_effect = None
        # stat_object doesn't return anything useful for exists check; absence of exc = True
        assert store.exists("a/b.pcap")

    def test_exists_false(self):
        store = self._make_store()
        store._mock_client.stat_object.side_effect = Exception("NoSuchKey")
        assert not store.exists("a/b.pcap")

    def test_delete(self):
        store = self._make_store()
        store.delete("a/b.pcap")
        store._mock_client.remove_object.assert_called_once_with("test-bucket", "a/b.pcap")

    def test_get_as_path(self):
        store = self._make_store()
        mock_response = MagicMock()
        mock_response.read.return_value = b"temp content"
        store._mock_client.get_object.return_value = mock_response
        path = store.get_as_path("a/b.pcap")
        assert path.exists()
        assert path.read_bytes() == b"temp content"


class TestGetObjectStore:
    """Factory-level tests wiring Settings to the correct backend."""

    def test_local_backend(self, tmp_path: Path):
        settings = Settings(
            object_store_backend="local",
            upload_dir=tmp_path,
        )
        store = get_object_store(settings)
        assert isinstance(store, LocalObjectStore)

    def test_s3_backend(self):
        fake_minio = MagicMock()
        fake_minio.Minio = MagicMock()
        with patch.dict("sys.modules", {"minio": fake_minio}):
            settings = Settings(
                object_store_backend="s3",
                s3_endpoint_url="http://minio:9000",
                s3_bucket="netmind",
                s3_access_key="key",
                s3_secret_key="secret",
                s3_region="us-east-1",
            )
            store = get_object_store(settings)
            assert isinstance(store, S3ObjectStore)
            fake_minio.Minio.assert_called_once()
            assert fake_minio.Minio.call_args[0][0] == "minio:9000"

    def test_unknown_backend_raises(self):
        mock_settings = MagicMock()
        mock_settings.object_store_backend = "invalid"
        with pytest.raises(ValueError, match="Unknown object_store_backend"):
            get_object_store(mock_settings)
