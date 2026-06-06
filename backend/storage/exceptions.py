"""Domain-specific exceptions for the storage lifecycle."""


class StorageError(Exception):
    """Base storage error."""


class DiskFullError(StorageError):
    """Raised when disk usage exceeds the configured threshold."""


class PcapNotFoundError(StorageError):
    """Raised when a PCAP record or its file is not found."""


class ArtifactNotFoundError(StorageError):
    """Raised when a job artifact is not found."""


class FileIntegrityError(StorageError):
    """Raised when a stored file fails integrity checks (hash mismatch, etc.)."""
