"""NetMind AI shared enums for contracts and persistence."""

from enum import IntEnum, StrEnum


class Severity(IntEnum):
    """Higher value = more severe."""

    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class Confidence(IntEnum):
    """Higher value = more certain the finding is valid."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


class Protocol(StrEnum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    DNS = "DNS"
    FTP = "FTP"
    SMTP = "SMTP"


class RiskLabel(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class AnalysisStatus(StrEnum):
    QUEUED = "queued"
    PARSING = "parsing"
    EXTRACTING = "extracting"
    DETECTING = "detecting"
    ASSESSING = "assessing"
    COMPLETED = "completed"
    FAILED = "failed"
