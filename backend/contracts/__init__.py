"""NetMind AI backend contracts.

Interface contracts between pipeline stages.
See DETECTION-PIPELINE.md for the full design.
"""

from .ai_context import AIContext, CaptureInfo, ProtocolSummary
from .ai_output import AIAssessment, AIFinding, FindingRationale, RemediationStep, SecurityReport
from .enums import (
    AnalysisStatus,
    Confidence,
    Protocol,
    RiskLabel,
    Severity,
)
from .features import (
    AggregatedFeatures,
    ConnectionProfile,
    DNSProfile,
    FlowRecord,
    FTPFlow,
    SMTPFlow,
    TrafficBaseline,
    TrafficDeviation,
)
from .findings import Evidence, Finding, OverallRiskScore
from .parser_output import (
    ParsedDNS,
    ParsedFTP,
    ParsedHTTP,
    ParsedPacket,
    ParsedProtocols,
    ParsedSMTP,
)

__all__ = [
    "AIAssessment",
    "AIContext",
    "AIFinding",
    "AggregatedFeatures",
    "AnalysisStatus",
    "CaptureInfo",
    "Confidence",
    "ConnectionProfile",
    "DNSProfile",
    "Evidence",
    "Finding",
    "FindingRationale",
    "FlowRecord",
    "FTPFlow",
    "OverallRiskScore",
    "ParsedDNS",
    "ParsedFTP",
    "ParsedHTTP",
    "ParsedPacket",
    "ParsedProtocols",
    "ParsedSMTP",
    "Protocol",
    "ProtocolSummary",
    "RemediationStep",
    "RiskLabel",
    "SMTPFlow",
    "SecurityReport",
    "Severity",
    "TrafficBaseline",
    "TrafficDeviation",
]
