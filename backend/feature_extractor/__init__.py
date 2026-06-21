"""Feature Extraction Layer for NetMind AI.

Converts raw parsed packets (ParsedProtocols) into aggregated network
security features (AggregatedFeatures) for Rule Engine consumption.

Provides:
    - FlowBuilder: groups packets into bidirectional 5-tuple flows
    - ConnectionProfileBuilder: per-source-IP behavioral profiles
    - DNSProfileBuilder: per-domain DNS analysis with entropy
    - HTTPSummaryBuilder: HTTP method/status/top-URI aggregation
    - FTPSummaryBuilder: per-IP FTP auth rate
    - SMTPSummaryBuilder: per-IP SMTP message rate
    - TrafficBaselineComputer: global baseline + per-flow deviations
    - FeatureExtractor: orchestrator tying all builders together
"""

from .connection_profiles import ConnectionProfileBuilder
from .dns_profiles import DNSProfileBuilder
from .extractor import FeatureExtractor, extract_features
from .flow_builder import FlowBuilder
from .ftp_summary import FTPSummaryBuilder
from .http_summary import HTTPSummaryBuilder
from .smtp_summary import SMTPSummaryBuilder
from .traffic_baseline import TrafficBaselineComputer

__all__ = [
    "FeatureExtractor",
    "extract_features",
    "FlowBuilder",
    "ConnectionProfileBuilder",
    "DNSProfileBuilder",
    "HTTPSummaryBuilder",
    "FTPSummaryBuilder",
    "SMTPSummaryBuilder",
    "TrafficBaselineComputer",
]
