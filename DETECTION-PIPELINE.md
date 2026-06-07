# NetMind AI — Detection Pipeline Architecture

## Design Purpose

This document specifies the complete Rule Engine and Detection Pipeline for the NetMind AI MVP. It defines every data boundary, contract, scoring rule, and prompt strategy between the Protocol Parser and the Security Report.

**Status:** Technical Design · Pre-implementation  
**Applies to:** MVP Stack (FastAPI + PostgreSQL + React + tshark + Ollama)  
**Related:** [ARCHITECTURE.md](./ARCHITECTURE.md), [MVP-AND-ROADMAP.md](./MVP-AND-ROADMAP.md)

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Data Flow Between Components](#2-data-flow-between-components)
3. [Pydantic Interface Contracts](#3-pydantic-interface-contracts)
4. [Plugin-Based Rule Architecture](#4-plugin-based-rule-architecture)
5. [MVP Detection Rules](#5-mvp-detection-rules)
6. [Findings Model](#6-findings-model)
7. [Risk Score System](#7-risk-score-system)
8. [AI Assessor Input Format](#8-ai-assessor-input-format)
9. [AI Assessor Prompt Strategy](#9-ai-assessor-prompt-strategy)
10. [Data Classification](#10-data-classification)
11. [End-to-End Detection Flow Example](#11-end-to-end-detection-flow-example)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         DETECTION PIPELINE                          │
│                                                                     │
│  ┌──────────────┐   ┌─────────────────┐   ┌──────────────────────┐  │
│  │    PCAP      │   │  Protocol Parser │   │  Feature Extractor   │  │
│  │  (.pcapng)  │──▶│   (tshark)       │──▶│  (aggregation +      │  │
│  │              │   │                  │   │   statistics)        │  │
│  └──────────────┘   │  Output:         │   │                      │  │
│                     │  ParsedPacket[]  │   │  Output:             │  │
│                     │  ParsedDNS[]     │   │  AggregatedFeatures  │  │
│                     │  ParsedHTTP[]    │   │  FlowRecord[]        │  │
│                     │  ParsedFTP[]     │   │  ConnectionProfile[] │  │
│                     │  ParsedSMTP[]    │   │  DNSProfile[]        │  │
│                     └─────────────────┘   └──────────┬───────────┘  │
│                                                       │              │
│                                                       ▼              │
│  ┌────────────────┐   ┌──────────────────────┐   ┌────────────────┐  │
│  │  AI Assessor   │◀──│     Rule Engine      │◀──│   Features     │  │
│  │  (Ollama LLM)  │   │                      │   │                │  │
│  │                │   │  ┌──────────────────┐│   │                │  │
│  │  Input:        │   │  │  RuleRegistry    ││   │                │  │
│  │  AIContext     │   │  │  ├─ PortScanRule ││   │                │  │
│  │                │   │  │  ├─ DNSTunRule   ││   │                │  │
│  │  Output:       │   │  │  ├─ FTPBruteRule ││   │                │  │
│  │  SecurityReport│   │  │  ├─ SMTPAbuseRule││   │                │  │
│  │                │   │  │  └─ TrafficVolRl ││   │                │  │
│  └────────┬───────┘   │  └──────────────────┘│   └────────────────┘  │
│           │           │                      │                        │
│           ▼           │  Output: Finding[]   │                        │
│  ┌────────────────┐   │  Output:             │                        │
│  │ SecurityReport │   │  OverallRiskScore    │                        │
│  │ (DB + API)     │   └──────────────────────┘                        │
│  └────────────────┘                                                   │
└─────────────────────────────────────────────────────────────────────┘
```

### Component Roles

| Component | Role | Consumes | Produces |
|---|---|---|---|
| **Protocol Parser** | Reads PCAP via tshark, extracts typed protocol records | PCAP file on disk | ParsedPacket[], ParsedDNS[], ParsedHTTP[], ParsedFTP[], ParsedSMTP[] |
| **Feature Extractor** | Aggregates raw records into behavioral features, computes statistics | Parsed*[] records | AggregatedFeatures, FlowRecord[], DNSProfile[], etc. |
| **Rule Engine** | Evaluates features against rule set, produces findings | AggregatedFeatures | Finding[], OverallRiskScore |
| **AI Assessor** | Synthesizes findings + context into natural-language report | AIContext (features + findings + scores) | SecurityReport |

---

## 2. Data Flow Between Components

### Pipeline Stage Sequence

```
Protocol Parser ──[ParsedPacket[]]──▶ Feature Extractor
                                          │
                                          ▼
Feature Extractor ──[AggregatedFeatures]──▶ Rule Engine
                                               │
                                               ▼
Rule Engine ──[Finding[] + OverallRiskScore]──▶ AI Assessor
                                                   │
                                                   ▼
AI Assessor ──[SecurityReport]──▶ Storage + Frontend API
```

### What Each Stage Reads and Writes

**Stage 1: Protocol Parser** (`pcap object` → `parsed_protocols`)
- Reads: PCAP file from disk/Docker volume
- Writes to DB: no packet rows; protocol records and flows are persisted by later stages
- Writes to pipeline: `ParsedProtocols` context object (in-memory, passed to next stage)

**Stage 2: Feature Extractor** (`parsed_records` → `aggregated_features`)
- Reads from memory: Parsed protocol records for this PCAP
- Computes: Flow aggregation, connection profiles, DNS entropy, traffic baselines
- Writes to DB: aggregated `flows`
- Writes to pipeline: `AggregatedFeatures` (in-memory)

**Stage 3: Rule Engine** (`features` → `findings`)
- Reads: `AggregatedFeatures`
- Evaluates: default production MVP rules via `RuleRegistry` (`DNSTunnelingRule`, `HTTPAnomalyRule`, `TopTalkerRule`)
- Writes to DB: `alerts`
- Writes to pipeline: `list[Finding]`, `OverallRiskScore`

**Stage 4: AI Assessor** (`findings + context` → `report`)
- Reads: `AIContext` (features + findings + scores)
- Invokes: Ollama `/api/generate` with structured prompt
- Writes to DB: `ai_assessments`
- Writes to pipeline: `SecurityReport`

### Data Flow Constraints (Design Rules)

1. **No stage writes to disk that the next stage must re-read.** The pipeline passes in-memory context objects. This avoids unnecessary I/O.
2. **The DB is the source of truth for persistence, not the pipeline context.** Each stage also persists its outputs to relevant DB tables.
3. **Stages are idempotent.** Running the same pcap_id through the same stage twice produces the same results (assuming tshark version and rule code are unchanged).
4. **Stage failure does not block downstream.** If Rule Engine succeeds but AI Assessor fails, findings are already persisted and can be viewed. The AI report is a post-hoc enrichment.

---

## 3. Pydantic Interface Contracts

All contracts live in `backend/contracts/`. Every module imports its consumer contracts — never the other way around.

### 3.1 Contract Directory Layout

```
backend/contracts/
  __init__.py
  parser_output.py     # Protocol Parser → Feature Extractor
  features.py          # Feature Extractor → Rule Engine
  findings.py          # Rule Engine → everywhere (DB, API, AI Assessor)
  risk_score.py        # Risk scoring types
  ai_context.py        # Rule Engine → AI Assessor (full context)
  ai_output.py         # AI Assessor → Storage/API
  enums.py             # Shared enums (Severity, Confidence, Protocol, etc.)
```

### 3.2 Shared Enums (`enums.py`)

```python
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
    LOW = 1      # Weak signal, high false positive probability
    MEDIUM = 2   # Moderate signal, plausible but verify
    HIGH = 3     # Strong signal, low false positive probability

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
```

### 3.3 Protocol Parser Output (`parser_output.py`)

**Boundary:** Protocol Parser → Feature Extractor

```python
from pydantic import BaseModel, Field
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID
from .enums import Protocol

class ParsedPacket(BaseModel):
    """A single packet from the PCAP. One row per packet."""
    pcap_id: UUID
    packet_number: int
    timestamp: datetime
    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    src_port: int | None = None
    dst_port: int | None = None
    protocol: Protocol
    length: int
    info: str | None = None

class ParsedDNS(BaseModel):
    """DNS query/response pair extracted from the PCAP."""
    pcap_id: UUID
    timestamp: datetime
    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    qname: str
    qtype: str
    response_code: str | None = None
    answers: list[str] = Field(default_factory=list)
    query_size_bytes: int | None = None

class ParsedHTTP(BaseModel):
    """HTTP request metadata extracted from the PCAP."""
    pcap_id: UUID
    timestamp: datetime
    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    method: str
    host: str
    uri: str
    status_code: int | None = None
    user_agent: str | None = None
    content_type: str | None = None
    request_length: int | None = None

class ParsedFTP(BaseModel):
    """FTP control-channel command or response."""
    pcap_id: UUID
    timestamp: datetime
    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    command: str
    argument: str | None = None
    response_code: int | None = None
    response_message: str | None = None

class ParsedSMTP(BaseModel):
    """SMTP command or response."""
    pcap_id: UUID
    timestamp: datetime
    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    command: str
    argument: str | None = None
    response_code: int | None = None
    mail_from: str | None = None
    rcpt_to: list[str] | None = None

class ParsedProtocols(BaseModel):
    """Fully parsed output of the Protocol Parser stage."""
    pcap_id: UUID
    packets: list[ParsedPacket]
    dns_queries: list[ParsedDNS] = Field(default_factory=list)
    http_requests: list[ParsedHTTP] = Field(default_factory=list)
    ftp_sessions: list[ParsedFTP] = Field(default_factory=list)
    smtp_messages: list[ParsedSMTP] = Field(default_factory=list)
    parser_version: str  # tshark version used
    parse_duration_ms: int
```

### 3.4 Feature Extractor Output (`features.py`)

**Boundary:** Feature Extractor → Rule Engine (the primary input to every rule)

```python
from pydantic import BaseModel, Field
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID

class FlowRecord(BaseModel):
    """Aggregated 5-tuple flow: bidirectional conversation metadata."""
    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    src_port: int
    dst_port: int
    protocol: str
    packets_total: int
    bytes_total: int
    duration_ms: float
    start_time: datetime
    end_time: datetime
    src_bytes: int
    dst_bytes: int
    syn_count: int = 0
    rst_count: int = 0

class ConnectionProfile(BaseModel):
    """Per-source-IP behavioral summary."""
    src_ip: IPv4Address | IPv6Address
    unique_dst_ips: int
    unique_dst_ports: int
    total_connections: int
    failed_connections: int       # SYN sent, no SYN-ACK or RST received
    success_connections: int      # Completed TCP handshake
    total_bytes_sent: int
    total_packets_sent: int
    first_seen: datetime
    last_seen: datetime
    distinct_protocols: list[str]

class DNSProfile(BaseModel):
    """Per-domain behavioral summary for DNS analysis."""
    qname: str                      # Fully qualified domain name
    query_count: int
    unique_qtypes: list[str]
    subdomain_entropy: float        # Shannon entropy of leftmost label
    avg_query_size_bytes: float
    response_success_rate: float    # 0.0 = all failed, 1.0 = all success
    ttl_values: list[int]
    src_ips: list[str]

class TrafficBaseline(BaseModel):
    """Expected traffic profile for the capture window."""
    expected_bytes_per_second: float
    expected_packets_per_second: float
    total_bytes: int
    total_packets: int
    duration_seconds: float
    unique_src_ips: int
    unique_dst_ips: int
    protocol_percentages: dict[str, float]  # e.g. {"TCP": 78.5, "UDP": 20.0}

class TrafficDeviation(BaseModel):
    """Per-flow or per-IP deviation from baseline."""
    src_ip: IPv4Address | IPv6Address
    dst_ip: IPv4Address | IPv6Address
    bytes_exceeded_pct: float      # How much above expected
    packets_per_second: float
    bytes_per_second: float
    is_upload_dominated: bool       # True if outbound > 70% of total

class FTPFlow(BaseModel):
    """FTP session-level summary."""
    src_ip: IPv4Address | IPv6Address
    failed_auth_count: int
    success_auth_count: int
    total_commands: int
    auth_rate_per_second: float | None = None

class SMTPFlow(BaseModel):
    """SMTP session-level summary."""
    src_ip: IPv4Address | IPv6Address
    message_count: int
    unique_recipients: int
    failed_auth_count: int
    total_connections: int
    avg_message_size_bytes: float | None = None

class AggregatedFeatures(BaseModel):
    """Complete feature set for Rule Engine consumption."""
    pcap_id: UUID
    capture_duration_seconds: float
    time_window_start: datetime
    time_window_end: datetime

    # Global traffic
    traffic_baseline: TrafficBaseline
    traffic_deviations: list[TrafficDeviation] = Field(default_factory=list)

    # Per-connection behavioral profiles
    connection_profiles: list[ConnectionProfile] = Field(default_factory=list)
    flows: list[FlowRecord] = Field(default_factory=list)

    # Protocol-specific profiles
    dns_profiles: list[DNSProfile] = Field(default_factory=list)
    ftp_flows: list[FTPFlow] = Field(default_factory=list)
    smtp_flows: list[SMTPFlow] = Field(default_factory=list)

    # HTTP aggregations (lightweight counts, not profiles)
    http_method_counts: dict[str, int] = Field(default_factory=dict)
    http_status_counts: dict[int, int] = Field(default_factory=dict)
    http_top_uris: list[tuple[str, int]] = Field(default_factory=list)
    http_user_agents: list[str] = Field(default_factory=list)

    # Feature extraction metadata
    extractor_version: str
    extraction_duration_ms: int
```

### 3.5 Findings and Risk Score (`findings.py`, `risk_score.py`)

**Boundary:** Rule Engine → AI Assessor, also Rule Engine → DB/API

```python
from pydantic import BaseModel, Field
from datetime import datetime
from uuid import UUID, uuid4
from .enums import Severity, Confidence, RiskLabel

class Evidence(BaseModel):
    """Specific feature values that triggered a rule."""
    key: str                         # e.g. "failed_auth_count"
    value: float | int | str
    threshold: float | int | str     # The threshold this value exceeded
    unit: str | None = None          # e.g. "count", "entropy", "bytes/sec"

class Finding(BaseModel):
    """A single detection result from a rule."""
    id: UUID = Field(default_factory=uuid4)
    pcap_id: UUID
    
    # Rule identification
    rule_id: str
    rule_name: str
    rule_version: str
    
    # Detection results
    severity: Severity
    confidence: Confidence
    risk_score: int                  # 0-100, computed by risk scorer
    
    # Human-readable
    title: str
    description: str
    recommendation: str
    
    # Structured evidence
    evidences: list[Evidence] = Field(default_factory=list)
    affected_entities: list[str] = Field(default_factory=list)
    
    # Timing
    timestamp_start: datetime
    timestamp_end: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Raw scoring internals (not shown in API output)
    raw_score: float                 # Pre-normalized detection strength
    feature_snapshot: dict[str, float] = Field(default_factory=dict)

class OverallRiskScore(BaseModel):
    """Aggregated risk score for the entire analysis."""
    max_score: int                   # 0-100: worst single finding
    weighted_score: int              # 0-100: max + bonus for other findings
    severity_label: RiskLabel
    total_findings: int
    findings_by_severity: dict[str, int]  # e.g. {"HIGH": 2, "MEDIUM": 1}
    top_finding_ids: list[UUID]      # Sorted by risk_score descending
```

### 3.6 AI Context and Output (`ai_context.py`, `ai_output.py`)

**Boundary:** Rule Engine → AI Assessor

```python
from pydantic import BaseModel, Field
from datetime import datetime
from uuid import UUID
from .enums import Severity, Confidence, RiskLabel

class CaptureInfo(BaseModel):
    """Minimal capture metadata for LLM context."""
    filename: str
    file_size_mb: float
    duration_seconds: float
    total_packets: int
    total_bytes: int
    unique_ips: int

class ProtocolSummary(BaseModel):
    """Top-N protocol distribution for LLM context."""
    top_protocols: list[dict]       # [{"protocol": "TCP", "percentage": 78.5}]
    top_talkers: list[dict]         # [{"ip": "10.0.0.5", "bytes": 9000000, "direction": "outbound"}]
    total_domains_queried: int
    total_http_requests: int

class AIContext(BaseModel):
    """Complete context sent to the AI Assessor."""
    capture_info: CaptureInfo
    protocol_summary: ProtocolSummary
    findings: list[dict]             # Purposely simplified dicts, not Finding objects
    overall_risk: OverallRiskScore
    feature_summary: dict            # Key aggregate numbers only
    
class AIFinding(BaseModel):
    """Finding as represented in AI output (simplified)."""
    severity: str
    title: str
    evidence_summary: str | None = None

class SecurityReport(BaseModel):
    """Output from the AI Assessor."""
    risk_score: int                  # 0-100
    risk_label: str
    executive_summary: str
    key_findings: list[AIFinding]
    recommendations: list[str]
    model_confidence: float          # 0.0-1.0, LLM self-assessed
    technical_context: str | None = None
    
    # Metadata
    model_name: str
    model_version: str | None = None
    generation_time_ms: int
    prompt_token_count: int
    generated_at: datetime = Field(default_factory=datetime.utcnow)
```

---

## 4. Plugin-Based Rule Architecture

### 4.1 Design Overview

The Rule Engine uses a **Registry pattern** where rules are self-discovering, order-independent units. Adding a new rule requires exactly one new file — no existing files are modified.

```
registry/
  __init__.py
  rule_registry.py       # Auto-discovery + orchestration
  base_rule.py           # Abstract base class
rules/
  __init__.py            # Re-exports for easy registration
  port_scan_rule.py
  dns_tunneling_rule.py
  ftp_brute_force_rule.py
  smtp_abuse_rule.py
  suspicious_traffic_rule.py
```

### 4.2 Rule Interface (Abstract Base)

Every rule must implement this interface:

```python
class BaseRule(ABC):
    """Abstract base for all detection rules."""

    # Identity (set as class attributes, not instance)
    rule_id: str                         # e.g. "netmind.port_scan.v1"
    rule_name: str                       # e.g. "Port Scan Detection"
    rule_version: str                    # e.g. "1.0.0"
    description: str
    severity: Severity                   # Default severity if triggered
    default_enabled: bool = True

    @abstractmethod
    def required_features(self) -> list[str]:
        """Returns feature field paths this rule needs.
        
        Used by the pipeline to validate that the Feature Extractor
        has produced all required data before this rule runs.
        Example: ["dns_profiles", "connection_profiles"]
        """
        ...

    @abstractmethod
    def evaluate(self, features: AggregatedFeatures) -> Finding | None:
        """Evaluate features and return a Finding if triggered.
        
        Returns None when no detection occurs.
        Must be pure — no side effects, no DB access.
        """
        ...
```

### 4.3 RuleRegistry Behavior

```python
class RuleRegistry:
    """Orchestrates rule discovery, validation, and execution."""
    
    def discover_rules(self) -> list[BaseRule]:
        """Auto-discovers + instantiates all BaseRule subclasses.
        
        Discovery strategies (MVP: explicit import scan):
        1. Scan `rules/` package for BaseRule subclasses
        2. Allow explicit registration via decorator
        
        Returns instantiated rule objects sorted by priority.
        """
        ...
    
    def validate_features(self, rules: list[BaseRule],
                          features: AggregatedFeatures) -> list[str]:
        """Checks all required_features exist in features.
        
        Returns list of missing feature paths. If non-empty, the
        pipeline should fail before rule evaluation begins.
        """
        ...
    
    def evaluate_all(self, features: AggregatedFeatures) -> list[Finding]:
        """Evaluates all enabled rules against features.
        
        Rules are evaluated in priority order (most severe first).
        Each rule is independent — evaluation is parallelizable.
        
        Returns list of Findings (empty list if no detections).
        """
        ...
```

### 4.4 Adding a New Rule (Extension Pattern)

To add a new rule, a developer:

1. Creates `backend/engine/rules/new_rule.py`
2. Subclasses `BaseRule`
3. Implements `rule_id`, `rule_name`, `rule_version`, `description`, `severity`
4. Implements `required_features()` — returns list of feature paths
5. Implements `evaluate(features) -> Finding | None`

**No existing files are touched.** The RuleRegistry auto-discovers the new subclass. The Rule Engine pipeline picks it up on next analysis.

### 4.5 Rule Execution Order

Rules are evaluated in **severity-descending order** (Critical rules first). Since all rules are independent (no rule depends on another rule's output), this is purely a UX convention — Critical findings appear first in the report.

```
Execution: PortScan ──▶ DNSTunneling ──▶ FTPBruteForce ──▶ SMTPAbuse ──▶ TrafficVol
              (parallel if async, sequential if sync — order-independent logic)
```

---

## 5. MVP Detection Rules

### 5.1 Port Scan Detection

| Property | Definition |
|---|---|
| **Rule ID** | `netmind.port_scan.v1` |
| **Default Severity** | MEDIUM |
| **Description** | Detects reconnaissance behavior: a single source contacting many unique destination ports in a short window. |

#### Detection Logic

```
1. Group flows by source IP
2. For each source IP in connection_profiles:
   a. Count unique_dst_ports
   b. Count failed_connections (SYN sent, no SYN-ACK)
3. If unique_dst_ports >= PORT_THRESHOLD_HIGH
   OR failed_connections >= FAIL_THRESHOLD:
     → Trigger finding
   Elif unique_dst_ports >= PORT_THRESHOLD_MED
   OR failed_connections >= FAIL_THRESHOLD_MED:
     → Trigger finding with lower confidence
```

#### Required Features

```
connection_profiles[].unique_dst_ports
connection_profiles[].failed_connections
connection_profiles[].total_connections
connection_profiles[].distinct_protocols
connection_profiles[].first_seen
connection_profiles[].last_seen
```

#### Thresholds

| Parameter | Threshold | Rationale |
|---|---|---|
| `PORT_THRESHOLD_HIGH` | 50 unique ports | Strong evidence of scan |
| `PORT_THRESHOLD_MED` | 20 unique ports | Weak evidence, possible benign |
| `FAIL_THRESHOLD` | 20 failed connections | Indicates no-response scan |
| `TIME_WINDOW_MIN` | 60 seconds | Window for rate calculation |

#### Risk Scoring

```
raw_score = min(100, (unique_ports / 50) * 60 + (failed_connections / 20) * 40)

severity mapping:
  unique_ports >= 50  → HIGH
  unique_ports >= 20  → MEDIUM
  failed >= 20        → MEDIUM
  Otherwise           → LOW
```

#### False Positive Considerations

| Source | Mitigation |
|---|---|
| Service discovery / CMDB scanners (nmap, Nesus) | Whitelist known scanners via env config |
| P2P applications (BitTorrent) | High port counts to multiple IPs, not single IP |
| Web browsers (many tabs) | HTTP-only ports (80,443), diverse but legitimate |
| Health checkers / load balancers | Known IPs, periodic pattern, low data volume |

---

### 5.2 DNS Tunneling Detection

| Property | Definition |
|---|---|
| **Rule ID** | `netmind.dns_tunneling.v1` |
| **Default Severity** | HIGH |
| **Description** | Detects DNS-based data exfiltration through high-entropy subdomains, excessive query rates, or unusual record types. |

#### Detection Logic

```
1. For each domain in dns_profiles:
   a. Compute subdomain_entropy of the leftmost label
      (Shannon entropy: -Σ p(x) · log₂ p(x), character-level)
   b. Compute query_rate = query_count / capture_duration_seconds
   c. Check for unusual qtypes (TXT, NULL, ANY, CNAME chains)
   d. Check avg_query_size_bytes > 100
2. Score each domain independently
3. Trigger finding if ANY threshold is exceeded
```

#### Required Features

```
dns_profiles[].qname
dns_profiles[].query_count
dns_profiles[].subdomain_entropy
dns_profiles[].avg_query_size_bytes
dns_profiles[].unique_qtypes
dns_profiles[].response_success_rate
```

#### Thresholds

| Parameter | Threshold | Rationale |
|---|---|---|
| `ENTROPY_HIGH` | 4.5 | Random/Base32 subdomain indicator |
| `ENTROPY_MED` | 4.0 | Suspicious, worth flagging |
| `QUERY_RATE_HIGH` | 100 q/min | Abnormally high for any domain |
| `QUERY_SIZE_HIGH` | 150 bytes | DNS tunneling tools use large queries |
| `UNUSUAL_TYPES` | TXT, NULL, ANY, MX | Commonly used for covert channels |

#### Risk Scoring

```
entropy_score   = min(100, max(0, (entropy - 3.0) / 2.0 * 100))
rate_score      = min(100, query_rate / 100 * 100)  
size_score      = min(100, avg_query_size / 150 * 100)
type_bonus      = 30 if unusual_type in qtypes else 0

raw_score = entropy_score * 0.4 + rate_score * 0.3 + size_score * 0.2 + type_bonus * 0.1

If entropy > 4.5 AND rate > 50:                → HIGH
If entropy > 4.0 OR query_size > 150:          → MEDIUM
If only one weak signal:                        → LOW
```

#### False Positive Considerations

| Source | Mitigation |
|---|---|
| CDN subdomains (content hash in URL) | Check domain reputation — CDN domains are known |
| Dynamic DNS providers | Maintain a allowlist of known DDNS providers |
| IoT device identifiers | UUID-style hostnames from devices |
| Long Session IDs in hostnames | Some SaaS/CASB systems use subdomain routing |

---

### 5.3 FTP Brute Force Detection

| Property | Definition |
|---|---|
| **Rule ID** | `netmind.ftp_bruteforce.v1` |
| **Default Severity** | HIGH |
| **Description** | Detects rapid failed FTP authentication attempts indicative of password guessing attacks. |

#### Detection Logic

```
1. For each src_ip in ftp_flows:
   a. Count failed_auth_count (response codes 530, 530, etc.)
   b. Compute auth_rate = failed_auth_count / session_duration
   c. Check if any successful auth occurred after failures
2. Trigger if thresholds exceeded
3. If successful auth AFTER brute force pattern, escalate severity
```

#### Required Features

```
ftp_flows[].src_ip
ftp_flows[].failed_auth_count
ftp_flows[].success_auth_count
ftp_flows[].total_commands
ftp_flows[].auth_rate_per_second
```

#### Thresholds

| Parameter | Threshold | Rationale |
|---|---|---|
| `FAIL_COUNT_HIGH` | 15 | Strong indicator of brute force |
| `FAIL_COUNT_MED` | 5 | Suspicious volume |
| `AUTH_RATE_HIGH` | 0.5/sec (1 per 2s) | Automated tool rate |
| `TIME_WINDOW` | Full capture | FTP is session-based, use entire session |

#### Risk Scoring

```
count_score = min(100, (failed_count / 15) * 100)
rate_score  = min(100, auth_rate / 0.5 * 100) if auth_rate else 0
breach_bonus = 30 if success_count > 0 AND failed_count >= FAIL_COUNT_MED

raw_score = count_score * 0.6 + rate_score * 0.4 + breach_bonus

If failed >= 15:                                    → HIGH
If failed >= 5 AND breach_bonus:                     → CRITICAL (account compromised)
If 5 <= failed < 15:                                 → MEDIUM
If failed < 5:                                       → LOW (too few attempts)
```

#### False Positive Considerations

| Source | Mitigation |
|---|---|
| Users mistyping passwords | Low rate (< 0.1/sec), few attempts |
| Automated deployment scripts | Known IP whitelist, consistent timing |
| Password rotation services | Known IP, predictable timing |
| Legacy systems retrying connections | Check for repeated same-credential attempts |

---

### 5.4 SMTP Abuse Detection

| Property | Definition |
|---|---|
| **Rule ID** | `netmind.smtp_abuse.v1` |
| **Default Severity** | MEDIUM |
| **Description** | Detects SMTP traffic patterns consistent with spam delivery, mule activity, or unauthorized relay usage. |

#### Detection Logic

```
1. For each src_ip in smtp_flows:
   a. Check message_count
   b. Check unique_recipients
   c. Check failed_auth_count
   d. Compute recipient_rate = unique_recipients / capture_duration
2. Also check raw SMTP commands for protocol violations
   (MAIL FROM without prior EHLO)
3. Trigger if any behavioral threshold is exceeded
```

#### Required Features

```
smtp_flows[].src_ip
smtp_flows[].message_count
smtp_flows[].unique_recipients
smtp_flows[].failed_auth_count
smtp_flows[].total_connections
smtp_flows[].avg_message_size_bytes
```

#### Thresholds

| Parameter | Threshold | Rationale |
|---|---|---|
| `MSG_COUNT_HIGH` | 50 messages in 5 min | Spam bot indicator |
| `RECIPIENT_HIGH` | 20 unique recipients in 5 min | Mass mailing indicator |
| `AUTH_FAIL_HIGH` | 5 failed auth | Credential stuffing on SMTP |
| `MSG_SIZE_SUSPICIOUS` | < 200 bytes avg | Spam messages are small |

#### Risk Scoring

```
msg_score     = min(100, message_count / 50 * 100)
recip_score   = min(100, unique_recipients / 20 * 100)
auth_score    = min(100, failed_auth_count / 5 * 100)

raw_score = msg_score * 0.4 + recip_score * 0.4 + auth_score * 0.2

If msg_count >= 50 OR unique_recipients >= 20: → HIGH
If (msg_count >= 10 OR unique_recipients >= 5): → MEDIUM
Otherwise:                                      → LOW
```

#### False Positive Considerations

| Source | Mitigation |
|---|---|
| Mailing list servers | Check for mail_from matching a known list domain |
| Monitoring/alerting systems | Known IP whitelist, periodic pattern |
| CRM bulk email | Corporate outbound gateways |
| Email migration tools | One-time bulk transfer, known IP |

---

### 5.5 Suspicious Traffic Volume Detection

| Property | Definition |
|---|---|
| **Rule ID** | `netmind.suspicious_volume.v1` |
| **Default Severity** | HIGH |
| **Description** | Detects anomalously high traffic volumes to a single destination, asymmetric bandwidth usage, or extreme deviations from baseline. |

#### Detection Logic

```
1. Compute global traffic_baseline from entire capture
2. For each traffic_deviation:
   a. Check bytes_exceeded_pct against threshold
   b. Check is_upload_dominated ratio
   c. Check bytes_per_second against absolute threshold
3. For each flow, check total_bytes to single destination
4. Trigger if any volume anomaly is detected
```

#### Required Features

```
traffic_baseline.expected_bytes_per_second
traffic_baseline.expected_packets_per_second
traffic_baseline.total_bytes
traffic_deviations[].bytes_exceeded_pct
traffic_deviations[].is_upload_dominated
traffic_deviations[].bytes_per_second
flows[].bytes_total
flows[].src_ip
flows[].dst_ip
```

#### Thresholds

| Parameter | Threshold | Rationale |
|---|---|---|
| `DEVIATION_HIGH` | 10x baseline | Extreme anomaly |
| `DEVIATION_MED` | 5x baseline | Notable anomaly |
| `UPLOAD_DOMINATED` | > 70% outbound to single IP | Data exfiltration pattern |
| `ABSOLUTE_VOLUME` | 100MB in 5 min to single IP | Large data transfer |

#### Risk Scoring

```
deviation_score  = min(100, (bytes_exceeded_pct / 10) * 100)
upload_score     = 70 if is_upload_dominated AND deviation_score > 50 else 0
volume_score     = min(100, total_bytes_to_dst_mb / 100 * 100)

raw_score = deviation_score * 0.5 + max(upload_score, volume_score * 0.5)

If deviation >= 10x OR (volume >= 100MB AND is_upload_dominated): → CRITICAL
If deviation >= 5x OR volume >= 100MB:                            → HIGH
If deviation >= 2x:                                               → MEDIUM
Otherwise:                                                         → LOW
```

#### False Positive Considerations

| Source | Mitigation |
|---|---|
| Large file backups (rsync, S3 sync) | Known cloud IPs, consistent volume |
| Video conferencing | Symmetric traffic (not upload-dominated) |
| Software updates | CDN IPs, periodic spikes |
| Cloud storage sync | Known application ports |

---

## 6. Findings Model

### 6.1 Canonical Finding Structure

```python
class Evidence(BaseModel):
    """One specific piece of evidence supporting a finding."""
    key: str                         # Feature name that triggered
    value: float | int | str         # Observed value
    threshold: float | int | str     # Threshold exceeded
    unit: str | None = None          # Optional metric unit

class Finding(BaseModel):
    """Canonical detection result, produced by rules."""
    
    # === Identity ===
    id: UUID                         # Unique per-finding identifier
    pcap_id: UUID                    # Parent analysis
    rule_id: str                     # Rule that produced this
    rule_name: str
    rule_version: str
    
    # === Severity & Confidence ===
    severity: Severity               # INFORMATIONAL | LOW | MEDIUM | HIGH | CRITICAL
    confidence: Confidence            # LOW | MEDIUM | HIGH
    risk_score: int                  # 0-100 computed score
    
    # === Human-readable ===
    title: str                       # "Port Scan Detected from 10.0.0.5"
    description: str                 # Detailed behavior description
    recommendation: str              # Actionable mitigation
    
    # === Evidence ===
    evidences: list[Evidence]        # Feature values that triggered detection
    affected_entities: list[str]     # IPs, domains, user agents involved
    
    # === Temporal ===
    timestamp_start: datetime        # When suspicious activity began
    timestamp_end: datetime          # When it ended (or last observed)
    created_at: datetime             # When the finding was generated
```

### 6.2 Finding Example (Port Scan)

```json
{
  "id": "f1a2b3c4-d5e6-7890-abcd-ef1234567890",
  "pcap_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "rule_id": "netmind.port_scan.v1",
  "rule_name": "Port Scan Detection",
  "rule_version": "1.0.0",
  
  "severity": "HIGH",
  "confidence": "HIGH",
  "risk_score": 85,
  
  "title": "Port Scan Detected from 10.0.0.5",
  "description": "Source IP 10.0.0.5 contacted 67 unique ports on 10.0.0.1 within 45 seconds. 22 connections failed or received RST responses, consistent with automated port scanning.",
  "recommendation": "Investigate 10.0.0.5 for compromised host or unauthorized scanning. Review firewall logs and isolate the host if scanning is unauthorized.",
  
  "evidences": [
    {"key": "unique_dst_ports", "value": 67, "threshold": 20, "unit": "ports"},
    {"key": "failed_connections", "value": 22, "threshold": 20, "unit": "connections"}
  ],
  "affected_entities": ["10.0.0.5"],
  
  "timestamp_start": "2026-06-04T12:01:00Z",
  "timestamp_end": "2026-06-04T12:01:45Z",
  "created_at": "2026-06-04T12:05:00Z"
}
```

### 6.3 Finding Persistence (DB Mapping)

The `Finding` model maps to the `alerts` table with flattened fields:

| Finding Field | DB Column | Type |
|---|---|---|
| `id` | `alerts.id` | UUID |
| `pcap_id` | `alerts.pcap_id` | UUID (FK) |
| `rule_id` | `alerts.rule_id` | TEXT |
| `severity` | `alerts.severity` | TEXT (enum string) |
| `title` | `alerts.title` | TEXT |
| `description` | `alerts.description` | TEXT |
| `evidences` | `alerts.evidence` | JSONB |
| `rule_name` + `rule_version` | Embedded in `alerts.evidence` | JSONB |
| `confidence` | Embedded in `alerts.evidence` | JSONB |
| `recommendation` | Embedded in `alerts.evidence` | JSONB |
| `affected_entities` | Embedded in `alerts.evidence` | JSONB |
| `risk_score` | Embedded in `alerts.evidence` | JSONB |
| `timestamp_start` → `alerts.triggered_at` | `alerts.triggered_at` | TIMESTAMPTZ |

---

## 7. Risk Score System

### 7.1 Individual Finding Risk Score

Each Finding's `risk_score` (0-100) is computed from three factors:

```
risk_score = clamp(0, round(raw_score × severity_weight × confidence_weight), 100)
```

**Severity weight:**

| Severity | Weight | Rationale |
|---|---|---|
| CRITICAL | 1.0 | Immediate attention required |
| HIGH | 0.8 | Investigation priority |
| MEDIUM | 0.5 | Should review soon |
| LOW | 0.2 | Worth noting |
| INFORMATIONAL | 0.05 | Context only |

**Confidence weight:**

| Confidence | Weight | Rationale |
|---|---|---|
| HIGH | 1.0 | Low false positive risk |
| MEDIUM | 0.6 | Might be benign |
| LOW | 0.3 | Likely false positive, barely triggered threshold |

**Example computation:**
```
raw_score = 72 (from Port Scan rule)
severity = HIGH (0.8)
confidence = HIGH (1.0)
risk_score = round(72 * 0.8 * 1.0) = 58
```

### 7.2 Overall Analysis Risk Score

**Formula: Worst-First with Bonus**

```
weighted_score = max_score + sum_of_top_3_bonuses

where:
  max_score = max(all findings.risk_score)
  bonus_for_each_additional = (risk_score × 0.05)
  sum_of_top_3_bonuses = sum of (top 3 additional scores × 0.05)
  
  weighted_score = clamp(0, max_score + sum_of_top_3_bonuses, 100)
```

**Rationale:** In security, the single most severe finding drives the response priority. Additional findings provide modest escalation but never dominate.

**Example:**
```
Findings: [85, 60, 45, 20]
max_score = 85
bonus = (60 + 45 + 20) × 0.05 = 6.25
weighted_score = min(91, 100) = 91
```

### 7.3 Severity Label Mapping

| Score Range | Label | UX Color |
|---|---|---|
| 0-15 | Informational | Gray |
| 16-35 | Low | Blue |
| 36-55 | Medium | Yellow |
| 56-75 | High | Orange |
| 76-100 | Critical | Red |

### 7.4 Risk Score Summary Object

```python
class OverallRiskScore(BaseModel):
    max_score: int                   # Highest single finding score
    weighted_score: int              # max + bonuses, clamped 0-100
    severity_label: RiskLabel        # "Critical", "High", etc.
    total_findings: int
    findings_by_severity: dict[str, int]  # {"HIGH": 2, "MEDIUM": 1}
```

---

## 8. AI Assessor Input Format

### 8.1 AIContext Object (sent to LLM)

The AI Assessor receives exactly one structured JSON object. This is the complete input — no additional context is injected.

```json
{
  "capture_info": {
    "filename": "corp_network_capture.pcapng",
    "file_size_mb": 15.2,
    "duration_seconds": 300,
    "total_packets": 52400,
    "total_bytes": 42000000,
    "unique_ips": 45
  },
  "protocol_summary": {
    "top_protocols": [
      {"protocol": "TCP", "percentage": 78.5},
      {"protocol": "UDP", "percentage": 20.0},
      {"protocol": "ICMP", "percentage": 1.5}
    ],
    "top_talkers": [
      {"ip": "10.0.0.5", "bytes": 9000000, "direction": "outbound"},
      {"ip": "10.0.0.1", "bytes": 8000000, "direction": "inbound"},
      {"ip": "192.168.1.1", "bytes": 5000000, "direction": "outbound"}
    ],
    "total_domains_queried": 87,
    "total_http_requests": 340
  },
  "findings": [
    {
      "severity": "HIGH",
      "confidence": "HIGH",
      "title": "Port Scan Detected from 10.0.0.5",
      "description": "Source IP 10.0.0.5 contacted 67 unique ports on 10.0.0.1 within 45 seconds.",
      "evidence_summary": "67 unique ports; 22 failed connections",
      "affected_entities": ["10.0.0.5"]
    },
    {
      "severity": "MEDIUM",
      "confidence": "MEDIUM",
      "title": "Suspicious DNS Query Volume to ddns.example.com",
      "description": "Domain ddns.example.com received 180 queries in 5 minutes. Subdomain entropy: 4.2.",
      "evidence_summary": "180 queries; entropy 4.2; avg query size 85 bytes",
      "affected_entities": ["ddns.example.com", "10.0.0.102"]
    }
  ],
  "overall_risk": {
    "max_score": 85,
    "weighted_score": 87,
    "severity_label": "HIGH",
    "total_findings": 2,
    "findings_by_severity": {"HIGH": 1, "MEDIUM": 1}
  },
  "feature_summary": {
    "avg_packet_size_bytes": 801,
    "packets_per_second": 174,
    "bytes_per_second": 140000,
    "top_dns_domains": [
      {"domain": "ddns.example.com", "count": 180},
      {"domain": "mail.corp.com", "count": 45}
    ],
    "top_http_hosts": [
      {"host": "api.corp.com", "requests": 120},
      {"host": "cdn.example.com", "requests": 80}
    ],
    "http_methods": {"GET": 200, "POST": 100, "PUT": 40},
    "http_status_codes": {"200": 250, "401": 50, "403": 40}
  }
}
```

### 8.2 What Is NOT Sent to the LLM

| Data | Reason |
|---|---|
| Raw packet bytes/hex | Too large, irrelevant for analysis |
| Full flow records | Redundant with features |
| Individual DNS responses | Only domain-level summaries |
| HTTP request/response bodies | PII risk, too verbose |
| Full evidence objects with internal scores | Contains thresholds, weights — implementation details |
| Pcap_id, user IDs, file paths | Operational metadata, no security value |
| Previous analysis results | Each analysis is independent |

**Rule of thumb for LLM input:** If a human analyst wouldn't need it to write an executive summary, the LLM doesn't need it either.

---

## 9. AI Assessor Prompt Strategy

### 9.1 Prompt Architecture

```
┌──────────────────────────────────┐
│         SYSTEM PROMPT            │
│  (set once, never varied)        │
│                                  │
│  • Role: cybersecurity analyst   │
│  • Rules: JSON only, strict      │
│  • Constraints: evidence-only    │
│  • Hallucination prevention      │
└──────────────┬───────────────────┘
               │
               ▼
┌──────────────────────────────────┐
│         USER PROMPT              │
│  (per-analysis, structured)      │
│                                  │
│  • AIContext JSON (entire)       │
│  • Output schema specification   │
└──────────────┬───────────────────┘
               │
               ▼
┌──────────────────────────────────┐
│         LLM OUTPUT (JSON)        │
│  • risk_score, risk_label        │
│  • executive_summary             │
│  • key_findings[]                │
│  • recommendations[]             │
│  • model_confidence              │
└──────────────────────────────────┘
```

### 9.2 System Prompt (Immutable)

```
You are a senior cybersecurity analyst reviewing network traffic detection results.

RULES:
1. Respond ONLY with valid JSON. Never include explanations outside the JSON.
2. Base every claim on evidence present in the provided data.
3. Do not mention external threat actors, CVEs, or indicators not in the input.
4. Do not fabricate specific packet contents, timestamps, or IP addresses.
5. Be concise. The executive summary must be under 500 characters.
6. The key_findings list must reference only findings present in the input.
7. Mark model_confidence < 0.5 if the evidence is weak or contradictory.
8. If no findings exist in the input, set risk_score=0 and explain briefly.

REQUIRED OUTPUT SCHEMA:
{
  "risk_score": int (0-100),
  "risk_label": string ("Critical"|"High"|"Medium"|"Low"|"Informational"),
  "executive_summary": string (max 500 chars),
  "key_findings": [
    {
      "severity": string,
      "title": string,
      "evidence_summary": string | null
    }
  ],
  "recommendations": [string],
  "model_confidence": float (0.0-1.0)
}
```

### 9.3 User Prompt Template (Populated per Analysis)

```
Below is the network traffic analysis result. Generate a security assessment.

ANALYSIS DATA:
{capture_info_json}

PROTOCOL SUMMARY:
{protocol_summary_json}

DETECTED FINDINGS:
{findings_json}

OVERALL RISK:
{overall_risk_json}

FEATURE SUMMARY:
{feature_summary_json}

Generate the assessment in the JSON schema specified in the system prompt.
```

### 9.4 Hallucination Prevention Strategy

| Technique | Implementation | Enforcement |
|---|---|---|
| **Structured output mode** | Use Ollama `format: "json"` parameter | Backend validates JSON before acceptance |
| **Evidence grounding** | `key_findings` must correspond to input findings | Post-processing check: every output finding title must match an input finding title (fuzzy, 80% Levenshtein) |
| **CVE / IMO ban** | System prompt: "Do not mention external threat actors, CVEs" | Regex post-processing: flag any match for `CVE-\d+-\d+`, `APT`, `Mirai`, etc. |
| **Timeline constraint** | System prompt: "Do not fabricate timestamps" | Not programmatically enforceable at MVP; manual review for edge cases |
| **Confidence calibration** | Model self-assigns confidence | Flag findings with `model_confidence < 0.4` for human review in UI |
| **Length limit** | Set `max_tokens: 2048` | Prevents verbose hallucination chains |
| **Fallback chain** | If JSON invalid → retry 2× → return rule-engine summary | Never expose raw LLM output to user |
| **Citation requirement** | System prompt: "Base every claim on evidence in the provided data" | Not enforceable programmatically; relies on model discipline |

### 9.5 LLM Output Validation (Post-Processing)

```python
def validate_llm_output(report: dict, input_context: AIContext) -> ValidationResult:
    """Validates the LLM output for hallucination and schema compliance."""
    errors = []
    
    # 1. Schema compliance
    if not valid_schema(report, SecurityReportSchema):
        errors.append("Invalid JSON schema")
    
    # 2. Score range
    if not (0 <= report.risk_score <= 100):
        errors.append(f"risk_score out of range: {report.risk_score}")
    
    # 3. Evidence grounding
    input_titles = {f.title for f in input_context.findings}
    for f in report.key_findings:
        if not any(similar(f.title, t) for t in input_titles):
            errors.append(f"Finding '{f.title}' has no matching input finding")
    
    # 4. CVE / IMO check
    if re.search(r'CVE-\d{4}-\d{4,7}', report.executive_summary):
        errors.append("Output references external CVEs not in input")
    
    # 5. Confidence range
    if not (0.0 <= report.model_confidence <= 1.0):
        errors.append(f"model_confidence out of range: {report.model_confidence}")
    
    return ValidationResult(passed=len(errors) == 0, errors=errors)
```

---

## 10. Data Classification

### 10.1 Classification Table

| Data | Classification | Stored Where | Consumed By | Sent to LLM? |
|---|---|---|---|---|
| Raw packet bytes/hex | **Raw packet data** | Not persisted in MVP | N/A | No |
| DNS response records | **Raw packet data** | `dns_queries.answers` (DB, JSONB) | DNS table UI | No |
| HTTP request/response bodies | **Raw packet data** | `http_requests.request_headers`, `response_headers` (DB, JSONB) | HTTP table UI | No |
| FTP command sequences | **Raw packet data** | `ftp_sessions.commands` (DB) | FTP detail UI | No |
| SMTP envelope headers | **Raw packet data** | `smtp_messages.headers` (DB) | SMTP detail UI | No |
| --- | --- | --- | --- | --- |
| Packet length, IP, port, protocol tuples | **Extracted features** | Parser memory, aggregated into `flows` (DB) | Feature Extractor, Flow UI | No |
| Protocol distribution (%) | **Extracted features** | Computed in pipeline | Rule Engine, AI Assessor, Dashboard | Yes (top 5) |
| Flow records (5-tuple + bytes + duration) | **Extracted features** | `flows` (DB) | Feature Extractor, Flow UI | No (full list) |
| Connection profiles per source IP | **Extracted features** | Pipeline only | Rule Engine | No |
| DNS entropy & query frequency | **Extracted features** | Pipeline only | Rule Engine | No |
| FTP auth failure counts | **Extracted features** | Pipeline only | Rule Engine | No |
| SMTP message & recipient counts | **Extracted features** | Pipeline only | Rule Engine | No |
| Traffic baselines & deviations | **Extracted features** | Pipeline only | Rule Engine | No (individual values) |
| --- | --- | --- | --- | --- |
| Rule-triggered alerts | **Findings** | `alerts` (DB) | AI Assessor, Alert UI | Yes (with evidence summary) |
| Severity, confidence, risk_score | **Findings** | `alerts.evidence` (JSONB) | AI Assessor, Frontend | Yes |
| Affected IPs & domains | **Findings** | `alerts.evidence` (JSONB) | AI Assessor, Alert UI | Yes |
| --- | --- | --- | --- | --- |
| Top 5 protocols with percentages | **LLM input** | Pipeline only | AI Assessor | Yes |
| Top 10 talkers | **LLM input** | Pipeline only | AI Assessor | Yes |
| Top DNS domains with query counts | **LLM input** | Pipeline only | AI Assessor | Yes (top 10) |
| All findings with titles + evidence | **LLM input** | Pipeline only | AI Assessor | Yes |
| Risk scores (individual + overall) | **LLM input** | Pipeline only | AI Assessor | Yes |
| Capture metadata | **LLM input** | Pipeline only | AI Assessor | Yes |
| Summary statistics | **LLM input** | Pipeline only | AI Assessor | Yes |

### 10.2 Tier Summary

```
TIER 1: Raw Packet Data (not persisted in MVP)
  Contains full payload + headers.
  Used for: hex viewer, deep protocol analysis (post-MVP).
  NOT consumed by rules, NOT sent to LLM.
  Access: DB queries only, not loaded into memory during pipeline.

TIER 2: Extracted Features (pipeline context + DB)
  Computed aggregations from raw data.
  Used for: rule evaluation, statistical analysis, dashboard charts.
  Consumed by: Rule Engine, frontend chart API.
  NOT sent to LLM (except top-N summaries).

TIER 3: Findings (DB + pipeline context + LLM input)
  Rule engine outputs with evidence, confidence, and scores.
  Used for: alert dashboards, AI assessment, report generation.
  Sent to LLM: YES (with evidence summaries, NOT full evidence objects).

TIER 4: LLM Input (pipeline context only)
  Top-N summaries + findings + risk scores.
  Purposefully narrowed — only what's needed for executive assessment.
  Sent to LLM: YES (the complete AIContext).
```

---

## 11. End-to-End Detection Flow Example

### Scenario
A user uploads `capture.pcapng` (15MB, 300 seconds, 52,400 packets). The capture contains:
- Normal HTTP traffic to `api.corp.com`
- A port scan from `10.0.0.5` to `10.0.0.1` (67 ports in 45 seconds)
- High DNS query volume to `ddns.example.com` (180 queries, high entropy)

### Flow Step-by-Step

**Step 1: Protocol Parser**
```
Input:  capture.pcapng (file on disk)
Output: ParsedProtocols {
          packets: [52,400 records],
          dns_queries: [340 records],
          http_requests: [340 records],
          ftp_sessions: [],
          smtp_messages: [],
          parse_duration_ms: 4500
        }
DB:     packets, flows, dns_queries, http_requests populated
```

**Step 2: Feature Extractor**
```
Input:  ParsedProtocols (from Step 1)
Output: AggregatedFeatures {
          traffic_baseline: { bytes/sec: 140000, packets/sec: 174, ... },
          connection_profiles: [
            { src_ip: 10.0.0.5, unique_dst_ports: 67, failed_connections: 22, ... },
            { src_ip: 10.0.0.102, unique_dst_ports: 1, failed_connections: 0, ... },
            ...
          ],
          dns_profiles: [
            { qname: "ddns.example.com", query_count: 180, subdomain_entropy: 4.2, ... },
            { qname: "api.corp.com", query_count: 45, subdomain_entropy: 2.1, ... },
            ...
          ],
          traffic_deviations: [
            { src_ip: 10.0.0.5, dst_ip: 10.0.0.1, bytes_exceeded_pct: 8.2, ... }
          ],
          ...
        }
Duration: 2300ms
```

**Step 3: Rule Engine**
```
Input:  AggregatedFeatures (from Step 2)

Rule 1: PortScanRule
  → unique_dst_ports: 67 ≥ 50 (HIGH threshold)
  → failed_connections: 22 ≥ 20 (HIGH threshold)
  → raw_score: 72
  → Finding: { severity: HIGH, confidence: HIGH, risk_score: 58, ... }

Rule 2: DNSTunnelingRule
  → subdomain_entropy: 4.2 > 4.0 (MEDIUM threshold)
  → query_count: 180 / 300s = 36/min
  → raw_score: 54
  → Finding: { severity: MEDIUM, confidence: MEDIUM, risk_score: 20, ... }

Rule 3-5: No triggers → None returned

OverallRiskScore:
  max_score: 58
  weighted_score: 62 (58 + 4 bonus)
  severity_label: "HIGH"
  total_findings: 2

Output: [Finding(port_scan), Finding(dns_tunneling)], OverallRiskScore
DB:     alerts table populated with 2 records
Duration: 35ms
```

**Step 4: AI Assessor**
```
Input:  AIContext {
          capture_info: { filename, 15.2MB, 300s, 52,400 packets, 45 IPs },
          protocol_summary: { TCP 78.5%, UDP 20%, ICMP 1.5%, ... },
          findings: [
            { severity: HIGH, title: "Port Scan...", evidence: "67 ports, 22 failures" },
            { severity: MEDIUM, title: "Suspicious DNS...", evidence: "180 queries, entropy 4.2" }
          ],
          overall_risk: { max: 58, weighted: 62, label: "HIGH", ... },
          feature_summary: { ... }
        }

Prompt:
  SYSTEM: (immutable — see §9.2)
  USER: (template — see §9.3, populated with AIContext)

Ollama API call:
  POST /api/generate
  { model: "llama3.2", prompt: "...", format: "json", max_tokens: 2048 }

Response:
  { risk_score: 58, risk_label: "HIGH", ... }

Post-processing:
  ✓ JSON schema valid
  ✓ risk_score 58 in range 0-100
  ✓ All output findings match input findings
  ✓ No CVE references detected
  ✓ model_confidence: 0.82

Output: SecurityReport { risk_score: 58, risk_label: "HIGH", ... }
DB:     ai_assessments table populated
Duration: 8200ms
```

**Total Pipeline Duration:** ~15 seconds (parse 4.5s + extract 2.3s + rules 35ms + AI 8.2s)

---

## Appendix A: Directory Structure for This Module

```
backend/
  contracts/
    __init__.py
    enums.py                    # Severity, Confidence, Protocol, etc.
    parser_output.py            # ParsedPacket, ParsedProtocols
    features.py                 # AggregatedFeatures, FlowRecord, profiles
    findings.py                 # Finding, Evidence, OverallRiskScore
    ai_context.py               # AIContext, CaptureInfo, ProtocolSummary
    ai_output.py                # SecurityReport, AIFinding
  engine/
    __init__.py
    pipeline.py                 # Orchestrates parser → extractor → rules → AI
    registry.py                 # RuleRegistry (discovery + execution)
    base_rule.py                # BaseRule (abstract class)
    rules/
      __init__.py               # Imports all rules for auto-discovery
      port_scan_rule.py
      dns_tunneling_rule.py
      ftp_brute_force_rule.py
      smtp_abuse_rule.py
      suspicious_traffic_rule.py
    features/
      __init__.py
      extractor.py              # Transforms ParsedProtocols → AggregatedFeatures
      traffic_baseline.py       # Baseline computation
      dns_analyzer.py           # DNS entropy + frequency analysis
      connection_profiler.py    # Per-IP connection profiling
    scoring/
      __init__.py
      risk_calculator.py        # Individual + overall score computation
    ai/
      __init__.py
      prompt_builder.py         # Assembles system + user prompt
      ollama_client.py          # HTTP client to Ollama API
      output_validator.py       # Post-processing validation
```
