# NetMind AI - System Architecture

## 1. System Architecture

### High-Level Design
NetMind AI follows a modular, event-driven architecture optimized for async network traffic analysis. The pipeline is: **Ingest -> Parse -> Extract -> Detect -> Assess -> Present**.

### Core Components
- **Ingestion Service**: PCAP/PCAPNG uploads, validation, object storage, queueing
- **Parsing Service**: tshark wrapper for multi-protocol dissection (HTTP, HTTPS, DNS, FTP, SMTP, TCP, UDP, ICMP)
- **Analysis Engine**: Metadata extraction, flow aggregation, statistical summaries
- **Rule Engine**: Production MVP detection for DNS tunneling, HTTP anomalies, and top talker flow-volume anomalies
- **AI/LLM Assessor**: Local Ollama LLM for natural language security assessments
- **API Server**: FastAPI REST API + WebSocket for real-time job progress
- **Frontend Dashboard**: React SPA with interactive visualizations
- **Database**: PostgreSQL 16 + TimescaleDB (time-series optimization for aggregated flow data)
- **Object Storage**: MinIO (S3-compatible) for PCAP originals
- **Task Queue**: Redis + Celery for distributed async analysis

### Communication Patterns
- API Server -> Celery -> Workers via Redis broker
- Workers -> PostgreSQL (results persistence, TimescaleDB hypertables)
- Workers -> MinIO (read PCAP originals)
- Frontend -> API Server (REST & WebSocket)
- AI Worker -> Ollama (HTTP REST /api/generate)

### Technology Stack
| Component | Technology | Rationale |
|---|---|---|
| Backend API | Python 3.11 + FastAPI | Async-native, OpenAPI auto-generation, excellent ecosystem |
| Task Workers | Celery + Redis | Mature, proven, supports retries + dead letter queues |
| Database | PostgreSQL 16 + TimescaleDB | Hypertables optimize time-series flow data; standard SQL |
| Cache/Queue | Redis 7 | Fast, proven, Celery broker, also cache layer |
| Object Storage | MinIO | S3-compatible, Docker-native, lightweight |
| LLM Runtime | Ollama | Local model hosting, simple HTTP API, no cloud dependency |
| Frontend | React 18 + TS + Vite | Performance, type safety, large ecosystem |
| Charts | Apache ECharts + Recharts | Network graphs, timelines, general statistics |
| Reverse Proxy | Traefik v3 | Auto HTTPS, Docker service discovery, minimal config |
| Containers | Docker Compose | Simple orchestration, runs everywhere |

### Architecture Diagram (Text)
```
+------------------------------------------------+
|           Traefik (Reverse Proxy)               |
+------------------------------------------------+
                    |
  +-----------------+-----------------+
  |                 |                 |
  v                 v                 v
+--------+    +----------+    +---------------+
|Frontend|    | API Srv  |    |  WebSocket    |
| React  |    | FastAPI  |    |   /ws/...     |
+--------+    +-----+----+    +---------------+
                    |
        +-----------+-----------+
        |           |           |
        v           v           v
   +--------+  +--------+  +------------+
   | Celery |  | Redis  |  |PostgreSQL  |
   |Workers |  | Queue  |  | + Timescale|
   +----+---+  +--------+  +------------+
        |
   +----+------------------------------+
   v                v                  v
+----------+   +----------+   +----------------+
| Protocol |   |  Rule    |   |   AI / LLM     |
| Parser   |   | Engine   |   |   Assessor     |
| (tshark) |   |          |   |   (Ollama)     |
+-----+----+   +----------+   +----------------+
      |
+-----+-----+
|   MinIO   |   PCAP originals stored here
+-----------+
```

---

## 2. Implementation Modules

| Module | Path | Responsibility |
|---|---|---|
| `pcap-ingestor` | `backend/pcap_ingestor/` | Upload validation, file storage, hash calculation, virus scan placeholder |
| `protocol-parser` | `backend/protocol_parser/` | tshark wrapper, protocol extraction (HTTP, DNS, FTP, SMTP, TCP, UDP, ICMP) |
| `feature-extractor` | `backend/feature_extractor/` | Flow generation, statistical aggregation, metadata extraction |
| `rule-engine` | `backend/rule_engine/` | Signature detection, IoC matching, alert generation |
| `ai-assessor` | `backend/ai_assessor/` | LLM prompt construction, Ollama client, report generation, result caching |
| `storage-layer` | `backend/storage/` + `db/` | SQLAlchemy models, migrations, TimescaleDB configuration |
| `api-server` | `backend/api/` | FastAPI routes, dependency injection, auth, WebSocket manager |
| `task-orchestrator` | `backend/tasks/` | Celery task definitions, worker bootstrapping, retry policies |
| `web-dashboard` | `frontend/` | React SPA, chart components, upload UI, report viewer |
| `infrastructure` | `docker/` + `compose.yaml` | Docker images, networking, volumes, health checks |
| `observability` | `backend/observability/` | Structured logging, metrics, tracing hooks |

### Repository Structure (Target)
```
netmind-ai/
 backend/
  api/
   routes/
    pcaps.py
    analysis.py
    alerts.py
    ai_report.py
   dependencies.py
   websocket.py
   main.py
  pcap_ingestor/
   upload.py
   validation.py
   storage_client.py
  protocol_parser/
   tshark_wrapper.py
   protocols/
    http.py
    dns.py
    tcp.py
    udp.py
    icmp.py
    ftp.py
    smtp.py
   models.py
  feature_extractor/
   flows.py
   statistics.py
   metadata.py
  rule_engine/
   rules/
   alert_generator.py
   ioc_matcher.py
  ai_assessor/
   prompt_builder.py
   ollama_client.py
   schema_validator.py
  storage/
   models.py
   migrations/
  tasks/
   celery_app.py
   analysis_pipeline.py
  observability/
   logging_config.py
 frontend/
  src/
   components/
   hooks/
   stores/
   pages/
   api/
 db/
  schema.sql
  migrations/
 docker/
  compose.yaml
  Dockerfile.api
  Dockerfile.worker
  Dockerfile.frontend
```

---

## 3. Task Dependencies (Dependency Graph)

### Development Phases

```
Phase 0: Infrastructure
  - docker-compose, networking, volumes
  - PostgreSQL, Redis, MinIO, Ollama containers
                     |
                     v
Phase 1: storage-layer
  - DB schema, SQLAlchemy models, migrations
                     |
                     v
Phase 2: pcap-ingestor
  - Upload endpoint, validation, S3 storage
                     |
                     v
Phase 3: protocol-parser
  - tshark streaming wrapper, packet insert
                     |
                     v
Phase 4: feature-extractor
  - Flow aggregation, stats calculation
                     |
        +------------+------------+
        |                         |
        v                         v
Phase 5: rule-engine      Phase 5b: api-server
  - Signature detection      - REST endpoints, WebSocket
        |                         |
        +------------+------------+
                     |
                     v
Phase 6: ai-assessor
  - LLM prompt, Ollama client
                     |
                     v
Phase 7: web-dashboard
  - React SPA, charts, upload UI
                     |
                     v
Phase 8: observability
  - Logging, metrics, health
```

### Strict Module Dependencies
- `storage-layer`: none (foundation)
- `pcap-ingestor`: `storage-layer`
- `protocol-parser`: `storage-layer`, `pcap-ingestor`
- `feature-extractor`: `protocol-parser`
- `rule-engine`: `feature-extractor`
- `anomaly-detector`: `feature-extractor`
- `ai-assessor`: `rule-engine`, `feature-extractor`, `storage-layer`
- `api-server`: all backend modules
- `web-dashboard`: `api-server`

---

## 4. Database Schema

### Design Principles
- Use **TimescaleDB hypertables** for high-cardinality time-series data (aggregated flows)
- Normalize protocol-specific tables (dns_queries, http_requests) for query efficiency
- JSONB for flexible evidence and headers
- UUIDv4 primary keys for distributed-future-proofing
- Foreign keys with CASCADE delete for cleanup

### Core Tables
- **pcap_files**: File metadata, status, hashes, storage keys
- **flows**: Aggregated 5-tuple flows (hypertable on time)
- **dns_queries**: DNS transaction details with suspicion flag
- **http_requests**: HTTP request/response metadata
- **alerts**: Security findings with severity and category
- **analysis_jobs**: Async job progress tracking
- **ai_assessments**: LLM-generated structured reports
- **users**: Multi-user support (Post-MVP)
- **audit_log**: Compliance tracking (Post-MVP)

### Full DDL
See [db/schema.sql](./db/schema.sql) for complete PostgreSQL + TimescaleDB DDL with indexes and constraints.

---

## 5. API Design

### REST Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | /api/v1/pcaps | Upload PCAP/PCAPNG (multipart) |
| GET | /api/v1/pcaps | List uploads (paginated, filterable) |
| GET | /api/v1/pcaps/{id} | Get file metadata and status |
| DELETE | /api/v1/pcaps/{id} | Delete file and all derived data |
| POST | /api/v1/pcaps/{id}/analyze | Trigger async analysis pipeline |
| GET | /api/v1/pcaps/{id}/analysis | Get aggregated analysis results |
| GET | /api/v1/pcaps/{id}/flows | Flow summary with top talkers |
| GET | /api/v1/pcaps/{id}/dns | DNS query list |
| GET | /api/v1/pcaps/{id}/http | HTTP request list |
| GET | /api/v1/pcaps/{id}/alerts | Security alerts |
| GET | /api/v1/pcaps/{id}/ai-report | AI assessment report |
| GET | /api/v1/stats/global | Global platform statistics |
| WS | /ws/analysis/{job_id} | Real-time analysis progress stream |

### Response Examples

**Upload PCAP (201 Created):**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "filename": "capture.pcapng",
  "size": 104857600,
  "status": "uploaded",
  "hash_sha256": "a94b...",
  "uploaded_at": "2026-06-04T12:00:00Z"
}
```

**Trigger Analysis (202 Accepted):**
```json
{
  "job_id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
  "status": "queued",
  "queued_at": "2026-06-04T12:01:00Z"
}
```

**AI Report (200 OK):**
```json
{
  "id": "c3d4e5f6-a7b8-9012-cdef-345678901234",
  "risk_score": 3,
  "risk_label": "Medium",
  "executive_summary": "The capture contains cleartext HTTP authentication and DNS queries to a suspicious domain. Recommend enforcing HTTPS and reviewing DNS filters.",
  "key_findings": [
    {"severity": "high", "title": "Cleartext HTTP Basic Auth", "evidence": "Authorization: Basic dXNlcjpwYXNz"},
    {"severity": "medium", "title": "Unknown DNS Domain", "evidence": "evil.example.com queried 150 times"}
  ],
  "recommendations": [
    "Migrate all HTTP services to HTTPS",
    "Block evil.example.com at DNS resolver level"
  ],
  "protocol_distribution": {"TCP": 78, "UDP": 20, "ICMP": 2},
  "model_name": "llama3.2",
  "generated_at": "2026-06-04T12:05:00Z"
}
```

### WebSocket Protocol

**Connect:** `wss://host/ws/analysis/{job_id}`

**Server -> Client Messages:**
```json
{"type": "status", "status": "parsing", "progress": 10, "message": "Extracting packets..."}
{"type": "status", "status": "analyzing", "progress": 60, "message": "Running AI assessment..."}
{"type": "complete", "status": "completed", "progress": 100, "report_id": "uuid"}
{"type": "error", "status": "failed", "error": "LLM inference timeout"}
```

---

## 6. AI Analysis Workflow

### Data Flow
1. **Preparation**: Gather structured summary from `feature-extractor` + `rule-engine` alerts
2. **Prompt Assembly**: Build context-optimized prompt with protocol distribution, top talkers, alerts, and suspicious flows
3. **LLM Invocation**: POST to Ollama `/api/generate` with:
   - `model`: `llama3.2` (configurable)
   - `system`: security analyst persona
   - `prompt`: structured JSON summary
   - `format`: JSON schema for deterministic output
4. **Post-Processing**: Validate JSON schema, normalize scores, cache result
5. **Delivery**: Store in `ai_assessments` table, return via API

### Prompt Engineering Strategy
```
SYSTEM PROMPT:
You are a senior cybersecurity analyst reviewing network traffic.
You receive structured data from a network protocol analyzer.
Respond ONLY with valid JSON conforming to the specified schema.
Do not explain reasoning outside the JSON. Be concise and factual.

USER PROMPT (template):
{
  "capture_info": {
    "file_size_mb": 12,
    "duration_seconds": 300,
    "total_packets": 50000,
    "unique_ips": 45
  },
  "protocol_distribution": {"TCP": 78, "UDP": 20, "ICMP": 2},
  "top_talkers": [
    {"ip": "10.0.0.5", "bytes_sent": 9000000, "bytes_recv": 2000000}
  ],
  "dns_queries": [{"domain": "evil.example.com", "count": 150}],
  "detected_alerts": [
    {"severity": "high", "title": "Cleartext FTP Auth"}
  ],
  "http_requests": [{"method": "POST", "uri": "/admin/login"}]
}

OUTPUT JSON SCHEMA:
{
  "risk_score": "integer 0-5",
  "risk_label": "string: Critical|High|Medium|Low|Informational",
  "executive_summary": "string max 500 chars",
  "key_findings": [{"severity": "string", "title": "string", "evidence": "string"}],
  "recommendations": ["string"],
  "confidence": "float 0.0-1.0"
}
```

### Fallback Strategy
- If LLM returns invalid JSON: retry up to 2 times, then fallback to rule-engine summary
- If Ollama unreachable: flag analysis incomplete, return partial results
- If context exceeds model window: trim to top N alerts + top 20 flows only

---

## 7. Frontend Architecture

### Stack
- **Framework**: React 18.3 + TypeScript 5.4
- **Bundler**: Vite 5
- **Server State**: TanStack Query (React Query) with background refetching
- **Client State**: Zustand (lightweight, no boilerplate)
- **Routing**: TanStack Router (type-safe file-based routing)
- **UI**: Shadcn/ui component library + Tailwind CSS
- **Charts**: Apache ECharts (network graphs, timelines) + Recharts (bar/pie)
- **WebSocket**: Custom hook `useAnalysisProgress`
- **Upload**: `react-dropzone` with chunked upload for large files
- **Virtualization**: Efficient lists for findings, jobs, and aggregated flow views

### Component Hierarchy
```
App
+-- Layout
    +-- Sidebar (navigation)
    +-- Header (user, notifications)
    +-- Main Content
        +-- Dashboard (home)
        |   +-- UploadZone
        |   +-- RecentAnalysesTable
        |   +-- StatsCards
        +-- PCAPDetail (/pcaps/:id)
        |   +-- StatusBadge
        |   +-- ProtocolPieChart
        |   +-- TopTalkersBarChart
        |   +-- TimelineChart
        |   +-- AlertList
        |   +-- DNSQueryTable
        |   +-- HTTPRequestTable
        |   +-- AIReportPanel
        +-- Settings
+-- ToastProvider (real-time feedback)
```

### State Management
- **Server State**: TanStack Query caches API responses, auto-refetches stale data, handles pagination
- **Client State** (Zustand):
  - `activeJobs`: Map of job_id -> WebSocket listener
  - `selectedPcap`: Currently viewed PCAP ID
  - `uiConfig`: Collapsed panels, chart preferences
  - `theme`: Light / dark mode

### Performance Considerations
- Charts lazy-load when entering viewport
- Large uploads chunked into 1MB pieces, resumable
- AI report streamed character-by-character for perceived speed
- Debounced filtering on large result tables to avoid excessive API calls

---

## Suggested Agent Workflow

Use this workflow when beginning implementation of NetMind AI:

### Before Coding
1. **@architect** - Review this architecture, validate module interfaces, refine data contracts between modules
2. **@explore** - Research tshark JSON streaming output, Ollama API response format, TimescaleDB compression policies

### Implementation Order (per priority table)
3. **@build** (Phase 1-2: storage + ingest + parser)
   - Implement `db/schema.sql` migrations via Alembic
   - Build `pcap_ingestor` with MinIO upload
   - Build `protocol_parser` streaming tshark wrapper
   
4. **@build** (Phase 3-4: extractor + API)
   - Flow aggregation and statistics
   - FastAPI routes with OpenAPI docs
   
5. **@build** (Phase 5: dashboard)
   - React SPA with upload, charts, tables
   
6. **@build** (Phase 6-7: intelligence layers)
   - Rule engine with the 3-rule production MVP default set
   - AI assessor with Ollama integration

### Quality Gates
7. **@test-runner** - Write pytest integration tests for each module boundary before moving to next module
8. **@reviewer** - Review every module for: security, type safety, error handling, logging
9. **@docs-researcher** - Update API docs, frontend Storybook, and deployment README as features land

### Verification Loop
After each module completes:
```
Run tests -> Review coverage -> Check lint -> Security scan -> Merge
```

### Risk-Driven Checks
- Before `ai-assessor` lands: validate Ollama response schema strictly
- Before `pcap-ingestor` lands: verify file type validation and sandbox constraints
- Before `protocol-parser` lands: test with real-world multi-GB PCAP files

This workflow ensures the data pipeline is solid before adding intelligence, and every module has deterministic fallbacks and tests.
