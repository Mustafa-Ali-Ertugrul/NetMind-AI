# NetMind AI

AI-powered network traffic analysis platform for cybersecurity analysts and network administrators. Runs entirely on Docker and uses local LLMs for security assessments.

**Status:** Sprint 5 — Async pipeline + AI Assessor shipped. Full-stack roadmap continues to production hardening and frontend.

---

## Quick Start

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Start the stack (4 services: db + redis + api + worker)
docker compose up --build

# 3. Verify health
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "ok",
  "app_name": "NetMind AI",
  "database": "ok",
  "app_version": "0.1.0"
}
```

Upload a PCAP and poll for results:
```bash
# Upload
curl -s -X POST http://localhost:8000/api/v1/pcaps \
  -F "file=@sample.pcapng" | jq .
# → { "job_id": "uuid...", "pcap_id": "uuid...", "status": "queued" }

# Poll job status (every 1-2 seconds)
curl -s http://localhost:8000/api/v1/jobs/<job_id> | jq .
# → { "status": "parsing" | "extracting" | "detecting" | "assessing" | "completed" }

# Get full result (alerts + AI assessment)
curl -s http://localhost:8000/api/v1/jobs/<job_id>/result | jq .
```

API documentation (when running): <http://localhost:8000/docs>

---

## What Works

| Feature | Sprint | Status |
|---|---|---|
| PCAP/PCAPNG upload with SHA-256 dedup | 5 | ✓ |
| Protocol parsing via tshark JSON streaming | 2 | ✓ |
| Feature extraction (flows, DNS profiles, traffic baselines) | 3 | ✓ |
| Rule engine — 4 detection rules (port scan, DNS tunneling, FTP brute force, SMTP abuse) | 3 | ✓ |
| **Async pipeline** (Celery + Redis — parse → extract → detect → assess) | 5 | ✓ |
| **AI Assessor** (Ollama, single LLM call, template fallback) | 4A | ✓ |
| **Job polling API** (`GET /jobs/{id}`, `GET /jobs/{id}/result`) | 5 | ✓ |
| Alert + AI Assessment persistence to PostgreSQL | 5 | ✓ |
| 4 Docker containers: `db`, `redis`, `api`, `worker` | 5 | ✓ |
| Validation suite (CTU-13 Scenario 1, Stratosphere Android) | 3.5 | ✓ |
| Auto table creation on startup | 1 | ✓ |
| Configuration via `.env` (pydantic-settings) | 1 | ✓ |
| CORS middleware | 1 | ✓ |
| OpenAPI / Swagger UI at `/docs` | 1 | ✓ |

## What Does Not Work Yet

| Feature | Planned Sprint |
|---|---|
| **Base Detection rules 5-6** (HTTP brute force, beaconing) | 7 |
| **Production storage** — 30-day cleanup, download endpoint | 6 |
| **Frontend** (React + Vite + TanStack Query + Tailwind + ECharts) | 7 |
| CI / GitHub Actions | 8 |
| Authentication / multi-user | 8 |

---

## Sprint History

| Sprint | Status | Highlights |
|---|---|---|
| 1 | ✓ | Repo scaffold, config, Pydantic contracts, PostgreSQL + async SQLAlchemy |
| 2 | ✓ | Protocol parsers (tcp/udp/dns/http/ftp/smtp) via tshark JSON streaming |
| 3 | ✓ | Feature extractor, rule engine, 4 detection rules |
| 3.5 | ✓ | Validation against CTU-13 + Stratosphere (100% Recall port scan, 100% Precision DNS tunneling) |
| 4A | ✓ | AI Assessor (Ollama, single-call, template fallback, backward‑compatible) |
| 5 | ✓ | Celery + Redis async pipeline, job polling API, storage writers, 4‑service Docker Compose |
| 6 | → | 30‑day cleanup, PCAP download endpoint |
| 7 | → | Frontend (React + Vite + TanStack Query) |
| 8 | → | CI, Docker hardening, GitHub release |

---

## Project Layout

```
NetMind-AI/
├── ARCHITECTURE.md              # System design docs
├── DETECTION-PIPELINE.md        # Pipeline + contract reference
├── MVP-AND-ROADMAP.md           # Roadmap
├── RISK-ANALYSIS.md             # Risk register
├── README.md
├── docker-compose.yaml          # db + redis + api + worker
├── .env.example                 # Config template
├── .gitignore
├── backend/
│   ├── main.py                  # Uvicorn entrypoint
│   ├── config.py                # pydantic-settings
│   ├── pyproject.toml           # Dependencies
│   ├── Dockerfile               # API container
│   ├── Dockerfile.worker        # Celery worker container
│   ├── contracts/               # Pydantic models
│   ├── storage/                 # SQLAlchemy ORM + writers
│   │   ├── models.py
│   │   ├── database.py
│   │   ├── alert_writer.py
│   │   └── assessment_writer.py
│   ├── protocol_parser/         # tshark streaming parser
│   ├── feature_extractor/       # Flow builder, profiles, baselines
│   ├── rule_engine/             # 4 detection rules + engine
│   ├── ai_assessor/             # Ollama provider, assessor
│   ├── api/                     # FastAPI routes
│   │   ├── app.py
│   │   ├── schemas.py
│   │   └── routes/ (health, pcaps, jobs)
│   ├── worker/                  # Celery app + tasks
│   │   ├── __init__.py
│   │   └── tasks/pcap_analysis.py
│   ├── validation/              # Performance validation
│   └── tests/                   # 250+ tests
├── datasets/                    # Labeled PCAPs (CTU-13, Stratosphere)
├── db/schema.sql                # Reference DDL
└── reports/                     # Validation reports (JSON + MD)
```

---

## API Quick Reference

### `GET /health`
Returns 200 if the service is up and can reach PostgreSQL + Redis.

### `POST /api/v1/pcaps`
Upload a PCAP/PCAPNG file. Multipart form-data with `file` field.
- Max size: 100 MB (configurable)
- Allowed extensions: `.pcap`, `.pcapng`
- SHA-256 dedup: re-uploading the same file returns 200 with the existing `job_id` and `deduplicated: true`
- Returns 201 with `job_id` and `pcap_id`; analysis starts asynchronously

```bash
curl -s -X POST http://localhost:8000/api/v1/pcaps \
  -F "file=@sample.pcapng"
# → { "job_id": "uuid...", "pcap_id": "uuid...", "status": "queued" }
```

### `GET /api/v1/jobs/{job_id}`
Poll the job status. Poll once per second.
```json
{ "id": "uuid", "status": "parsing", "pcap_id": "uuid", "created_at": "..." }
```

### `GET /api/v1/jobs/{job_id}/result`
Get full analysis result once the job is `completed`.
- **200** — complete result with alerts + AI assessment
- **409** — job not yet completed
- **422** — job failed (includes error message)

### `GET /api/v1/jobs/by_pcap/{pcap_id}`
List all jobs for a given PCAP.

---

## Development

Run locally without Docker:
```bash
cd backend
python -m venv .venv
# Linux: source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -e .[dev]

# Start API
DATABASE_URL=postgresql+asyncpg://netmind:netmind@localhost:5432/netmind \
  uvicorn backend.main:app --reload

# Start worker (separate terminal, requires Redis)
celery -A backend.worker worker --loglevel=INFO --pool=solo
```

Run tests:
```bash
cd backend
python -m pytest tests/ -v
```

---

## Next Sprint

Sprint 6 will add:
- **30‑day PCAP cleanup** via Celery Beat
- **PCAP download endpoint** (`GET /api/v1/pcaps/{pcap_id}/download`)
- Option B: aggregate packet/flow/dns summaries for the "browse traffic" feature

See [MVP-AND-ROADMAP.md](./MVP-AND-ROADMAP.md) for the full plan.
