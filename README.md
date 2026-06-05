# NetMind AI

AI-powered network traffic analysis platform for cybersecurity analysts and network administrators. Runs entirely on Docker and uses local LLMs for security assessments.

**Status:** Phase 1 — Backend Skeleton (runnable, `/health` returns 200, upload stub in place)

---

## Quick Start

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Start the stack
docker compose up --build

# 3. Verify health
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "ok",
  "app_name": "NetMind AI",
  "app_version": "0.1.0",
  "environment": "development",
  "database": "ok",
  "timestamp": "2026-06-05T12:00:00Z"
}
```

API documentation: <http://localhost:8000/docs>

---

## What Works in Phase 1

| Feature | Status |
|---|---|
| FastAPI application with lifespan management | ✓ |
| PostgreSQL 16 with async SQLAlchemy | ✓ |
| Auto table creation on startup | ✓ |
| Configuration via `.env` (pydantic-settings) | ✓ |
| CORS middleware | ✓ |
| `GET /health` (with DB connectivity check) | ✓ |
| `POST /api/v1/pcaps` (validates, hashes, persists) | ✓ stub |
| `GET /api/v1/pcaps/{id}` | stub (501) |
| OpenAPI / Swagger UI at `/docs` | ✓ |

## What Does Not Work Yet (Phase 2+)

- Protocol parsing (tshark)
- Feature extraction
- Rule engine
- AI Assessor (Ollama)
- Frontend
- WebSocket progress streaming
- Authentication / multi-user
- Real PCAP file storage (only metadata persisted in Phase 1)

---

## Project Layout

```
NetMind-AI/
├── ARCHITECTURE.md              # System design
├── DETECTION-PIPELINE.md        # Pipeline + Pydantic contracts
├── MVP-AND-ROADMAP.md           # Phase plan
├── RISK-ANALYSIS.md             # Risk register
├── README.md                    # This file
├── docker-compose.yaml          # PostgreSQL + API
├── .env.example                 # Environment template
├── .gitignore
├── backend/
│   ├── __init__.py
│   ├── main.py                  # Uvicorn entrypoint
│   ├── config.py                # Settings (pydantic-settings)
│   ├── pyproject.toml           # Dependencies
│   ├── Dockerfile
│   ├── contracts/               # Pydantic models (18 models)
│   │   ├── __init__.py
│   │   ├── enums.py
│   │   ├── parser_output.py
│   │   ├── features.py
│   │   ├── findings.py
│   │   ├── ai_context.py
│   │   └── ai_output.py
│   ├── storage/                 # SQLAlchemy ORM
│   │   ├── __init__.py
│   │   ├── database.py
│   │   └── models.py
│   └── api/                     # FastAPI
│       ├── __init__.py
│       ├── app.py
│       ├── dependencies.py
│       ├── schemas.py
│       └── routes/
│           ├── __init__.py
│           ├── health.py
│           └── pcaps.py
└── db/
    └── schema.sql               # Reference DDL (init_db uses SQLAlchemy)
```

---

## API Quick Reference

### `GET /health`
Liveness + readiness. Returns 200 if the service is up and can reach PostgreSQL.

### `POST /api/v1/pcaps`
Upload a PCAP/PCAPNG file. Multipart form-data with `file` field.
- Max size: 100 MB (configurable)
- Allowed extensions: `.pcap`, `.pcapng`
- Computes SHA-256, stores metadata, returns 201 with pcap UUID

Example:
```bash
curl -X POST http://localhost:8000/api/v1/pcaps \
  -F "file=@sample.pcapng"
```

Response:
```json
{
  "id": "a1b2c3d4-...",
  "filename": "abc123.pcapng",
  "original_name": "sample.pcapng",
  "file_size": 1048576,
  "sha256": "abc123...",
  "status": "uploaded",
  "uploaded_at": "2026-06-05T12:00:00Z",
  "note": "Phase 1 stub. Real ingestion pipeline arrives in Phase 2."
}
```

---

## Development

Run locally without Docker:
```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e .[dev]
DATABASE_URL=postgresql+asyncpg://netmind:netmind@localhost:5432/netmind \
  uvicorn backend.main:app --reload
```

---

## Next Phase

Phase 2 will add:
- `protocol_parser` module (tshark subprocess wrapper)
- `feature_extractor` module
- `rule_engine` with 5 MVP rules
- Celery + Redis for async analysis
- Real file storage (Docker volume + content-addressable)
- LLM integration (Ollama)

See [MVP-AND-ROADMAP.md](./MVP-AND-ROADMAP.md) for the full plan.
