# NetMind AI Frontend

React SPA for the NetMind AI network-traffic analysis platform.

## Stack

- React 19.2 + TypeScript 6
- Vite 8
- Tailwind CSS v4
- TanStack Query (React Query)
- Axios
- ECharts (tree-shaken, core + canvas renderer)
- react-dropzone
- react-router-dom
- lucide-react

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `VITE_API_BASE_URL` | `/api/v1` | Backend API prefix. In dev, the Vite proxy strips `/api` and forwards the rest to `localhost:8000`. In Docker, nginx proxies `/api/` to the API container. |

## Dev Run

```bash
npm install --legacy-peer-deps
npm run dev          # http://localhost:5173
```

Dev server proxies `/api/*` to `http://localhost:8000` via `vite.config.ts`.

## Docker Run

```bash
# From project root (NetMind-AI/)
docker compose up frontend
```

Serves on `http://localhost` (port 80). nginx reverse-proxies `/api/` to the `api` container so the frontend stays same-origin with the backend.

## Available Routes

| Route | Page | Notes |
|---|---|---|
| `/` | Dashboard | Disk gauge, job-status pie chart, recent jobs table. Requires backend. |
| `/upload` | Upload PCAP | File dropzone, SHA-256 dedup check, redirects to job. |
| `/jobs/:jobId` | Job Detail | Progress timeline, findings table, AI report, artifacts download. Requires backend. |
| `/storage` | Storage | Disk usage, PCAP/artifact counts, manual cleanup trigger. Requires backend. |
| `*` | Not Found | Catch-all 404. |

## Test Commands

```bash
npm run lint          # ESLint
npm run typecheck     # tsc -b --noEmit
npm run test          # Vitest unit tests
npm run test:e2e      # Playwright (Chromium)
```

Unit tests cover pure utilities (`formatBytes`, `formatDate`, `formatDuration`).
E2E tests are smoke tests for SPA routing and upload-page render; they do **not** require a running backend.

## API Proxy Explanation

- **Dev:** Vite dev server proxies `/api` to `http://localhost:8000`. The frontend calls `/api/v1/...`, Vite strips `/api` and forwards `/v1/...`.
- **Production (Docker):** nginx listens on port 80 and proxies `/api/` to `http://api:8000`. The frontend still calls `/api/v1/...` so no CORS is needed.

## Screenshots

> Placeholder — capture after running the full Docker stack.

- `![Dashboard](docs/dashboard.png)`
- `![Upload](docs/upload.png)`
- `![Job Detail](docs/job-detail.png)`
- `![Storage](docs/storage.png)`
