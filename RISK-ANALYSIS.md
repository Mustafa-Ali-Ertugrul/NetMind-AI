# NetMind AI Risk Analysis

## Technical Risks

| Risk | Severity | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| Large PCAP files (>1GB) crash parser or OOM | High | High | High | Streaming tshark output (JSON line mode), chunked parsing, configurable memory limits per worker |
| Tshark version mismatch breaking parsing | Medium | Medium | Medium | Pin tshark version in Docker image, validate with `tshark --version`, graceful degradation on unknown protocols |
| Ollama LLM returns hallucinated/incorrect analysis | High | Medium | Medium | Strict JSON schema validation, fallback to rule-engine summary, human review disclaimer, confidence scoring |
| Database bloat from packet-level storage | High | Low | High | TimescaleDB compression policies, automatic chunking by time, retention policy, tiered storage (old chunks to Parquet) |
| Slow LLM inference blocks analysis queue | Medium | Medium | Medium | Dedicated LLM worker queue, timeout of 120s, async-only model, GPU passthrough for Ollama container |
| Upload of malicious PCAP exploits parsing | Critical | Low | High | Run tshark in isolated container with no network, strict seccomp profile, no-shell user, file size limits, input validation |
| PCAP contains sensitive PII (passwords, emails) | High | Medium | High | Encryption at rest, access control, audit logging, data retention policies, admin-only raw download |

## Operational Risks

| Risk | Severity | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| Ollama container fails to start on CPU-only hosts | Medium | High | Medium | Provide CPU-optimized model variants, clear Docker Compose profiles (`docker compose --profile gpu up`), graceful degradation |
| PostgreSQL + TimescaleDB setup complexity | Medium | Medium | Medium | Single `compose.yaml`, automated migrations on startup, health checks, clear README |
| Cross-platform issues (Windows / Mac / Linux) | Low | Medium | Low | Docker Desktop for Windows/Mac, Linux-native, WSL2 paths documented |
| Analysis jobs hang/deadlock | Medium | Medium | High | Celery hard time limits (600s), visibility timeouts, dead letter queues, admin retry dashboard |

## Project Risks

| Risk | Severity | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| Over-engineering before MVP | High | High | High | Strict MVP boundary, weekly milestone demos, simplified designs, agent-workflow gates |
| LLM integration complexity underestimated | Medium | Medium | Medium | Start with simple prompt, iterate, measure end-to-end latency before optimization |
| Frontend performance with large tables | Medium | Medium | Medium | Virtualized lists from day 1, pagination enforced, off-load heavy computation to backend |

## Risk-Priority Dependency Graph

```
storage-layer       (low risk -- PostgreSQL is proven)
pcap-ingestor       (medium risk -- file handling, security)
protocol-parser     (medium risk -- tshark dependency)
feature-extractor   (low risk -- pure computation)
api-server          (low risk -- FastAPI is mature)
web-dashboard       (medium risk -- performance at scale)
rule-engine         (low risk -- deterministic logic)
ai-assessor         (HIGH risk -- LLM unpredictability, latency)
anomaly-detector    (medium risk -- requires data quality)
observability       (low risk -- additive)
```

## Mitigation Strategy Summary
1. **Containment**: Run all parsing and LLM inference in isolated Docker services
2. **Observability**: Structured logging + metrics from day one to catch issues early
3. **Fallbacks**: Every AI feature has a deterministic fallback (rule engine)
4. **Limits**: Memory caps, file size limits, time limits on all async tasks
5. **Validation**: JSON schema validation, input sanitization, output verification
6. **Security**: Defense in depth for file uploads (type, size, hash, sandbox)