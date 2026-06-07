# NetMind AI - MVP Scope & Roadmap

## 8. MVP Scope

### In Scope
1. **Single-user mode** (no JWT auth, basic session)
2. **Upload** one PCAP/PCAPNG file at a time, up to 100MB
3. **Parse** protocols needed for MVP analysis: HTTP, DNS, TCP, UDP
4. **Extract** metadata: aggregated flows, top talkers, protocol distribution, timeline
5. **Store** PCAP objects in MinIO and derived results in PostgreSQL with TimescaleDB
6. **Rule engine** with 3 default production MVP rules:
   - DNS tunneling detection
   - HTTP anomaly detection
   - Top talker flow-volume anomaly detection
7. **AI assessment** via Ollama using default `llama3.2` model, basic prompt template
8. **Dashboard**:
   - Upload zone with progress
   - Analysis status bar with WebSocket updates
   - Protocol pie chart
   - Top talkers bar chart
   - Alert table with severity coloring
   - AI report card (executive summary, findings, recommendations)
9. **Docker Compose** full stack: PostgreSQL, Redis, MinIO, Ollama, API, Frontend, Worker
10. **Async analysis** via Celery with worker autoscale and real-time progress streaming

### Excluded from MVP
- Multi-user authentication and RBAC
- HTTPS/TLS decryption
- FTP/SMTP deep parsing
- Machine learning anomaly detection
- Real-time packet capture from interfaces
- PDF/CSV report export
- Scheduled recurring analysis
- Threat intel feeds (MISP, AbuseIPDB)
- Search/filter across multiple captures
- Packet payload hex viewer
- API rate limiting and quotas
- Packet-level database storage

---

## 9. Post-MVP Roadmap

### Phase 2: Security Hardening (Weeks 4-6)
- OAuth2 / username-password authentication
- Role-based access (Admin, Analyst, Viewer)
- PCAP file encryption at rest in MinIO
- API rate limiting
- Input sanitization and upload validation hardening
- Activity audit log

### Phase 3: Advanced Protocols (Weeks 7-9)
- HTTPS/TLS handshake analysis (certificate parsing, JA3 fingerprinting)
- FTP session reconstruction (cleartext credential extraction)
- SMTP envelope and header analysis
- SMB/NetBIOS enumeration detection
- RDP / SSH session metadata

### Phase 4: ML Anomaly Detection (Weeks 10-13)
- Statistical baseline building (per subnet / time window)
- Isolation Forest for outlier detection in flows
- Time-series forecasting for bandwidth anomalies
- Unsupervised clustering of similar traffic patterns
- Integration with anomaly-detector module

### Phase 5: Operational Features (Weeks 14-16)
- PDF and CSV report export with branding
- Scheduled analysis jobs (cron for directory monitoring)
- Webhook alerts (Slack, Teams, generic webhook)
- Email notifications for critical findings
- Search across historical captures (full-text search on AI reports)

### Phase 6: Scalability & Integration (Weeks 17-20)
- Live packet capture from network interfaces (libpcap integration)
- Clustered workers with Celery + RabbitMQ
- Threat intelligence feed integration (AbuseIPDB, AlienVault OTX)
- SIEM export (CEF, LEEF, Syslog)
- REST API versioning (v2 for bulk operations)

---

## 10. Priority Recommendation Summary

| Priority | Module | Why First |
|---|---|---|
| P0 | storage-layer | Zero features work without persistence |
| P1 | pcap-ingestor | Entry point for all user value |
| P2 | protocol-parser | Core feature; required for every other module |
| P3 | feature-extractor | Unlocks dashboard visualizations |
| P4 | api-server | Bridge between backend and frontend |
| P5 | web-dashboard | Primary user interface |
| P6 | rule-engine | First security value delivery |
| P7 | ai-assessor | Competitive differentiator |
| P8 | anomaly-detector | Requires baseline data from earlier phases |
| P9 | observability | Production readiness |

### Rationale
Build the data pipeline first (P0-P3), then expose it (P4), then wrap it in UI (P5). Security intelligence layers (P6-P8) follow once the foundation is solid. Observability (P9) comes last as a polish layer.

### Implementation Sequence
```
Week 1-2:  P0(storage) + P1(ingest) + P2(parser)
Week 3-4:  P3(extractor) + P4(api)
Week 5-6:  P5(dashboard) -- end-to-end demo ready
Week 7-8:  P6(rule-engine) + P7(ai-assessor)
Week 9-10: P8(anomaly-detector) + P9(observability)
Week 11+:  Phase 2-6 roadmap items
```
