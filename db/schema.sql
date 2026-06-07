-- ============================================================
-- NetMind AI - PostgreSQL 16 + TimescaleDB Schema
-- ============================================================
-- This schema is designed for network traffic analysis with:
--   - Time-series optimization via TimescaleDB hypertables
--   - Standard SQL for protocol-specific tables
--   - JSONB for flexible evidence and metadata
--   - UUIDv4 primary keys for distributed future-proofing
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ============================================================
-- 1. pcap_files : Uploaded capture file metadata
-- ============================================================
CREATE TABLE pcap_files (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    filename         TEXT NOT NULL,
    original_name    TEXT NOT NULL,
    file_size        BIGINT NOT NULL,
    mime_type        TEXT,
    sha256           TEXT NOT NULL UNIQUE,
    storage_key      TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'uploaded'
                     CHECK (status IN ('uploaded','queued','parsing','extracting','detecting','assessing','completed','failed')),
    duration_seconds FLOAT,
    packet_count     BIGINT,
    bytes_total      BIGINT,
    start_time       TIMESTAMP WITH TIME ZONE,
    end_time         TIMESTAMP WITH TIME ZONE,
    uploaded_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    uploaded_by      UUID,
    error_message    TEXT
);

CREATE INDEX idx_pcap_files_status      ON pcap_files(status);
CREATE INDEX idx_pcap_files_uploaded_at ON pcap_files(uploaded_at);

-- ============================================================
-- 2. flows : Aggregated 5-tuple flows (TimescaleDB hypertable)
-- ============================================================
CREATE TABLE flows (
    time          TIMESTAMP WITH TIME ZONE NOT NULL,
    pcap_id       UUID NOT NULL REFERENCES pcap_files(id) ON DELETE CASCADE,
    src_ip        INET NOT NULL,
    dst_ip        INET NOT NULL,
    src_port      INTEGER,
    dst_port      INTEGER,
    protocol      TEXT NOT NULL,
    bytes_sent    BIGINT DEFAULT 0,
    bytes_recv    BIGINT DEFAULT 0,
    packets_count INTEGER DEFAULT 0,
    start_time    TIMESTAMP WITH TIME ZONE,
    end_time      TIMESTAMP WITH TIME ZONE,
    duration_ms   FLOAT,
    alert_count   INTEGER DEFAULT 0
);

SELECT create_hypertable('flows', 'time', chunk_time_interval => INTERVAL '1 hour');

CREATE INDEX idx_flows_pcap_id  ON flows(pcap_id);
CREATE INDEX idx_flows_5tuple   ON flows(src_ip, dst_ip, src_port, dst_port, protocol);

-- ============================================================
-- 4. dns_queries : DNS transaction details
-- ============================================================
CREATE TABLE dns_queries (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pcap_id         UUID NOT NULL REFERENCES pcap_files(id) ON DELETE CASCADE,
    packet_time     TIMESTAMP WITH TIME ZONE,
    src_ip          INET,
    dst_ip          INET,
    transaction_id  INTEGER,
    qname           TEXT,
    qtype           TEXT,
    response_code   TEXT,
    answers         JSONB,
    is_suspicious   BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_dns_pcap_id    ON dns_queries(pcap_id);
CREATE INDEX idx_dns_qname      ON dns_queries(qname);
CREATE INDEX idx_dns_suspicious ON dns_queries(is_suspicious);

-- ============================================================
-- 5. http_requests : HTTP request/response metadata
-- ============================================================
CREATE TABLE http_requests (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pcap_id           UUID NOT NULL REFERENCES pcap_files(id) ON DELETE CASCADE,
    packet_time       TIMESTAMP WITH TIME ZONE,
    src_ip            INET,
    dst_ip            INET,
    method            TEXT,
    host              TEXT,
    uri               TEXT,
    status_code       INTEGER,
    user_agent        TEXT,
    content_type      TEXT,
    request_headers   JSONB,
    response_headers  JSONB,
    is_suspicious     BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_http_pcap_id    ON http_requests(pcap_id);
CREATE INDEX idx_http_host       ON http_requests(host);
CREATE INDEX idx_http_suspicious ON http_requests(is_suspicious);

-- ============================================================
-- 6. ftp_sessions : FTP control channel events
-- ============================================================
CREATE TABLE ftp_sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pcap_id         UUID NOT NULL REFERENCES pcap_files(id) ON DELETE CASCADE,
    src_ip          INET,
    dst_ip          INET,
    commands        TEXT[],
    username        TEXT,
    password        TEXT,
    file_transfers  JSONB
);

CREATE INDEX idx_ftp_pcap_id ON ftp_sessions(pcap_id);

-- ============================================================
-- 7. smtp_messages : SMTP envelope and header info
-- ============================================================
CREATE TABLE smtp_messages (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pcap_id         UUID NOT NULL REFERENCES pcap_files(id) ON DELETE CASCADE,
    src_ip          INET,
    dst_ip          INET,
    envelope_from   TEXT,
    envelope_to     TEXT[],
    subject         TEXT,
    headers         JSONB,
    body_length     INTEGER
);

CREATE INDEX idx_smtp_pcap_id ON smtp_messages(pcap_id);

-- ============================================================
-- 8. alerts : Security findings with severity
-- ============================================================
CREATE TABLE alerts (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pcap_id          UUID NOT NULL REFERENCES pcap_files(id) ON DELETE CASCADE,
    severity         TEXT NOT NULL
                     CHECK (severity IN ('critical','high','medium','low','informational')),
    category         TEXT NOT NULL,
    title            TEXT NOT NULL,
    description      TEXT,
    evidence         JSONB,
    rule_id          TEXT,
    triggered_at     TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ai_corroborated  BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_alerts_pcap_id  ON alerts(pcap_id);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_category ON alerts(category);

-- ============================================================
-- 9. analysis_jobs : Async analysis job tracking
-- ============================================================
CREATE TABLE analysis_jobs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pcap_id         UUID NOT NULL REFERENCES pcap_files(id) ON DELETE CASCADE,
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued','parsing','extracting','detecting','assessing','completed','failed')),
    worker_id       TEXT,
    started_at      TIMESTAMP WITH TIME ZONE,
    completed_at    TIMESTAMP WITH TIME ZONE,
    error_message   TEXT,
    model_used      TEXT,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_jobs_pcap_id ON analysis_jobs(pcap_id);
CREATE INDEX idx_jobs_status   ON analysis_jobs(status);

-- ============================================================
-- 10. ai_assessments : LLM-generated structured reports
-- ============================================================
CREATE TABLE ai_assessments (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id                UUID NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    pcap_id               UUID NOT NULL REFERENCES pcap_files(id) ON DELETE CASCADE,
    risk_score            INTEGER CHECK (risk_score BETWEEN 0 AND 5),
    risk_label            TEXT CHECK (risk_label IN ('Critical','High','Medium','Low','Informational')),
    executive_summary     TEXT,
    key_findings          JSONB,
    recommendations       JSONB,
    protocol_distribution JSONB,
    top_talkers           JSONB,
    model_name            TEXT,
    model_confidence      FLOAT,
    raw_response          TEXT,
    generation_time_ms    INTEGER,
    created_at            TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_ai_pcap_id    ON ai_assessments(pcap_id);
CREATE INDEX idx_ai_risk_score ON ai_assessments(risk_score);

-- ============================================================
-- 11. users : Multi-user support (Post-MVP)
-- ============================================================
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username      TEXT UNIQUE NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'analyst'
                  CHECK (role IN ('admin','analyst','viewer')),
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login    TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_users_email ON users(email);

-- ============================================================
-- 12. audit_log : Compliance tracking (Post-MVP)
-- ============================================================
CREATE TABLE audit_log (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       UUID REFERENCES users(id),
    action        TEXT NOT NULL,
    resource_type TEXT,
    resource_id   UUID,
    ip_address    INET,
    user_agent    TEXT,
    details       JSONB,
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_audit_user    ON audit_log(user_id);
CREATE INDEX idx_audit_created ON audit_log(created_at);

-- ============================================================
-- TimescaleDB recommended configurations
-- ============================================================

-- Enable compression on flows after 7 days
ALTER TABLE flows SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'pcap_id,protocol',
    timescaledb.compress_orderby   = 'time DESC'
);

SELECT add_compression_policy('flows', INTERVAL '7 days');

-- Optional: Retention policy - keep flow data for 90 days
-- SELECT add_retention_policy('flows', INTERVAL '90 days');
