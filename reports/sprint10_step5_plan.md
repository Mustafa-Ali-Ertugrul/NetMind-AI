# Sprint 10 — Adım 5 Planı: Alembic Migration (Extended Schema)

> **Status**: PLAN (read-only) — onayınız sonrası implementation başlayacak.
> **Repo root**: `C:\Users\Ali\Projects\NetMind-AI`
> **Hedef dosyalar**:
>   - `backend/migrations/versions/<rev>_sprint10_live_engine_schema.py` (NEW migration)
>   - `backend/storage/models.py` (extend)
> **Test dosyaları**:
>   - `backend/tests/test_migrations.py` (NEW) — upgrade/downgrade smoke

---

## 1. Context

Sprint 10'da `StreamingRuleEngine` artık sürekli olarak `Finding` üretiyor. Bunları:
1. **Persist etmemiz** gerekiyor (operational memory → durable storage)
2. **Real-time API'ye** sunmamız gerekiyor (Adım 7'de)
3. **Adaptive threshold** için kural performans geçmişini izlememiz gerekiyor (Adım 9)

Mevcut `alerts` tablosu **batch pipeline** için tasarlanmış: `pcap_id` FK zorunlu, `pcap_files` tablosuna cascade. Streaming'de `pcap_id` yok — sadece **synthetic `session_id` UUID** var. Bu yüzden **ayrı `live_alerts` tablosu** gerek.

---

## 2. Mevcut DB Infrastructure (Sprint 9X+9A'dan)

```
backend/
├── alembic.ini                     # ✓ config
├── migrations/
│   ├── env.py                      # ✓ async engine, target_metadata=Base.metadata
│   └── versions/
│       ├── 1f7f3693f325_baseline_schema.py
│       └── b0e5f0c53d14_add_flow_interval_variance_and_ack_count.py
└── storage/
    ├── models.py                   # ✓ PcapFile, Packet, Flow, DnsQuery, HttpRequest,
    │                                 #   Alert, AnalysisJob, AiAssessment
    ├── alert_writer.py             # ✓ batch findings → Alert rows
    └── database.py                 # ✓ SQLAlchemy async Base
```

**Sprint 9A'dan gelen pattern**: Mevcut `Alert` modeli `pcap_id` FK ile sıkıca bağlı, batch job'lar için. Streaming için ayrı bir tablo ailesi kuracağız (FK olmadan, synthetic session_id).

---

## 3. 🅰️ Minimal vs 🅱️ Extended Schema Kararı

### 🅰️ Minimal
- `live_alerts`
- `rule_stats`

### 🅱️ Extended (önerilen)
- `live_alerts` — streaming findings
- `alert_events` — alert lifecycle (ack, dismiss, resolve)
- `rule_stats` — adaptive threshold input
- `rule_performance_history` — rule hit/miss over time
- `flow_samples` — debug/observability (last N flows per session)

### Neden extended?
- "Engine + Intelligence" fazındayız → minimal DB ileride tıkanır
- Sprint 9 (adaptive threshold v1) → `rule_stats` zorunlu
- Sprint 10 (real-time observability) → `alert_events` ve `flow_samples` kritik
- Minimal ile başlayıp genişletmek → her yeni ihtiyaçta migration yazmak (operationally pahalı)
- 5 tablo eklemek ile 2 tablo eklemek implementation süresi olarak benzer (tek migration)

---

## 4. Schema Design

### 4.1 `live_alerts` (primary output)

Streaming session'dan gelen findings. `pcap_id` FK YOK — synthetic `session_id` (UUID) string.

```python
class LiveAlert(Base):
    __tablename__ = "live_alerts"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    session_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_entities: Mapped[list[str]] = mapped_column(JSONB, nullable=True, default=list)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=True, default=dict)
    feature_snapshot: Mapped[dict] = mapped_column(JSONB, nullable=True, default=dict)
    timestamp_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    timestamp_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    raw_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    __table_args__ = (
        CheckConstraint(
            "status IN ('active','acknowledged','dismissed','resolved')",
            name="ck_live_alerts_status",
        ),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','informational')",
            name="ck_live_alerts_severity",
        ),
        Index("idx_live_alerts_session", "session_id"),
        Index("idx_live_alerts_rule", "rule_id"),
        Index("idx_live_alerts_severity_triggered", "severity", "triggered_at"),
        Index("idx_live_alerts_status", "status"),
    )
```

### 4.2 `alert_events` (lifecycle audit)

Alert ack/dismiss/resolve olayları.

```python
class AlertEvent(Base):
    __tablename__ = "alert_events"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    alert_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("live_alerts.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(64), nullable=True)  # user, system
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    __table_args__ = (
        CheckConstraint(
            "event_type IN ('created','acknowledged','dismissed','resolved','reopened')",
            name="ck_alert_events_type",
        ),
        Index("idx_alert_events_alert_id", "alert_id"),
        Index("idx_alert_events_created", "created_at"),
    )
```

### 4.3 `rule_stats` (adaptive threshold input)

Per-rule rolling window (son 100 evaluation).

```python
class RuleStats(Base):
    __tablename__ = "rule_stats"

    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    session_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True, index=True)
    evaluations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    miss: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    avg_risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    max_risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    rolling_window_size: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    last_evaluation_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("idx_rule_stats_rule_updated", "rule_id", "updated_at"),
    )
```

### 4.4 `rule_performance_history` (time-series, Adım 9 için)

Rule hit/miss geçmişi. Zaman-bazlı performans grafiği.

```python
class RulePerformanceHistory(Base):
    __tablename__ = "rule_performance_history"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    bucket_duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    evaluations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    false_positive_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    avg_risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    __table_args__ = (
        Index("idx_rph_rule_bucket", "rule_id", "bucket_start"),
        Index("idx_rph_bucket", "bucket_start"),
    )
```

### 4.5 `flow_samples` (debug/observability)

Son N flow per session. Overhead kontrolü için.

```python
class FlowSample(Base):
    __tablename__ = "flow_samples"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    src_ip: Mapped[IPv4Address | IPv6Address] = mapped_column(INET, nullable=False)
    dst_ip: Mapped[IPv4Address | IPv6Address] = mapped_column(INET, nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    bytes_total: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    packets_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    flow_metadata: Mapped[dict] = mapped_column(JSONB, nullable=True, default=dict)

    __table_args__ = (
        Index("idx_flow_samples_session_time", "session_id", "captured_at"),
    )
```

---

## 5. Migration File

**Path**: `backend/migrations/versions/<rev>_sprint10_live_engine_schema.py`

**Rev zinciri**: `b0e5f0c53d14` → `<new_rev>`

```python
"""Sprint 10 live engine schema

Revision ID: <autogen>
Revises: b0e5f0c53d14
Create Date: <autogen>

Adds 5 tables for streaming/real-time engine:
- live_alerts: streaming findings (no pcap_id FK, synthetic session_id)
- alert_events: alert lifecycle audit
- rule_stats: rolling-window per-rule stats
- rule_performance_history: time-bucketed performance history
- flow_samples: debug/observability (last N flows)
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID as PG_UUID

revision: str = "<autogen>"
down_revision: Union[str, Sequence[str], None] = "b0e5f0c53d14"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # live_alerts
    op.create_table(
        "live_alerts",
        sa.Column("id", PG_UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id", PG_UUID(as_uuid=True), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("affected_entities", JSONB(), nullable=True),
        sa.Column("evidence", JSONB(), nullable=True),
        sa.Column("feature_snapshot", JSONB(), nullable=True),
        sa.Column("timestamp_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("timestamp_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("triggered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("raw_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.CheckConstraint(
            "status IN ('active','acknowledged','dismissed','resolved')",
            name="ck_live_alerts_status",
        ),
        sa.CheckConstraint(
            "severity IN ('critical','high','medium','low','informational')",
            name="ck_live_alerts_severity",
        ),
    )
    op.create_index("idx_live_alerts_session", "live_alerts", ["session_id"])
    op.create_index("idx_live_alerts_rule", "live_alerts", ["rule_id"])
    op.create_index("idx_live_alerts_severity_triggered", "live_alerts", ["severity", "triggered_at"])
    op.create_index("idx_live_alerts_status", "live_alerts", ["status"])

    # alert_events
    op.create_table(
        "alert_events",
        sa.Column("id", PG_UUID(as_uuid=True), primary_key=True),
        sa.Column("alert_id", PG_UUID(as_uuid=True),
                  sa.ForeignKey("live_alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(64), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint(
            "event_type IN ('created','acknowledged','dismissed','resolved','reopened')",
            name="ck_alert_events_type",
        ),
    )
    op.create_index("idx_alert_events_alert_id", "alert_events", ["alert_id"])
    op.create_index("idx_alert_events_created", "alert_events", ["created_at"])

    # rule_stats
    op.create_table(
        "rule_stats",
        sa.Column("id", PG_UUID(as_uuid=True), primary_key=True),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("session_id", PG_UUID(as_uuid=True), nullable=True),
        sa.Column("evaluations", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("miss", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("avg_risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("max_risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("rolling_window_size", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("last_evaluation_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_rule_stats_rule_updated", "rule_stats", ["rule_id", "updated_at"])

    # rule_performance_history
    op.create_table(
        "rule_performance_history",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("bucket_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("bucket_duration_seconds", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("evaluations", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("false_positive_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("avg_risk_score", sa.Float(), nullable=False, server_default="0.0"),
    )
    op.create_index("idx_rph_rule_bucket", "rule_performance_history", ["rule_id", "bucket_start"])
    op.create_index("idx_rph_bucket", "rule_performance_history", ["bucket_start"])

    # flow_samples
    op.create_table(
        "flow_samples",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("session_id", PG_UUID(as_uuid=True), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("src_ip", INET(), nullable=False),
        sa.Column("dst_ip", INET(), nullable=False),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("bytes_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("packets_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("flow_metadata", JSONB(), nullable=True),
    )
    op.create_index("idx_flow_samples_session_time", "flow_samples", ["session_id", "captured_at"])


def downgrade() -> None:
    op.drop_table("flow_samples")
    op.drop_table("rule_performance_history")
    op.drop_table("rule_stats")
    op.drop_table("alert_events")
    op.drop_table("live_alerts")
```

---

## 6. Test Plan

**Path**: `backend/tests/test_migrations.py`

### 6.1 ~10 smoke tests

```python
class TestSprint10Migration:
    def test_migration_revision_chain(self): ...
    def test_live_alerts_columns(self): ...
    def test_alert_events_fk_cascade(self): ...
    def test_rule_stats_rolling_window_default(self): ...
    def test_rule_performance_history_indexes(self): ...
    def test_flow_samples_inet_columns(self): ...
    def test_upgrade_then_downgrade(self): ...
    def test_check_constraint_severity(self): ...
    def test_check_constraint_status(self): ...
    def test_check_constraint_event_type(self): ...
```

**Test yöntemi**:
- In-memory SQLite veya geçici test database
- `alembic upgrade head` → schema doğrula
- `alembic downgrade -1` → reverse doğrula
- SQLAlchemy metadata yansıması kullanarak tablo/kolon/index varlığını kontrol et

### 6.2 ~5 model unit tests (örneğin `test_live_alert_models.py`)

```python
class TestLiveAlertModel:
    def test_create_with_minimum_fields(self): ...
    def test_severity_check_constraint(self): ...
    def test_status_default_active(self): ...
    def test_session_id_required(self): ...

class TestRuleStatsModel:
    def test_create_defaults(self): ...
    def test_rolling_window_default_100(self): ...
```

---

## 7. Implementation Steps (Sıra)

| # | Adım | Çıktı |
|---|---|---|
| 1 | `backend/storage/models.py` — 5 yeni model ekle (LiveAlert, AlertEvent, RuleStats, RulePerformanceHistory, FlowSample) | Mevcut dosya extend |
| 2 | `alembic revision -m "sprint10 live engine schema"` çalıştır (autogen) | Migration skeleton |
| 3 | Migration'ı yukarıdaki `upgrade()` / `downgrade()` ile doldur | Yeni migration dosyası |
| 4 | `backend/tests/test_migrations.py` yaz | Yeni test dosyası |
| 5 | `alembic upgrade head` çalıştır → gerçek DB'de doğrula | (opsiyonel, lokal DB gerekli) |
| 6 | `pytest backend/tests/test_migrations.py` çalıştır | 10/10 yeşil |
| 7 | Full regression | 385+ passed |
| 8 | Commit + push | `origin/master` |

> **Risk değerlendirmesi**: Düşük. Sadece yeni tablolar ekleniyor, mevcut tablolara dokunulmuyor. Downgrade güvenli (yeni tablolar drop).

---

## 8. Open Questions (sormam gereken kararlar)

1. **`live_alerts.session_id` FK olsun mu?**
   - **Öneri**: Hayır, FK yok. `session_id` synthetic UUID. `live_sessions` tablosu ileride Adım 7'de eklenirse FK'ya dönüştürülebilir (nullable şimdi yapsak bile).

2. **`flow_samples` retention policy?**
   - **Öneri**: Sprint 10 kapsamı dışında bırak (TTL/cleanup policy). Adım 7 veya ops task'ı. Şimdilik sadece index'liyoruz.

3. **`rule_performance_history` bucket size default'u 60s mi olsun?**
   - **Öneri**: 60s. Sprint 10'da 5s window var ama per-rule metrics için 60s bucket daha temiz grafik verir.

4. **`live_alerts.evidence` ve `feature_snapshot` JSONB olsun mu?**
   - **Öneri**: Evet (sorgulama esnekliği + ileride JSON path queries).

5. **Migration `down_revision` ne olacak?**
   - **Öneri**: `b0e5f0c53d14` (mevcut son migration).

---

## 9. Next Steps After Adım 5

- **Adım 6**: `storage/live_alert_writer.py` + `storage/rule_stats_writer.py` (models'ı kullanan DB writers)
- **Adım 7**: `api/routes/live.py` — ingest endpoint, timeline, live alerts, rule stats
- **Adım 8**: Frontend `LiveMonitorPage` + Dashboard widget
- **Adım 9**: Adaptive threshold (memory-based) — `rule_stats` reader
- **Adım 10**: Anomaly fusion + final regression + push

---

## 10. Onay İsteyen Sorular

Lütfen şunları onaylayın veya düzeltin:

1. **🅱️ Extended schema onaylıyor musunuz?** (5 tablo: `live_alerts`, `alert_events`, `rule_stats`, `rule_performance_history`, `flow_samples`)
2. **Migration `down_revision = b0e5f0c53d14` olsun mu?**
3. **Test sayısı ~15 (10 migration smoke + 5 model unit) yeterli mi?**
4. **Models'ı `backend/storage/models.py` mevcut dosyasına mı ekleyelim, yoksa `backend/storage/live_models.py` ayrı dosyaya mı?**
   - **Öneri**: Aynı dosyada (mevcut pattern, basit)
5. **Tüm `live_alerts` alanları (severity/confidence/affected_entities/...) yukarıdaki gibi mi?**

"Onayla" derseniz, **Adım 5 implementation'a geçiyorum** (plan modundan çıkıp migration + models + tests yazacağım).
