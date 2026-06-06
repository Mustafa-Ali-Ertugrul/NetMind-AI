# Sprint 10 — Adım 4 Planı: SlidingWindow

> **Status**: PLAN (read-only) — onayınız sonrası implementasyon başlayacak.
> **Repo root**: `C:\Users\Ali\Projects\NetMind-AI`
> **Hedef dosya**: `backend/live_engine/window.py`
> **Test dosyası**: `backend/tests/test_window.py`

---

## 1. Context

Sprint 10'da dönüştürülen pipeline için **zaman dilimleme katmanı** eksik:

```
[Planlanan pipeline]

RawEvent (HTTP POST)
   ↓ to_flow_event()
FlowEvent
   ↓
SlidingWindow              ← Adım 4 (bu)
   ↓ (5s window, 1s slide, enqueue + auto-evict)
FlowAggregator / StreamingRuleEngine
   ↓
Findings
   ↓
LiveAlertStore (Adım 6)
   ↓
API + Dashboard
```

Mevcut akışta `process_event()` her event için **anında** `feature_builder.add_event()` çağrısı yapıyor, `flush()` tüm birikimi tek seferde rule engine'e veriyor. Bu yüzden:
- **Zaman sınırı yok**: 1 saatte gelen event'ler tek window'da birikiyor.
- **Sürekli büyüyen state**: eski flow'lar hafızada tutulmaya devam ediyor.
- **Latency hedefi tutmuyor**: 5s pencere hedefi karşılanmıyor.

SlidingWindow ekleyerek:
1. Sadece son N saniyenin event'leri tutulur (memory bounded).
2. Periyodik (1s'de bir) otomatik flush tetiklenir.
3. Eski flow'lar evict edilir (`flush_older_than` entegrasyonu — `flow_aggregator.py:215` zaten mevcut).

---

## 2. Critical Integration Point

`SlidingWindow` → **sadece** time-slicing katmanı. Şunlara **dokunmaz**:
- `StreamingRuleEngine.process_event` / `flush` / `reset` mantığı
- `StreamingFlowAggregator` accumulator mantığı (sadece `flush_older_than`'ı çağırır)
- 9 batch rule (`backend/rule_engine/rules/*.py`)
- Threshold'lar (`backend/feature_extractor/constants.py`)

Eklediği tek şey: **"hangi event'ler şu anda aktif pencerede?"** kararı.

---

## 3. Design

### 3.1 Sınıf yapısı

```python
class SlidingWindow:
    """Time-windowed event buffer with auto-flush.

    Buffers FlowEvents into timestamped buckets; periodically
    flushes the windowed batch through a user-supplied callback
    (typically ``StreamingRuleEngine.flush()`` or a wrapper).

    Parameters
    ----------
    window_size : float
        Width of the active window in seconds. Default 5.0.
    slide : float
        Sliding interval in seconds. Default 1.0.
    on_flush : Callable[[list[FlowEvent]], Awaitable[None] | None]
        Callback invoked on every tick with the events currently
        in the (now-expanded) window. May be sync or async.
    max_window_events : int
        Hard cap on buffered events (defensive OOM guard). Default 50_000.
    """

    def __init__(
        self,
        window_size: float = 5.0,
        slide: float = 1.0,
        on_flush: Callable | None = None,
        max_window_events: int = 50_000,
    ): ...

    # ---- Producer API ----
    def add_event(self, event: FlowEvent) -> None: ...
    async def aadd_event(self, event: FlowEvent) -> None: ...

    # ---- Consumer API ----
    def get_window(self, now: datetime | None = None) -> list[FlowEvent]: ...
    def flush_old(self, now: datetime | None = None) -> list[FlowEvent]: ...

    # ---- Lifecycle ----
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    def slide(self) -> None: ...     # sync tick — useful for tests

    # ---- Metrics ----
    @property
    def size(self) -> int: ...
    @property
    def total_received(self) -> int: ...
    @property
    def total_flushed(self) -> int: ...
    @property
    def total_dropped(self) -> int: ...
```

### 3.2 Data structure

```python
self._buckets: deque[Bucket]   # ordered by bucket start_time
self._window_size: float
self._slide: float
self._on_flush: Callable
self._max_window_events: int

@dataclass
class _Bucket:
    start_ts: float          # monotonic seconds (aligned to slide boundary)
    events: list[FlowEvent] = field(default_factory=list)
```

**Neden `deque` + monolitik bucket yerine aligned bucket'lar?**
- `flush_old()` O(eski_bucket_sayısı) çalışır — event-by-event tarama yok.
- Her slide tick'inde tam bir bucket drop edilir → tahmin edilebilir bellek.
- `monotonic()` kullanılır → `time.time()`'a göre saat kaymasına duyarsız.

### 3.3 Window logic

```
t=0  window=[0..5]      bucket[0]=[0..1] bucket[1]=[1..2] ... bucket[4]=[4..5]
t=1  tick: bucket[0] expire, slide → window=[1..6] → add new bucket[5]=[5..6]
t=2  tick: bucket[1] expire ...
...
```

- Bucket'lar **mutlak event.ts**'e göre değil, **`monotonic()`-align** edilmiş `slide` aralıklarına yerleştirilir.
- `add_event(event)` → `bucket_idx = floor((monotonic() - epoch) / slide)` → uygun bucket'a append.
- `get_window(now)`: `now` anında `[now - window_size, now]` aralığına düşen bucket'ların tüm event'lerini döner.
- `flush_old(now)`: `now - window_size`'ten eski bucket'ları drop eder ve event'lerini döner (test/manuel kullanım).
- `slide()`: periyodik tick — `flush_old` çağırır, ardından `on_flush(window_events)` çağırır.

### 3.4 Async tasarım

`start()` bir `asyncio.Task` başlatır, her `slide` saniyede bir:
1. `flush_old()` çağır → eski event'ler callback'e gider (veya drop).
2. `get_window()` çağır → aktif event'leri callback'e gider.
3. Sleep `slide` seconds.

`stop()` graceful shutdown:
1. `_stop_event.set()`
2. `asyncio.wait_for(task, timeout=5.0)`
3. Son bir kez `on_flush(remaining_events)` çağır.

### 3.5 Backpressure

`max_window_events` aşıldığında:
- Eski event'ler evict edilir (FIFO).
- `_total_dropped` artırılır.
- `logger.warning` ile log düşülür (EventStream ile aynı pattern).

---

## 4. Test Plan — `backend/tests/test_window.py`

Toplam **~14 test** (her biri 1 saniye altı çalışır; time-based test'lerde `time.sleep` minimum 0.01–0.05s).

### 4.1 Window construction
- `test_default_window_size_and_slide` — 5.0 / 1.0 default
- `test_invalid_window_size_raises` — `window_size <= 0` → `ValueError`
- `test_invalid_slide_raises` — `slide <= 0` veya `slide > window_size` → `ValueError`

### 4.2 Add / Get semantics
- `test_add_event_appends_to_current_window` — `add_event` sonra `get_window()` event'i içerir
- `test_get_window_returns_only_last_5s` — 6 saniye önce eklenen event görünmez
- `test_multiple_events_in_window` — 10 event ekle, `len(get_window()) == 10`
- `test_empty_window` — `get_window()` boş liste döner

### 4.3 Sliding correctness
- `test_slide_drops_old_bucket` — `flush_old()` çağrıldığında eski bucket event'leri drop olur
- `test_slide_increments_total_flushed` — `slide()` çağrı sayısı `total_flushed` ile artar
- `test_slide_invokes_callback` — `on_flush` callback'i doğru event listesiyle çağrılır
- `test_slide_increments_total_received` — 5 event ekle, `slide()` çağır, `total_received == 5`

### 4.4 Memory bounds
- `test_max_window_events_cap` — 100.000 event ekle, `size() <= 50_000`
- `test_dropped_counter_increments_on_overflow` — overflow'da `total_dropped` artar

### 4.5 Async lifecycle
- `test_async_start_stop` — `start()` → 1 slide geçir → `stop()` graceful
- `test_async_callback_receives_windowed_events` — async `on_flush` çağrıldığında windowed event listesi gelir
- `test_double_start_raises` — `start()` iki kere → `RuntimeError`
- `test_stop_without_start_is_noop` — `stop()` hata vermez

### 4.6 Integration smoke
- `test_window_feeds_streaming_engine` — 10 event → SlidingWindow → `StreamingRuleEngine.process_event` → `engine.flush()` → `findings` döner (Step 3 ile entegrasyon)
- `test_async_window_end_to_end` — `start()` → 3 saniye boyunca async add → `stop()` → en az 1 flush oldu

---

## 5. Implementation Steps (Sıra)

| # | Adım | Çıktı |
|---|---|---|
| 1 | `backend/live_engine/window.py` yaz | Yeni dosya, ~150 satır |
| 2 | `backend/tests/test_window.py` yaz | Yeni dosya, ~14 test |
| 3 | `pytest backend/tests/test_window.py` çalıştır | 14/14 yeşil |
| 4 | `pytest backend/tests --ignore=backend/tests/test_storage_api.py` çalıştır | Full regression yeşil (362→362+) |
| 5 | Commit + push | `origin/master` |

> **Risk değerlendirmesi**: Düşük. Yeni dosyalar, mevcut API'lere dokunulmuyor. `SlidingWindow` opsiyonel bir katman — `StreamingRuleEngine` doğrudan kullanılmaya devam edebilir.

---

## 6. Open Questions (sormam gereken kararlar)

1. **`on_flush` senkron mu async mi olmalı?**
   - **Öneri**: İkisi de kabul edilsin (`Callable[[list[FlowEvent]], Awaitable[None] | None]`), runtime'da `inspect.iscoroutine()` ile dispatch.
   - Alternatif: Sadece async (`Awaitable` zorunlu) — test'lerde `asyncio.run` gerekir.

2. **Bucket alignment `monotonic()`'a mı `event.ts`'e mi göre?**
   - **Öneri**: `monotonic()` (scheduler clock'una güvenir, dış saat kaymalarından etkilenmez).
   - Alternatif: `event.ts` (kullanıcı-supplied zaman, ama backfill event'lerde garip davranır).

3. **`add_event` senkron mu async mi olmalı?**
   - **Öneri**: İkisi de (`add_event` sync, `aadd_event` async). Producer'lar genelde sync path'ten gelir (HTTP handler, internal queue drain).
   - Alternatif: Sadece sync, async kullanım `loop.run_in_executor` ile.

4. **`slide()` ve `start()` ayrı mı olmalı?**
   - **Öneri**: Evet — `slide()` test'lerde senkron ilerletme için, `start()` prod ortamda background task için. Pattern `EventConsumer.start()` / `stop()` ile aynı.

5. **Default `max_window_events = 50_000` uygun mu?**
   - **Öneri**: 50.000 (5s × 10K eps peak). 1M sınırı memory'yi şişirir, 5K çok kısıtlayıcı.

Bunlardan herhangi birinde farklı bir tercihiniz varsa söyleyin, yoksa **önerilen default'larla** ilerleyeceğim.

---

## 7. Next Step After Adım 4

- **Adım 5**: Alembic migration for `live_alerts` + `rule_stats` tables
- **Adım 6**: `storage/live_alert_writer.py` + `storage/rule_stats_writer.py`
- **Adım 7**: `api/routes/live.py` — ingest endpoint, timeline, live alerts, rule stats
- **Adım 8–10**: Frontend + adaptive + anomaly fusion

---

## 8. Onay İsteyen Sorular

Lütfen şunları onaylayın veya düzeltin:

1. **`SlidingWindow` API'si yukarıdaki gibi olsun mu?** (sync + async dual API, dual bucket structure)
2. **Test sayısı ~14 yeterli mi, yoksa daha fazla mı?**
3. **`max_window_events = 50_000` default uygun mu?**
4. **Bucket alignment `monotonic()`'a göre olsun mu?**

"Onayla" derseniz, **Adım 4 implementation'a geçiyorum** (plan modundan çıkıp dosyaları yazacağım).
