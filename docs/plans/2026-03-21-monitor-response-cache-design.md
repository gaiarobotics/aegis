# Monitor Response Cache & Performance Fixes — Design Spec

**Goal:** Eliminate per-request O(n) serialization in high-traffic endpoints, parallelize WebSocket broadcasts, and move expensive computations off request paths to handle 10K concurrent agents.

**Architecture:** In-process precomputed response cache with mutation-driven invalidation behind a protocol that can be swapped for Redis when horizontal scaling is needed. Parallel WebSocket sends via `asyncio.gather`. R0 computation and record pruning moved to periodic background task.

---

## 1. CacheBackend Protocol + InMemoryCache

New file: `monitor/cache.py`

### Interface

```python
class CacheBackend(Protocol):
    def get(self, key: str) -> bytes | None: ...
    def set(self, key: str, data: bytes) -> None: ...
    def invalidate(self, key: str) -> None: ...
    def invalidate_all(self) -> None: ...
```

### InMemoryCache

Stores `dict[str, bytes]` for cached response bodies and `dict[str, bool]` for validity flags. Thread-safe via the GIL (single-process, single event loop). No TTL — invalidation is explicit.

### Cache Keys and Invalidation Map

| Key | Endpoints served | Invalidated by |
|-----|-----------------|----------------|
| `"threat-intel"` | `GET /api/v1/threat-intel` | compromise, quarantine rule change |
| `"graph"` | `GET /api/v1/graph` | heartbeat, compromise, quarantine, killswitch |
| `"metrics"` | `GET /api/v1/metrics` | heartbeat, compromise, threat, quarantine, killswitch |

### Endpoint Cache Hit Path

On cache hit, return `Response(content=cached_bytes, media_type="application/json")` directly — no dict construction, no JSON serialization, no Pydantic.

On cache miss, compute the response as before, serialize to JSON bytes, store in cache, return.

### Redis Swap Path

Implement `RedisCache` satisfying `CacheBackend`. Swap in `lifespan()`. No changes to endpoints or invalidation call sites.

---

## 2. Parallel WebSocket Broadcast

Replace the sequential loop in `_broadcast()`:

```python
# Before: sequential
for ws in app_state.ws_clients:
    await ws.send_text(message)

# After: parallel
results = await asyncio.gather(
    *(ws.send_text(message) for ws in app_state.ws_clients),
    return_exceptions=True,
)
```

Dead clients identified from exceptions in results, removed from the set.

---

## 3. R0 Computation Moved to Background Task

Rename `_periodic_recluster` to `_periodic_background`. Add R0 estimation to the loop body:

```python
cached_r0 = r0.estimate_r0(cfg.r0_window_hours)
cached_r0_trend = r0.get_r0_trend(cfg.r0_window_hours)
r0.prune(time.time() - cfg.r0_window_hours * 3600)
```

Store results on `app.state` (e.g., `app.state.cached_r0`, `app.state.cached_r0_trend`). The `get_metrics` endpoint reads these instead of computing on every request.

---

## 4. Remove Dead Query in Metrics

Line 657 of `app.py` does `await run_db(db.get_events, event_type="threat", limit=0)` — fetches all threat events and discards the result. Remove it.

---

## 5. Metrics Uses Cached Counts

Instead of `graph.get_graph_state()` (constructs 10K dicts) just to count compromised/quarantined/killswitched, maintain counters on `app.state`:

```python
app.state.agent_counts = {"total": 0, "compromised": 0, "quarantined": 0, "killswitched": 0}
```

Updated by mutation handlers (heartbeat, compromise, quarantine, killswitch). The background task periodically recomputes from the graph as a consistency check.

`get_metrics` reads the counters directly instead of scanning the graph.

---

## 6. R0Estimator Record Pruning

Add to `monitor/epidemiology.py`:

```python
def prune(self, cutoff: float) -> int:
    """Remove records older than cutoff timestamp. Returns count removed."""
    before = len(self._records)
    self._records = [r for r in self._records if r.timestamp >= cutoff]
    return before - len(self._records)
```

Called by the background task after each R0 computation. Prevents unbounded memory growth.

---

## Files Changed

| File | Change |
|------|--------|
| `monitor/cache.py` | New — CacheBackend protocol + InMemoryCache |
| `monitor/app.py` | Cache in endpoints, parallel broadcast, expanded background task, agent counters, invalidation calls |
| `monitor/epidemiology.py` | Add `prune()` method |
| `tests/test_cache.py` | New — InMemoryCache unit tests |
| `tests/test_epidemiology.py` | Test `prune()` |
| `tests/test_app.py` | Verify cached endpoints return correct data |

---

## What This Does NOT Change

- Database schema — no changes
- Agent-side SDK — no changes
- WebSocket protocol — same events, just sent faster
- API contracts — same JSON responses, just served from cache
