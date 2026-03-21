# Monitor Response Cache & Performance Fixes — Design Spec

**Goal:** Eliminate per-request O(n) serialization in high-traffic endpoints, parallelize WebSocket broadcasts, and move expensive computations off request paths to handle 10K concurrent agents.

**Architecture:** In-process precomputed response cache with mutation-driven invalidation behind an async protocol that can be swapped for Redis when horizontal scaling is needed. Parallel WebSocket sends via `asyncio.gather`. R0 computation and record pruning moved to periodic background task.

---

## 1. CacheBackend Protocol + InMemoryCache

New file: `monitor/cache.py`

### Interface

```python
class CacheBackend(Protocol):
    async def get(self, key: str) -> bytes | None: ...
    async def set(self, key: str, data: bytes) -> None: ...
    async def invalidate(self, key: str) -> None: ...
    async def invalidate_all(self) -> None: ...
```

Methods are `async` so a Redis backend (`redis.asyncio`) can be dropped in without wrapping every call site in `run_in_executor`. The `InMemoryCache` implementation awaits trivially (no actual I/O).

### InMemoryCache

Stores `dict[str, bytes]` for cached response bodies and `dict[str, bool]` for validity flags. No TTL — invalidation is explicit and mutation-driven.

### Cache Keys and Invalidation Matrix

| Handler | `"threat-intel"` | `"graph"` | `"metrics"` |
|---------|:-:|:-:|:-:|
| `receive_heartbeat` | | X | X |
| `receive_heartbeat` (contagion auto-quarantine path) | X | X | X |
| `receive_compromise` | X | X | X |
| `receive_threat` | | | X |
| `create_quarantine_rule` | X | X | X |
| `delete_quarantine_rule` | X | X | X |
| `create_killswitch_rule` | | X | X |
| `delete_killswitch_rule` | | X | X |

`invalidate_all()` is used during testing and available for the Redis swap path (e.g., cache flush on deploy).

### Endpoint Cache Hit Path

On cache hit, return `Response(content=cached_bytes, media_type="application/json")` directly — no dict construction, no JSON serialization, no Pydantic.

On cache miss, compute the response as before, serialize to JSON bytes, store in cache, return.

### Cache Warming

At the end of `lifespan()` startup (after graph rebuild), pre-populate all three cache keys to avoid first-request latency spikes.

### Redis Swap Path

Implement `RedisCache` satisfying `CacheBackend` (async methods map naturally to `redis.asyncio`). Swap in `lifespan()`: `app.state.cache = RedisCache(url)`. No changes to endpoints or invalidation call sites.

---

## 2. Parallel WebSocket Broadcast

Replace the sequential loop in `_broadcast()`. Take a snapshot of clients before gathering to prevent `RuntimeError: Set changed size during iteration`:

```python
async def _broadcast(app_state: Any, event: dict) -> None:
    clients = list(app_state.ws_clients)
    if not clients:
        return
    message = json.dumps(event)
    results = await asyncio.gather(
        *(ws.send_text(message) for ws in clients),
        return_exceptions=True,
    )
    dead = {ws for ws, r in zip(clients, results) if isinstance(r, Exception)}
    app_state.ws_clients -= dead
```

---

## 3. R0 Computation Moved to Background Task

Rename `_periodic_recluster` to `_periodic_background`. Add R0 estimation to the loop body:

```python
cached_r0 = r0.estimate_r0(cfg.r0_window_hours)
cached_r0_trend = r0.get_r0_trend(cfg.r0_window_hours)
r0.prune(time.time() - cfg.r0_window_hours * 3600)
```

Store results on `app.state` (e.g., `app.state.cached_r0`, `app.state.cached_r0_trend`). Initialize to `0.0` and `[]` respectively. The `get_metrics` endpoint reads these instead of computing on every request.

---

## 4. Remove Dead Query in Metrics

The `get_metrics` handler does `await run_db(db.get_events, event_type="threat", limit=0)` — fetches all threat events and discards the result (`limit=0` means "no limit" in the current `get_events` implementation). Remove it.

---

## 5. Metrics Uses Cached Counts

Instead of `graph.get_graph_state()` (constructs 10K dicts) just to count compromised/quarantined/killswitched, maintain counters on `app.state`:

```python
app.state.agent_counts = {"total": 0, "compromised": 0, "quarantined": 0, "killswitched": 0}
```

Updated by mutation handlers. Counter update rules:

- **Heartbeat**: increment `total` only if `agent_id not in graph` (new agent); existing agents are no-ops for the counter.
- **Compromise**: increment `compromised`.
- **Quarantine create/delete**: increment/decrement `quarantined`. Swarm-scope rules adjust by the count of affected agents.
- **Killswitch create/delete**: increment/decrement `killswitched`. Same swarm-scope handling.

The background task recomputes all counters from the graph every cycle (30s) as a consistency correction. On discrepancy, the counters are silently corrected (the graph is the source of truth). No logging unless drift exceeds a threshold.

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
| `monitor/app.py` | Cache in endpoints, parallel broadcast, expanded background task, agent counters, invalidation calls, cache warming |
| `monitor/epidemiology.py` | Add `prune()` method |
| `tests/test_cache.py` | New — InMemoryCache unit tests |
| `tests/test_epidemiology.py` | Test `prune()` |
| `tests/test_app.py` | Verify cached endpoints return correct data |

---

## Known Limitations / Out of Scope

- **`receive_trust` does not update the in-memory graph** — this is a pre-existing issue. Trust changes go to DB only. The graph (and therefore the `"graph"` cache) does not reflect trust score changes from trust reports. Fixing this is out of scope for this change.
- **`/api/v1/topic-clusters`, `/api/v1/embeddings`, `/api/v1/dendrogram`** are not cached. These are dashboard-only endpoints with lower traffic. They are candidates for future caching (invalidated by the background recluster task) but not required for the 10K agent target.

---

## What This Does NOT Change

- Database schema — no changes
- Agent-side SDK — no changes
- WebSocket protocol — same events, just sent faster
- API contracts — same JSON responses, just served from cache
