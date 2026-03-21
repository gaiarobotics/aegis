# Monitor Response Cache & Performance Fixes — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate per-request O(n) serialization in high-traffic monitor endpoints to handle 10K concurrent agents.

**Architecture:** Async `CacheBackend` protocol with `InMemoryCache` implementation storing pre-serialized JSON bytes. Mutation-driven invalidation from all 8 handler paths. Parallel WebSocket broadcast. R0 + record pruning moved to background task. Agent counters replace full graph scans in metrics.

**Tech Stack:** Python asyncio, FastAPI, JSON bytes caching

**Spec:** `docs/plans/2026-03-21-monitor-response-cache-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `monitor/cache.py` | New — `CacheBackend` protocol + `InMemoryCache` class |
| `monitor/epidemiology.py` | Add `prune()` method |
| `monitor/app.py` | Cache integration, parallel broadcast, background task expansion, counters, invalidation |
| `tests/test_cache.py` | New — `InMemoryCache` unit tests |
| `tests/test_epidemiology.py` | Add `prune()` tests |
| `tests/test_app.py` | Verify cached endpoints return correct data |

---

## Chunk 1: Foundation (cache module + R0 pruning)

### Task 1: Create CacheBackend protocol and InMemoryCache

**Files:**
- Create: `aegis-monitor/monitor/cache.py`
- Create: `aegis-monitor/tests/test_cache.py`

- [ ] **Step 1: Write the failing tests**

Create `aegis-monitor/tests/test_cache.py`:

```python
"""Tests for the response cache."""

import pytest

from monitor.cache import InMemoryCache


@pytest.mark.asyncio
class TestInMemoryCache:
    async def test_get_returns_none_on_miss(self):
        cache = InMemoryCache()
        assert await cache.get("nonexistent") is None

    async def test_set_then_get(self):
        cache = InMemoryCache()
        await cache.set("key", b'{"data": 1}')
        result = await cache.get("key")
        assert result == b'{"data": 1}'

    async def test_invalidate_clears_key(self):
        cache = InMemoryCache()
        await cache.set("key", b"data")
        await cache.invalidate("key")
        assert await cache.get("key") is None

    async def test_invalidate_nonexistent_key_is_noop(self):
        cache = InMemoryCache()
        await cache.invalidate("nonexistent")  # should not raise

    async def test_invalidate_all(self):
        cache = InMemoryCache()
        await cache.set("a", b"1")
        await cache.set("b", b"2")
        await cache.invalidate_all()
        assert await cache.get("a") is None
        assert await cache.get("b") is None

    async def test_set_overwrites_previous(self):
        cache = InMemoryCache()
        await cache.set("key", b"old")
        await cache.set("key", b"new")
        assert await cache.get("key") == b"new"

    async def test_invalidate_then_set_works(self):
        cache = InMemoryCache()
        await cache.set("key", b"v1")
        await cache.invalidate("key")
        await cache.set("key", b"v2")
        assert await cache.get("key") == b"v2"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_cache.py -v`
Expected: FAIL — `monitor.cache` does not exist

- [ ] **Step 3: Implement cache module**

Create `aegis-monitor/monitor/cache.py`:

```python
"""Response cache for AEGIS monitor.

Stores pre-serialized JSON bytes keyed by string.  Invalidation is
explicit and mutation-driven (no TTL).

The ``CacheBackend`` protocol uses async methods so a Redis backend
(``redis.asyncio``) can be dropped in without wrapping call sites.
The ``InMemoryCache`` implementation awaits trivially.
"""

from __future__ import annotations

from typing import Protocol


class CacheBackend(Protocol):
    """Async cache interface — swap InMemoryCache for RedisCache later."""

    async def get(self, key: str) -> bytes | None: ...
    async def set(self, key: str, data: bytes) -> None: ...
    async def invalidate(self, key: str) -> None: ...
    async def invalidate_all(self) -> None: ...


class InMemoryCache:
    """In-process cache storing pre-serialized response bytes."""

    def __init__(self) -> None:
        self._data: dict[str, bytes] = {}

    async def get(self, key: str) -> bytes | None:
        return self._data.get(key)

    async def set(self, key: str, data: bytes) -> None:
        self._data[key] = data

    async def invalidate(self, key: str) -> None:
        self._data.pop(key, None)

    async def invalidate_all(self) -> None:
        self._data.clear()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_cache.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git -c commit.gpgsign=false add aegis-monitor/monitor/cache.py aegis-monitor/tests/test_cache.py
git -c commit.gpgsign=false commit -m "feat(monitor): add async CacheBackend protocol and InMemoryCache"
```

---

### Task 2: Add R0Estimator.prune() method

**Files:**
- Modify: `aegis-monitor/monitor/epidemiology.py`
- Modify: `aegis-monitor/tests/test_epidemiology.py`

- [ ] **Step 1: Write the failing tests**

Append to `aegis-monitor/tests/test_epidemiology.py`:

```python
class TestPrune:
    def test_prune_removes_old_records(self):
        est = R0Estimator()
        now = time.time()
        est.add_record(_make_record("a1", "a2", now - 7200))  # old
        est.add_record(_make_record("a1", "a3", now))          # recent
        removed = est.prune(now - 3600)
        assert removed == 1
        assert len(est._records) == 1

    def test_prune_returns_zero_when_nothing_to_remove(self):
        est = R0Estimator()
        now = time.time()
        est.add_record(_make_record("a1", "a2", now))
        removed = est.prune(now - 3600)
        assert removed == 0

    def test_prune_empty(self):
        est = R0Estimator()
        assert est.prune(time.time()) == 0

    def test_prune_removes_all(self):
        est = R0Estimator()
        old = time.time() - 7200
        est.add_record(_make_record("a1", "a2", old))
        est.add_record(_make_record("a1", "a3", old))
        removed = est.prune(time.time())
        assert removed == 2
        assert len(est._records) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_epidemiology.py::TestPrune -v`
Expected: FAIL — `R0Estimator` has no `prune` method

- [ ] **Step 3: Implement prune**

Add to `R0Estimator` class in `aegis-monitor/monitor/epidemiology.py`:

```python
def prune(self, cutoff: float) -> int:
    """Remove records older than *cutoff* timestamp.

    Returns the number of records removed.
    """
    before = len(self._records)
    self._records = [r for r in self._records if r.timestamp >= cutoff]
    return before - len(self._records)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_epidemiology.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git -c commit.gpgsign=false add aegis-monitor/monitor/epidemiology.py aegis-monitor/tests/test_epidemiology.py
git -c commit.gpgsign=false commit -m "feat(monitor): add R0Estimator.prune() to cap record growth"
```

---

## Chunk 2: Parallel broadcast + background task expansion

### Task 3: Parallel WebSocket broadcast

**Files:**
- Modify: `aegis-monitor/monitor/app.py`

- [ ] **Step 1: Replace `_broadcast` function**

In `aegis-monitor/monitor/app.py`, replace the `_broadcast` function (currently around lines 110-119) with:

```python
async def _broadcast(app_state: Any, event: dict) -> None:
    """Push an event to all connected WebSocket clients in parallel."""
    clients = list(app_state.ws_clients)
    if not clients:
        return
    message = json.dumps(event)
    results = await asyncio.gather(
        *(ws.send_text(message) for ws in clients),
        return_exceptions=True,
    )
    dead = {ws for ws, r in zip(clients, results) if isinstance(r, Exception)}
    if dead:
        app_state.ws_clients -= dead
```

- [ ] **Step 2: Run existing tests**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_app.py -v`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git -c commit.gpgsign=false add aegis-monitor/monitor/app.py
git -c commit.gpgsign=false commit -m "perf(monitor): parallelize WebSocket broadcast with asyncio.gather"
```

---

### Task 4: Expand background task with R0 caching + pruning + counter sync

**Files:**
- Modify: `aegis-monitor/monitor/app.py`

- [ ] **Step 1: Rename `_periodic_recluster` to `_periodic_background` and expand**

Replace the `_periodic_recluster` function and update lifespan references. The new function does:
1. Topic reclustering (existing)
2. R0 computation + caching on `app.state`
3. Record pruning
4. Agent counter recomputation from graph (consistency correction)

```python
async def _periodic_background(app_state, interval: float = 30.0):
    """Periodic background work: reclustering, R0, pruning, counter sync."""
    while True:
        await asyncio.sleep(interval)
        try:
            # 1. Topic reclustering
            graph_state = app_state.graph.get_graph_state()
            agent_statuses = {}
            for n in graph_state["nodes"]:
                if n["is_compromised"]:
                    agent_statuses[n["id"]] = "compromised"
                elif n["is_quarantined"]:
                    agent_statuses[n["id"]] = "quarantined"
                else:
                    agent_statuses[n["id"]] = "active"
            app_state.topic_clusterer.update_stable_clusters(agent_statuses)

            centroids = app_state.topic_clusterer.get_cluster_centroids()
            active_count = sum(1 for c in centroids if c["active"])
            await _broadcast(app_state, {
                "type": "topic_clusters_updated",
                "active_cluster_count": active_count,
            })

            # 2. R0 computation + caching
            cfg = app_state.config
            app_state.cached_r0 = app_state.r0.estimate_r0(cfg.r0_window_hours)
            app_state.cached_r0_trend = app_state.r0.get_r0_trend(cfg.r0_window_hours)

            # 3. Prune old records
            cutoff = time.time() - cfg.r0_window_hours * 3600
            app_state.r0.prune(cutoff)

            # 4. Recompute agent counters from graph (consistency correction)
            nodes = graph_state["nodes"]
            app_state.agent_counts = {
                "total": len(nodes),
                "compromised": sum(1 for n in nodes if n["is_compromised"]),
                "quarantined": sum(1 for n in nodes if n["is_quarantined"]),
                "killswitched": sum(1 for n in nodes if n["is_killswitched"]),
            }
        except Exception:
            logging.getLogger(__name__).debug("Background task failed", exc_info=True)
```

- [ ] **Step 2: Update lifespan to initialize cached state and use new function name**

In the `lifespan` function, before the `recluster_task` line, add:

```python
app.state.cached_r0 = 0.0
app.state.cached_r0_trend = []
app.state.agent_counts = {"total": 0, "compromised": 0, "quarantined": 0, "killswitched": 0}
```

Update the task creation:
```python
recluster_task = asyncio.create_task(_periodic_background(app.state))
```

- [ ] **Step 3: Run tests**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_app.py -v`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git -c commit.gpgsign=false add aegis-monitor/monitor/app.py
git -c commit.gpgsign=false commit -m "perf(monitor): expand background task with R0 caching, pruning, counter sync"
```

---

## Chunk 3: Cache integration in endpoints + invalidation

### Task 5: Integrate cache in `get_threat_intel` endpoint

**Files:**
- Modify: `aegis-monitor/monitor/app.py`

- [ ] **Step 1: Add cache to lifespan**

In `lifespan`, add after other state initialization:

```python
app.state.cache = InMemoryCache()
```

Add the import at top of file:

```python
from monitor.cache import InMemoryCache
```

- [ ] **Step 2: Convert `get_threat_intel` to use cache**

Replace the `get_threat_intel` handler with:

```python
@app.get("/api/v1/threat-intel")
async def get_threat_intel(_key: str = Depends(verify_api_key)):
    """Return threat intelligence for agent-side pre-emptive filtering."""
    cache = app.state.cache
    cached = await cache.get("threat-intel")
    if cached is not None:
        from fastapi.responses import Response
        return Response(content=cached, media_type="application/json")

    graph: AgentGraph = app.state.graph
    contagion_detector: ContagionDetector = app.state.contagion_detector

    graph_state = graph.get_graph_state()

    compromised_agents = [
        n["id"] for n in graph_state["nodes"] if n["is_compromised"]
    ]
    quarantined_agents = [
        n["id"] for n in graph_state["nodes"] if n["is_quarantined"]
    ]
    compromised_hashes = [
        f"{h:032x}" for h in contagion_detector._compromised.values()
    ]

    result = {
        "compromised_agents": compromised_agents,
        "compromised_hashes": compromised_hashes,
        "quarantined_agents": quarantined_agents,
        "generated_at": time.time(),
    }
    await cache.set("threat-intel", json.dumps(result).encode())
    return result
```

- [ ] **Step 3: Add invalidation calls to handlers that affect threat-intel**

Per the invalidation matrix, add `await app.state.cache.invalidate("threat-intel")` to:

1. `receive_compromise` — after the contagion cloud update (after the `if vr.hash_confirmed` block, before `at_risk` computation)
2. `create_quarantine_rule` — after the graph update
3. `delete_quarantine_rule` — after the graph update
4. `receive_heartbeat` — inside the contagion auto-quarantine path (after `graph.mark_quarantined`)

- [ ] **Step 4: Run tests**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_app.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git -c commit.gpgsign=false add aegis-monitor/monitor/app.py
git -c commit.gpgsign=false commit -m "perf(monitor): cache threat-intel endpoint with mutation-driven invalidation"
```

---

### Task 6: Integrate cache in `get_graph` endpoint

**Files:**
- Modify: `aegis-monitor/monitor/app.py`

- [ ] **Step 1: Convert `get_graph` to use cache**

Replace the `get_graph` handler:

```python
@app.get("/api/v1/graph")
async def get_graph(_key: str = Depends(verify_api_key)):
    cache = app.state.cache
    cached = await cache.get("graph")
    if cached is not None:
        from fastapi.responses import Response
        return Response(content=cached, media_type="application/json")

    graph: AgentGraph = app.state.graph
    topic_clusterer: TopicHashClusterer = app.state.topic_clusterer
    graph_data = graph.get_graph_state()

    cluster_colors = topic_clusterer.get_cluster_colors_stable()
    if not cluster_colors:
        cluster_colors = topic_clusterer.get_cluster_colors()
    for node in graph_data["nodes"]:
        node["topic_color"] = cluster_colors.get(node["id"], "")

    await cache.set("graph", json.dumps(graph_data).encode())
    return graph_data
```

- [ ] **Step 2: Add `"graph"` invalidation to all mutation handlers**

Per the invalidation matrix, add `await app.state.cache.invalidate("graph")` to:

1. `receive_heartbeat` — after graph update (after `graph.update_from_heartbeat`)
2. `receive_heartbeat` (contagion path) — already covered by heartbeat invalidation
3. `receive_compromise` — after `graph.mark_compromised`
4. `create_quarantine_rule` — after graph update
5. `delete_quarantine_rule` — after graph update
6. `create_killswitch_rule` — after graph update
7. `delete_killswitch_rule` — after graph update

- [ ] **Step 3: Run tests**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_app.py -v`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git -c commit.gpgsign=false add aegis-monitor/monitor/app.py
git -c commit.gpgsign=false commit -m "perf(monitor): cache graph endpoint with mutation-driven invalidation"
```

---

### Task 7: Integrate cache in `get_metrics` + remove dead query + use counters

**Files:**
- Modify: `aegis-monitor/monitor/app.py`

- [ ] **Step 1: Replace `get_metrics` handler**

Replace with version that:
- Uses cache for full response
- Reads `cached_r0` and `cached_r0_trend` from `app.state`
- Reads `agent_counts` from `app.state`
- Removes the dead `get_events(limit=0)` call

```python
@app.get("/api/v1/metrics")
async def get_metrics(_key: str = Depends(verify_api_key)):
    cache = app.state.cache
    cached = await cache.get("metrics")
    if cached is not None:
        from fastapi.responses import Response
        return Response(content=cached, media_type="application/json")

    clusterer: ThreatClusterer = app.state.clusterer
    db: Database = app.state.db

    cluster_info = clusterer.get_cluster_info()
    real_clusters = [c for c in cluster_info if c["cluster_id"] >= 0]

    topic_clusterer: TopicHashClusterer = app.state.topic_clusterer
    topic_centroids = topic_clusterer.get_cluster_centroids()
    topic_cluster_count = sum(1 for c in topic_centroids if c["active"])

    active_threats = await run_db(db.get_events, event_type="threat",
                                  since=time.time() - 3600)

    counts = app.state.agent_counts
    result = {
        "r0": app.state.cached_r0,
        "r0_trend": app.state.cached_r0_trend,
        "active_threats": len(active_threats),
        "total_agents": counts["total"],
        "compromised_agents": counts["compromised"],
        "quarantined_agents": counts["quarantined"],
        "killswitched_agents": counts["killswitched"],
        "cluster_count": len(real_clusters),
        "clusters": cluster_info,
        "topic_cluster_count": topic_cluster_count,
    }
    await cache.set("metrics", json.dumps(result).encode())
    return result
```

- [ ] **Step 2: Add `"metrics"` invalidation to all mutation handlers**

Per the invalidation matrix, add `await app.state.cache.invalidate("metrics")` to:

1. `receive_heartbeat` — after graph update
2. `receive_compromise` — after graph update
3. `receive_threat` — after clusterer update
4. `create_quarantine_rule` — after graph update
5. `delete_quarantine_rule` — after graph update
6. `create_killswitch_rule` — after graph update
7. `delete_killswitch_rule` — after graph update

Many of these handlers already have `"graph"` invalidation from Task 6 — add `"metrics"` alongside it.

- [ ] **Step 3: Add counter updates to mutation handlers**

Add counter increments/decrements in the relevant handlers:

- `receive_heartbeat`: before graph update, check `agent_id not in graph.graph`. If new agent, increment `app.state.agent_counts["total"]`.
- `receive_compromise`: increment `app.state.agent_counts["compromised"]`.
- `create_quarantine_rule`: for agent scope, increment `app.state.agent_counts["quarantined"]`. For swarm scope, set to total agent count.
- `delete_quarantine_rule`: counter is corrected by background task (too complex to accurately decrement here since multiple rules can overlap).
- `create_killswitch_rule`: same pattern as quarantine.
- `delete_killswitch_rule`: same — let background task correct.

- [ ] **Step 4: Run tests**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_app.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git -c commit.gpgsign=false add aegis-monitor/monitor/app.py
git -c commit.gpgsign=false commit -m "perf(monitor): cache metrics endpoint, remove dead query, use agent counters"
```

---

## Chunk 4: Cache warming + invalidate_all in tests + final verification

### Task 8: Add cache warming on startup

**Files:**
- Modify: `aegis-monitor/monitor/app.py`

- [ ] **Step 1: Add cache warming helper and call in lifespan**

Add a helper function that pre-populates all three cache keys. Call it at the end of `lifespan`, after graph rebuild and before `yield`:

```python
async def _warm_cache(app_state) -> None:
    """Pre-populate response cache to avoid first-request latency spike."""
    # threat-intel
    graph_state = app_state.graph.get_graph_state()
    compromised_agents = [n["id"] for n in graph_state["nodes"] if n["is_compromised"]]
    quarantined_agents = [n["id"] for n in graph_state["nodes"] if n["is_quarantined"]]
    compromised_hashes = [
        f"{h:032x}" for h in app_state.contagion_detector._compromised.values()
    ]
    ti_result = {
        "compromised_agents": compromised_agents,
        "compromised_hashes": compromised_hashes,
        "quarantined_agents": quarantined_agents,
        "generated_at": time.time(),
    }
    await app_state.cache.set("threat-intel", json.dumps(ti_result).encode())
```

Note: `"graph"` and `"metrics"` will be populated on first request (startup has zero agents typically). Only `"threat-intel"` benefits from warming since agents poll it immediately.

- [ ] **Step 2: Add `invalidate_all` to test fixture**

In `tests/test_app.py`, inside the `client` fixture, after `yield c`, add cache cleanup:

```python
# Inside the client fixture, after the existing setup:
if hasattr(app.state, 'cache'):
    import asyncio
    asyncio.get_event_loop().run_until_complete(app.state.cache.invalidate_all())
```

Alternatively, add `invalidate_all` at the START of the fixture so each test gets a fresh cache. The simplest approach: after `app.state.config.api_keys = []`, add:

```python
if hasattr(app.state, 'cache'):
    import asyncio
    loop = asyncio.new_event_loop()
    loop.run_until_complete(app.state.cache.invalidate_all())
    loop.close()
```

- [ ] **Step 3: Run full test suite**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/ -v --ignore=tests/test_simulator`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git -c commit.gpgsign=false add aegis-monitor/monitor/app.py aegis-monitor/tests/test_app.py
git -c commit.gpgsign=false commit -m "perf(monitor): add cache warming on startup, clear cache between tests"
```

---

### Task 9: Final verification — lint + full test suite

**Files:**
- All modified files

- [ ] **Step 1: Run linter**

Run: `cd /workspace/aegis-monitor && python -m ruff check monitor/ tests/test_cache.py tests/test_async_db.py tests/test_transactions.py tests/test_app.py tests/test_epidemiology.py`
Expected: No errors (or only pre-existing ones in files we didn't touch)

- [ ] **Step 2: Fix any lint issues**

- [ ] **Step 3: Run full test suite**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/ -v --ignore=tests/test_simulator`
Expected: All tests PASS

- [ ] **Step 4: Commit any fixes**

```bash
git -c commit.gpgsign=false add -A
git -c commit.gpgsign=false commit -m "chore(monitor): lint fixes for cache integration"
```
