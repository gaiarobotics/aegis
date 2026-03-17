# Monitor Async DB + Transactions Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Unblock the FastAPI event loop by offloading DB I/O to threads, add transaction support for atomic multi-step operations, and move expensive reclustering off the heartbeat hot path.

**Architecture:** Add a `transaction()` context manager to both database backends that defers commits until exit and rolls back on exception. Wrap all DB calls in `app.py` handlers with `asyncio.to_thread()`, batching multi-step operations into single threaded transaction calls. Replace per-heartbeat topic reclustering with a periodic background task.

**Tech Stack:** Python asyncio, FastAPI, SQLite (WAL), psycopg3 connection pool

---

### Task 1: Add transaction context manager to SQLite backend

**Files:**
- Modify: `aegis-monitor/monitor/backends/_sqlite.py`
- Test: `aegis-monitor/tests/test_transactions.py`

**Step 1: Write the failing test**

Create `aegis-monitor/tests/test_transactions.py`:

```python
"""Tests for backend transaction support."""

import pytest
from monitor.backends._sqlite import SqliteBackend


@pytest.fixture
def backend():
    b = SqliteBackend(":memory:")
    b.init_schema()
    return b


class TestSqliteTransaction:
    def test_transaction_commits_on_success(self, backend):
        with backend.transaction() as tx:
            tx.execute(
                "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?)",
                ("tx-agent", "op", 0, "{}"),
            )
        row = backend.fetchone("SELECT * FROM agents WHERE agent_id = ?", ("tx-agent",))
        assert row is not None
        assert row["agent_id"] == "tx-agent"

    def test_transaction_rolls_back_on_exception(self, backend):
        with pytest.raises(ValueError):
            with backend.transaction() as tx:
                tx.execute(
                    "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
                    "VALUES (?, ?, ?, ?)",
                    ("doomed-agent", "op", 0, "{}"),
                )
                raise ValueError("boom")
        row = backend.fetchone("SELECT * FROM agents WHERE agent_id = ?", ("doomed-agent",))
        assert row is None

    def test_transaction_batches_multiple_writes(self, backend):
        with backend.transaction() as tx:
            tx.execute(
                "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?)",
                ("batch-1", "op", 0, "{}"),
            )
            tx.execute(
                "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?)",
                ("batch-2", "op", 0, "{}"),
            )
        rows = backend.fetchall("SELECT * FROM agents WHERE agent_id LIKE 'batch-%'")
        assert len(rows) == 2

    def test_transaction_fetchone(self, backend):
        backend.execute(
            "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
            "VALUES (?, ?, ?, ?)",
            ("existing", "op", 0, "{}"),
        )
        with backend.transaction() as tx:
            row = tx.fetchone("SELECT * FROM agents WHERE agent_id = ?", ("existing",))
        assert row is not None

    def test_transaction_fetchall(self, backend):
        backend.execute(
            "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
            "VALUES (?, ?, ?, ?)",
            ("a1", "op", 0, "{}"),
        )
        with backend.transaction() as tx:
            rows = tx.fetchall("SELECT * FROM agents")
        assert len(rows) >= 1
```

**Step 2: Run test to verify it fails**

Run: `cd aegis-monitor && python -m pytest tests/test_transactions.py -v`
Expected: FAIL — `SqliteBackend` has no `transaction` method

**Step 3: Implement transaction context manager on SqliteBackend**

In `aegis-monitor/monitor/backends/_sqlite.py`, add after the `SqliteBackend` class definition:

```python
from contextlib import contextmanager

# Inside SqliteBackend class:

@contextmanager
def transaction(self):
    """Yield a transaction handle that batches writes into one commit.

    Rolls back on exception, commits on clean exit.
    """
    conn = self._get_conn()
    conn.execute("BEGIN")
    tx = _SqliteTransaction(conn)
    try:
        yield tx
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


class _SqliteTransaction:
    """Handle returned by ``SqliteBackend.transaction()``."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=()):
        cur = self._conn.execute(sql, params)
        return cur.rowcount

    def fetchone(self, sql, params=()):
        row = self._conn.execute(sql, params).fetchone()
        return dict(row) if row is not None else None

    def fetchall(self, sql, params=()):
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
```

**Step 4: Run test to verify it passes**

Run: `cd aegis-monitor && python -m pytest tests/test_transactions.py -v`
Expected: All 5 tests PASS

**Step 5: Commit**

```bash
git add aegis-monitor/monitor/backends/_sqlite.py aegis-monitor/tests/test_transactions.py
git commit -m "feat(monitor): add transaction context manager to SQLite backend"
```

---

### Task 2: Add transaction context manager to Postgres backend

**Files:**
- Modify: `aegis-monitor/monitor/backends/_postgres.py`
- Modify: `aegis-monitor/tests/test_transactions.py`

**Step 1: Write the failing test**

Append to `aegis-monitor/tests/test_transactions.py`:

```python
import os

@pytest.fixture
def pg_backend():
    url = os.environ.get("TEST_POSTGRES_URL")
    if not url:
        pytest.skip("TEST_POSTGRES_URL not set")
    from monitor.backends._postgres import PostgresBackend
    b = PostgresBackend(url)
    b.init_schema()
    return b


@pytest.mark.postgres
class TestPostgresTransaction:
    def test_transaction_commits_on_success(self, pg_backend):
        with pg_backend.transaction() as tx:
            tx.execute(
                "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
                "VALUES (%s, %s, %s, %s)",
                ("pg-tx-agent", "op", 0, "{}"),
            )
        row = pg_backend.fetchone("SELECT * FROM agents WHERE agent_id = %s", ("pg-tx-agent",))
        assert row is not None

    def test_transaction_rolls_back_on_exception(self, pg_backend):
        with pytest.raises(ValueError):
            with pg_backend.transaction() as tx:
                tx.execute(
                    "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
                    "VALUES (%s, %s, %s, %s)",
                    ("pg-doomed", "op", 0, "{}"),
                )
                raise ValueError("boom")
        row = pg_backend.fetchone("SELECT * FROM agents WHERE agent_id = %s", ("pg-doomed",))
        assert row is None
```

**Step 2: Run SQLite tests to verify nothing broke**

Run: `cd aegis-monitor && python -m pytest tests/test_transactions.py -v -k "not postgres"`
Expected: All SQLite tests PASS, Postgres tests skipped

**Step 3: Implement transaction on PostgresBackend**

In `aegis-monitor/monitor/backends/_postgres.py`, add:

```python
from contextlib import contextmanager

# Inside PostgresBackend class:

@contextmanager
def transaction(self):
    """Yield a transaction handle. Commits on clean exit, rolls back on exception."""
    with self._pool.connection() as conn:
        tx = _PgTransaction(conn, self._translate)
        try:
            yield tx
            conn.commit()
        except BaseException:
            conn.rollback()
            raise


class _PgTransaction:
    """Handle returned by ``PostgresBackend.transaction()``."""

    def __init__(self, conn, translate):
        self._conn = conn
        self._translate = translate

    def execute(self, sql, params=()):
        sql = self._translate(sql)
        cur = self._conn.execute(sql, params)
        return cur.rowcount

    def fetchone(self, sql, params=()):
        sql = self._translate(sql)
        cur = self._conn.execute(sql, params)
        return cur.fetchone()

    def fetchall(self, sql, params=()):
        sql = self._translate(sql)
        cur = self._conn.execute(sql, params)
        return cur.fetchall()
```

**Step 4: Run all transaction tests**

Run: `cd aegis-monitor && python -m pytest tests/test_transactions.py -v`
Expected: SQLite tests PASS, Postgres tests skipped (no TEST_POSTGRES_URL)

**Step 5: Commit**

```bash
git add aegis-monitor/monitor/backends/_postgres.py aegis-monitor/tests/test_transactions.py
git commit -m "feat(monitor): add transaction context manager to Postgres backend"
```

---

### Task 3: Add transaction method to Database facade

**Files:**
- Modify: `aegis-monitor/monitor/db.py`
- Modify: `aegis-monitor/monitor/backends/_base.py`
- Modify: `aegis-monitor/tests/test_transactions.py`

**Step 1: Write the failing test**

Append to `aegis-monitor/tests/test_transactions.py`:

```python
from monitor.db import Database


class TestDatabaseTransaction:
    def test_facade_transaction_commits(self):
        db = Database(":memory:")
        with db.transaction() as tx:
            tx.execute(
                "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?)",
                ("facade-agent", "op", 0, "{}"),
            )
        agent = db.get_agent("facade-agent")
        assert agent is not None

    def test_facade_transaction_rolls_back(self):
        db = Database(":memory:")
        with pytest.raises(RuntimeError):
            with db.transaction() as tx:
                tx.execute(
                    "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
                    "VALUES (?, ?, ?, ?)",
                    ("doomed", "op", 0, "{}"),
                )
                raise RuntimeError("fail")
        agent = db.get_agent("doomed")
        assert agent is None
```

**Step 2: Run test to verify it fails**

Run: `cd aegis-monitor && python -m pytest tests/test_transactions.py::TestDatabaseTransaction -v`
Expected: FAIL — `Database` has no `transaction` method

**Step 3: Add transaction to Database facade and base protocol**

In `aegis-monitor/monitor/backends/_base.py`, add the `transaction` method to the protocol:

```python
from contextlib import contextmanager
from typing import Any, Generator, Protocol

class DatabaseBackend(Protocol):
    # ... existing methods ...

    def transaction(self) -> Any:
        """Return a context manager that batches writes into one commit."""
        ...
```

In `aegis-monitor/monitor/db.py`, add:

```python
def transaction(self):
    """Return a context manager for atomic multi-statement operations."""
    return self._backend.transaction()
```

**Step 4: Run test to verify it passes**

Run: `cd aegis-monitor && python -m pytest tests/test_transactions.py -v`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add aegis-monitor/monitor/db.py aegis-monitor/monitor/backends/_base.py aegis-monitor/tests/test_transactions.py
git commit -m "feat(monitor): expose transaction() on Database facade and backend protocol"
```

---

### Task 4: Add async DB helper functions

**Files:**
- Create: `aegis-monitor/monitor/async_db.py`
- Test: `aegis-monitor/tests/test_async_db.py`

**Step 1: Write the failing test**

Create `aegis-monitor/tests/test_async_db.py`:

```python
"""Tests for async database helpers."""

import pytest
from monitor.db import Database
from monitor.async_db import run_db, run_in_transaction


@pytest.fixture
def db():
    return Database(":memory:")


@pytest.mark.asyncio
class TestRunDb:
    async def test_run_db_offloads_to_thread(self, db):
        db.upsert_agent(
            __import__("monitor.models", fromlist=["AgentNode"]).AgentNode(
                agent_id="async-1", last_heartbeat=0,
            )
        )
        agent = await run_db(db.get_agent, "async-1")
        assert agent is not None
        assert agent.agent_id == "async-1"

    async def test_run_db_returns_none(self, db):
        agent = await run_db(db.get_agent, "nonexistent")
        assert agent is None


@pytest.mark.asyncio
class TestRunInTransaction:
    async def test_transaction_commits(self, db):
        def do_writes(tx):
            tx.execute(
                "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?)",
                ("tx-async-1", "op", 0, "{}"),
            )
            tx.execute(
                "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?)",
                ("tx-async-2", "op", 0, "{}"),
            )

        await run_in_transaction(db, do_writes)
        a1 = db.get_agent("tx-async-1")
        a2 = db.get_agent("tx-async-2")
        assert a1 is not None
        assert a2 is not None

    async def test_transaction_rolls_back(self, db):
        def do_writes(tx):
            tx.execute(
                "INSERT INTO agents (agent_id, operator_id, last_heartbeat, metadata) "
                "VALUES (?, ?, ?, ?)",
                ("tx-doomed", "op", 0, "{}"),
            )
            raise ValueError("boom")

        with pytest.raises(ValueError):
            await run_in_transaction(db, do_writes)
        agent = db.get_agent("tx-doomed")
        assert agent is None
```

**Step 2: Run test to verify it fails**

Run: `cd aegis-monitor && python -m pytest tests/test_async_db.py -v`
Expected: FAIL — `monitor.async_db` does not exist

**Step 3: Implement async_db helpers**

Create `aegis-monitor/monitor/async_db.py`:

```python
"""Async wrappers for the synchronous Database layer.

Uses ``asyncio.to_thread()`` to run blocking DB calls in the default
thread pool, keeping the FastAPI event loop unblocked.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, TypeVar

from monitor.db import Database

T = TypeVar("T")


async def run_db(fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run a synchronous Database method in a thread."""
    return await asyncio.to_thread(fn, *args, **kwargs)


async def run_in_transaction(db: Database, fn: Callable[..., T]) -> T:
    """Run *fn(tx)* inside a database transaction in a thread.

    ``fn`` receives a transaction handle with ``execute``, ``fetchone``,
    and ``fetchall`` methods.  The transaction commits on clean return
    and rolls back on exception.
    """

    def _run() -> T:
        with db.transaction() as tx:
            return fn(tx)

    return await asyncio.to_thread(_run)
```

**Step 4: Install pytest-asyncio and run tests**

Run: `cd aegis-monitor && pip install pytest-asyncio -q && python -m pytest tests/test_async_db.py -v`
Expected: All 4 tests PASS

**Step 5: Commit**

```bash
git add aegis-monitor/monitor/async_db.py aegis-monitor/tests/test_async_db.py
git commit -m "feat(monitor): add async DB helpers using asyncio.to_thread"
```

---

### Task 5: Convert heartbeat handler to async DB

**Files:**
- Modify: `aegis-monitor/monitor/app.py`

**Step 1: Identify the heartbeat DB calls**

In `receive_heartbeat`, the DB calls are:
1. `db.upsert_agent(...)` — single write
2. `db.upsert_edge(...)` — N writes in a loop
3. `db.insert_event(...)` — conditional write (contagion alert)
4. `db.insert_quarantine_rule(...)` — conditional write
5. `db.set_agent_quarantined(...)` — conditional write

**Step 2: Batch heartbeat DB writes into a transaction**

Refactor `receive_heartbeat` in `aegis-monitor/monitor/app.py`. Add import at top:

```python
from monitor.async_db import run_db, run_in_transaction
```

Replace the DB writes in `receive_heartbeat` with:

```python
# Batch all heartbeat DB writes into one transaction
def _heartbeat_db_writes(tx):
    tx.execute(
        """INSERT INTO agents
               (agent_id, operator_id, trust_tier, trust_score,
                is_compromised, is_quarantined, is_killswitched,
                last_heartbeat, metadata)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(agent_id) DO UPDATE SET
               operator_id     = excluded.operator_id,
               trust_tier      = excluded.trust_tier,
               trust_score     = excluded.trust_score,
               is_compromised  = excluded.is_compromised,
               is_quarantined  = excluded.is_quarantined,
               is_killswitched = excluded.is_killswitched,
               last_heartbeat  = excluded.last_heartbeat,
               metadata        = excluded.metadata
        """,
        (agent_id, data.get("operator_id", ""),
         data.get("trust_tier", 0), data.get("trust_score", 0.0),
         0, int(data.get("is_quarantined", False)), 0,
         time.time(), json.dumps(metadata)),
    )
    for edge in edges:
        target = edge.get("target_agent_id", "")
        if not target:
            continue
        tx.execute(
            """INSERT INTO edges
                   (source_agent_id, target_agent_id, direction, last_seen, message_count)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(source_agent_id, target_agent_id) DO UPDATE SET
                   direction     = excluded.direction,
                   last_seen     = excluded.last_seen,
                   message_count = excluded.message_count
            """,
            (agent_id, target, edge.get("direction", "outbound"),
             edge.get("last_seen", time.time()), edge.get("message_count", 0)),
        )

await run_in_transaction(db, _heartbeat_db_writes)
```

Remove the old individual `db.upsert_agent()` and `db.upsert_edge()` calls.

For the conditional contagion alert writes later in the handler, wrap them similarly:

```python
if score >= contagion_detector._alert_threshold:
    def _contagion_db_writes(tx):
        tx.execute(
            """INSERT INTO events (event_id, event_type, agent_id, operator_id, timestamp, payload)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(event_id) DO UPDATE SET ...""",
            (event_id, "contagion_alert", agent_id, ...),
        )
        tx.execute(
            """INSERT INTO quarantine_rules (rule_id, scope, target, quarantined, reason, severity, created_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(rule_id) DO UPDATE SET ...""",
            (...),
        )
        tx.execute(
            "UPDATE agents SET is_quarantined = ? WHERE agent_id = ?",
            (1, agent_id),
        )
    await run_in_transaction(db, _contagion_db_writes)
```

**Step 3: Run existing tests to verify nothing broke**

Run: `cd aegis-monitor && python -m pytest tests/test_app.py -v`
Expected: All tests PASS

**Step 4: Commit**

```bash
git add aegis-monitor/monitor/app.py
git commit -m "perf(monitor): offload heartbeat DB writes to thread pool with transaction"
```

---

### Task 6: Convert compromise handler to async DB

**Files:**
- Modify: `aegis-monitor/monitor/app.py`

**Step 1: Batch compromise DB writes**

In `receive_compromise`, batch the three writes (`insert_compromise`, `upsert_agent`, `insert_event`) and the conditional quarantine writes into transactions:

```python
def _compromise_db_writes(tx):
    # Insert compromise record
    tx.execute(
        """INSERT INTO compromises
               (record_id, reporter_agent_id, compromised_agent_id,
                source, nk_score, nk_verdict, recommended_action,
                content_hash_hex, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(record_id) DO UPDATE SET ...""",
        (...),
    )
    # Mark agent compromised
    tx.execute(
        """INSERT INTO agents (agent_id, ...) VALUES (?, ...)
           ON CONFLICT(agent_id) DO UPDATE SET
               is_compromised = 1, trust_tier = 0, trust_score = 0.0, ...""",
        (...),
    )
    # Store event
    tx.execute(
        """INSERT INTO events (...) VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(event_id) DO UPDATE SET ...""",
        (...),
    )
    # Read reporter info for validation
    return tx.fetchone(
        "SELECT * FROM agents WHERE agent_id = ?",
        (record.reporter_agent_id,),
    )

reporter_row = await run_in_transaction(db, _compromise_db_writes)
```

**Step 2: Convert remaining reads to async**

Wrap `db.get_agent()` calls that happen outside the transaction with `run_db`:

```python
reporter_node = await run_db(db.get_agent, record.reporter_agent_id)
```

**Step 3: Run tests**

Run: `cd aegis-monitor && python -m pytest tests/test_app.py -v`
Expected: All tests PASS

**Step 4: Commit**

```bash
git add aegis-monitor/monitor/app.py
git commit -m "perf(monitor): offload compromise DB writes to thread pool with transaction"
```

---

### Task 7: Convert remaining handlers to async DB

**Files:**
- Modify: `aegis-monitor/monitor/app.py`

**Step 1: Convert these handlers**

- `receive_trust` — single `insert_event` + `upsert_agent`
- `receive_threat` — single `insert_event`
- `get_metrics` — reads (`get_events`)
- `get_trust` — read (`get_agent`)
- `killswitch_status` — read (`check_killswitch`)
- `create_killswitch_rule` — write + `get_all_agents` loop
- `delete_killswitch_rule` — write + `get_all_agents` loop
- `quarantine_status` — read (`check_quarantine`)
- `create_quarantine_rule` — write + `get_all_agents` loop
- `delete_quarantine_rule` — write + `get_all_agents` loop

Pattern for simple writes:
```python
await run_db(db.insert_event, event)
```

Pattern for reads:
```python
agent = await run_db(db.get_agent, agent_id)
```

Pattern for rule creation with `get_all_agents` loop (batch into transaction):
```python
def _apply_swarm_killswitch(tx):
    tx.execute("INSERT INTO killswitch_rules (...) VALUES (...)", (...))
    rows = tx.fetchall("SELECT agent_id FROM agents")
    for row in rows:
        tx.execute("UPDATE agents SET is_killswitched = 1 WHERE agent_id = ?", (row["agent_id"],))

await run_in_transaction(db, _apply_swarm_killswitch)
```

**Step 2: Run full test suite**

Run: `cd aegis-monitor && python -m pytest tests/ -v --ignore=tests/test_simulator`
Expected: All tests PASS

**Step 3: Commit**

```bash
git add aegis-monitor/monitor/app.py
git commit -m "perf(monitor): convert all remaining handlers to async DB calls"
```

---

### Task 8: Move topic reclustering to background task

**Files:**
- Modify: `aegis-monitor/monitor/app.py`

**Step 1: Add background reclustering task to lifespan**

In the `lifespan` function, start a background task that runs `update_stable_clusters` periodically:

```python
async def _periodic_recluster(app_state, interval: float = 30.0):
    """Run topic reclustering periodically instead of per-heartbeat."""
    while True:
        await asyncio.sleep(interval)
        try:
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
        except Exception:
            logging.getLogger(__name__).debug("Recluster failed", exc_info=True)
```

In `lifespan`, before `yield`:

```python
recluster_task = asyncio.create_task(_periodic_recluster(app.state))
```

After `yield`:

```python
recluster_task.cancel()
```

**Step 2: Remove reclustering from heartbeat handler**

In `receive_heartbeat`, remove the block that calls `topic_clusterer.update_stable_clusters()` and the associated `_broadcast` for `topic_clusters_updated`. Keep only:

```python
if hash_for_analysis:
    topic_clusterer.update(agent_id, hash_for_analysis)
```

And the contagion detection (`contagion_detector.check_with_velocity()`).

**Step 3: Run full test suite**

Run: `cd aegis-monitor && python -m pytest tests/ -v`
Expected: All tests PASS

**Step 4: Commit**

```bash
git add aegis-monitor/monitor/app.py
git commit -m "perf(monitor): move topic reclustering to 30s background task"
```

---

### Task 9: Add pytest-asyncio dependency and run full suite

**Files:**
- Modify: `aegis-monitor/pyproject.toml`

**Step 1: Add pytest-asyncio to dev dependencies**

In `aegis-monitor/pyproject.toml`, add `pytest-asyncio>=0.23` to the dev extras.

**Step 2: Run full test suite**

Run: `cd aegis-monitor && python -m pytest tests/ -v`
Expected: All tests PASS

**Step 3: Run linter**

Run: `cd aegis-monitor && python -m ruff check monitor/ tests/`
Expected: No errors

**Step 4: Commit**

```bash
git add aegis-monitor/pyproject.toml
git commit -m "chore(monitor): add pytest-asyncio to dev dependencies"
```
