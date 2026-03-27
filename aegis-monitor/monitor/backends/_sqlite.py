"""SQLite backend for AEGIS monitor.

Uses stdlib ``sqlite3`` with WAL journaling.  Thread safety is handled via
per-thread connections (or a single shared connection for ``:memory:``).
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterator

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id       TEXT PRIMARY KEY,
    operator_id    TEXT NOT NULL DEFAULT '',
    trust_tier     INTEGER NOT NULL DEFAULT 0,
    trust_score    REAL NOT NULL DEFAULT 0.0,
    is_compromised INTEGER NOT NULL DEFAULT 0,
    is_quarantined  INTEGER NOT NULL DEFAULT 0,
    is_killswitched INTEGER NOT NULL DEFAULT 0,
    last_heartbeat  REAL NOT NULL DEFAULT 0,
    metadata        TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS edges (
    source_agent_id TEXT NOT NULL,
    target_agent_id TEXT NOT NULL,
    direction       TEXT NOT NULL DEFAULT 'outbound',
    last_seen       REAL NOT NULL DEFAULT 0,
    message_count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (source_agent_id, target_agent_id)
);

CREATE TABLE IF NOT EXISTS events (
    event_id    TEXT PRIMARY KEY,
    event_type  TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    operator_id TEXT NOT NULL DEFAULT '',
    timestamp   REAL NOT NULL,
    payload     TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS compromises (
    record_id            TEXT PRIMARY KEY,
    reporter_agent_id    TEXT NOT NULL,
    compromised_agent_id TEXT NOT NULL,
    source               TEXT NOT NULL DEFAULT '',
    nk_score             REAL NOT NULL DEFAULT 0.0,
    nk_verdict           TEXT NOT NULL DEFAULT '',
    recommended_action   TEXT NOT NULL DEFAULT 'quarantine',
    content_hash_hex     TEXT NOT NULL DEFAULT '',
    embedding_model      TEXT NOT NULL DEFAULT '',
    timestamp            REAL NOT NULL,
    verified             INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_compromises_compromised ON compromises(compromised_agent_id);
CREATE INDEX IF NOT EXISTS idx_compromises_ts ON compromises(timestamp);

CREATE TABLE IF NOT EXISTS killswitch_rules (
    rule_id    TEXT PRIMARY KEY,
    scope      TEXT NOT NULL DEFAULT 'agent',
    target     TEXT NOT NULL DEFAULT '',
    blocked    INTEGER NOT NULL DEFAULT 1,
    reason     TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    created_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ks_scope ON killswitch_rules(scope);

CREATE TABLE IF NOT EXISTS quarantine_rules (
    rule_id    TEXT PRIMARY KEY,
    scope      TEXT NOT NULL DEFAULT 'agent',
    target     TEXT NOT NULL DEFAULT '',
    quarantined INTEGER NOT NULL DEFAULT 1,
    reason     TEXT NOT NULL DEFAULT '',
    severity   TEXT NOT NULL DEFAULT 'low',
    created_at REAL NOT NULL,
    created_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_qr_scope ON quarantine_rules(scope);
"""


class _SqliteTransaction:
    """Handle returned by ``SqliteBackend.transaction()``."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        cur = self._conn.execute(sql, params)
        return cur.rowcount

    def fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        row = self._conn.execute(sql, params).fetchone()
        if row is None:
            return None
        return dict(row)

    def fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


class SqliteBackend:
    """SQLite implementation of the database backend."""

    def __init__(self, path: str = "monitor.db") -> None:
        self._path = path
        self._is_memory = path == ":memory:"
        self._local = threading.local()
        self._lock = threading.Lock()  # serialises access for :memory:
        self._shared_conn: sqlite3.Connection | None = None
        if self._is_memory:
            self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row

    def _get_conn(self) -> sqlite3.Connection:
        """Return a per-thread connection (or shared for :memory:)."""
        if self._shared_conn is not None:
            return self._shared_conn
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path, timeout=5, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return conn

    def init_schema(self) -> None:
        conn = self._get_conn()
        conn.executescript(_SCHEMA)
        # Migrate: add verified column if missing (existing databases)
        try:
            conn.execute("ALTER TABLE compromises ADD COLUMN verified INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # Column already exists
        try:
            conn.execute("ALTER TABLE compromises ADD COLUMN embedding_model TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # Column already exists
        conn.commit()

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        conn = self._get_conn()
        with self._lock:
            cur = conn.execute(sql, params)
            conn.commit()
            return cur.rowcount

    def fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        conn = self._get_conn()
        with self._lock:
            row = conn.execute(sql, params).fetchone()
        if row is None:
            return None
        return dict(row)

    def fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        conn = self._get_conn()
        with self._lock:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    @contextmanager
    def transaction(self) -> Iterator[_SqliteTransaction]:
        """Yield a transaction handle that batches writes.

        Commits on clean exit, rolls back on exception.  The lock is
        held for the entire transaction to prevent interleaving on the
        shared ``:memory:`` connection.  For file-backed databases
        (per-thread connections) the lock is uncontended.
        """
        conn = self._get_conn()
        self._lock.acquire()
        try:
            conn.execute("BEGIN")
            txn = _SqliteTransaction(conn)
            try:
                yield txn
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
        finally:
            self._lock.release()

    def close(self) -> None:
        if self._shared_conn:
            self._shared_conn.close()
