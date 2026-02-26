"""SQLite backend for AEGIS monitor.

Uses stdlib ``sqlite3`` with WAL journaling.  Thread safety is handled via
per-thread connections (or a single shared connection for ``:memory:``).
"""

from __future__ import annotations

import sqlite3
import threading
from typing import Any

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
    timestamp            REAL NOT NULL
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


class SqliteBackend:
    """SQLite implementation of the database backend."""

    def __init__(self, path: str = "monitor.db") -> None:
        self._path = path
        self._is_memory = path == ":memory:"
        self._local = threading.local()
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
            conn = sqlite3.connect(self._path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    def init_schema(self) -> None:
        conn = self._get_conn()
        conn.executescript(_SCHEMA)
        conn.commit()

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        conn = self._get_conn()
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.rowcount

    def fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        conn = self._get_conn()
        row = conn.execute(sql, params).fetchone()
        if row is None:
            return None
        return dict(row)

    def fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        conn = self._get_conn()
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        if self._shared_conn:
            self._shared_conn.close()
