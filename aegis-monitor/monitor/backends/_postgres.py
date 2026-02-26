"""Postgres backend for AEGIS monitor.

Requires ``psycopg[binary]>=3.1`` and ``psycopg-pool>=3.1``.
These are optional dependencies — install with ``pip install aegis-monitor[postgres]``.
"""

from __future__ import annotations

from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

_SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS agents (
        agent_id        TEXT PRIMARY KEY,
        operator_id     TEXT NOT NULL DEFAULT '',
        trust_tier      INTEGER NOT NULL DEFAULT 0,
        trust_score     DOUBLE PRECISION NOT NULL DEFAULT 0.0,
        is_compromised  BOOLEAN NOT NULL DEFAULT FALSE,
        is_quarantined  BOOLEAN NOT NULL DEFAULT FALSE,
        is_killswitched BOOLEAN NOT NULL DEFAULT FALSE,
        last_heartbeat  DOUBLE PRECISION NOT NULL DEFAULT 0,
        metadata        TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS edges (
        source_agent_id TEXT NOT NULL,
        target_agent_id TEXT NOT NULL,
        direction       TEXT NOT NULL DEFAULT 'outbound',
        last_seen       DOUBLE PRECISION NOT NULL DEFAULT 0,
        message_count   INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (source_agent_id, target_agent_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        event_id    TEXT PRIMARY KEY,
        event_type  TEXT NOT NULL,
        agent_id    TEXT NOT NULL,
        operator_id TEXT NOT NULL DEFAULT '',
        timestamp   DOUBLE PRECISION NOT NULL,
        payload     TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS compromises (
        record_id            TEXT PRIMARY KEY,
        reporter_agent_id    TEXT NOT NULL,
        compromised_agent_id TEXT NOT NULL,
        source               TEXT NOT NULL DEFAULT '',
        nk_score             DOUBLE PRECISION NOT NULL DEFAULT 0.0,
        nk_verdict           TEXT NOT NULL DEFAULT '',
        recommended_action   TEXT NOT NULL DEFAULT 'quarantine',
        content_hash_hex     TEXT NOT NULL DEFAULT '',
        timestamp            DOUBLE PRECISION NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)",
    "CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_compromises_compromised ON compromises(compromised_agent_id)",
    "CREATE INDEX IF NOT EXISTS idx_compromises_ts ON compromises(timestamp)",
    """
    CREATE TABLE IF NOT EXISTS killswitch_rules (
        rule_id    TEXT PRIMARY KEY,
        scope      TEXT NOT NULL DEFAULT 'agent',
        target     TEXT NOT NULL DEFAULT '',
        blocked    BOOLEAN NOT NULL DEFAULT TRUE,
        reason     TEXT NOT NULL DEFAULT '',
        created_at DOUBLE PRECISION NOT NULL,
        created_by TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ks_scope ON killswitch_rules(scope)",
    """
    CREATE TABLE IF NOT EXISTS quarantine_rules (
        rule_id     TEXT PRIMARY KEY,
        scope       TEXT NOT NULL DEFAULT 'agent',
        target      TEXT NOT NULL DEFAULT '',
        quarantined BOOLEAN NOT NULL DEFAULT TRUE,
        reason      TEXT NOT NULL DEFAULT '',
        severity    TEXT NOT NULL DEFAULT 'low',
        created_at  DOUBLE PRECISION NOT NULL,
        created_by  TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_qr_scope ON quarantine_rules(scope)",
]


class PostgresBackend:
    """Postgres implementation of the database backend.

    Uses ``psycopg`` v3 with ``psycopg_pool.ConnectionPool`` for thread safety.
    """

    def __init__(self, conninfo: str) -> None:
        self._pool = ConnectionPool(
            conninfo=conninfo,
            min_size=2,
            max_size=10,
            kwargs={"row_factory": dict_row},
        )

    def init_schema(self) -> None:
        with self._pool.connection() as conn:
            for stmt in _SCHEMA_STATEMENTS:
                conn.execute(stmt)
            conn.commit()

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        sql = self._translate(sql)
        with self._pool.connection() as conn:
            cur = conn.execute(sql, params)
            conn.commit()
            return cur.rowcount

    def fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        sql = self._translate(sql)
        with self._pool.connection() as conn:
            cur = conn.execute(sql, params)
            return cur.fetchone()

    def fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        sql = self._translate(sql)
        with self._pool.connection() as conn:
            cur = conn.execute(sql, params)
            return cur.fetchall()

    def close(self) -> None:
        self._pool.close()

    @staticmethod
    def _translate(sql: str) -> str:
        """Convert SQLite-style ``?`` placeholders to Postgres ``%s``."""
        return sql.replace("?", "%s")
