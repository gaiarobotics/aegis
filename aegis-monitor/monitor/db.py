"""SQLite database layer for AEGIS monitor.

Uses stdlib ``sqlite3`` — no ORM.  Schema is auto-created on startup.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

from monitor.models import AgentEdge, AgentNode, CompromiseRecord, KillswitchRule, QuarantineRule, StoredEvent

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


class Database:
    """Thread-safe SQLite wrapper with auto-schema creation."""

    def __init__(self, path: str = "monitor.db") -> None:
        self._path = path
        self._is_memory = path == ":memory:"
        self._local = threading.local()
        # For :memory: databases, share a single connection across threads
        # so all callers see the same schema and data.
        self._shared_conn: sqlite3.Connection | None = None
        if self._is_memory:
            self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row
        self._init_schema()

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

    def _init_schema(self) -> None:
        conn = self._get_conn()
        conn.executescript(_SCHEMA)
        conn.commit()

    # ---- Agents ----

    def upsert_agent(self, node: AgentNode) -> None:
        conn = self._get_conn()
        conn.execute(
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
            (
                node.agent_id,
                node.operator_id,
                node.trust_tier,
                node.trust_score,
                int(node.is_compromised),
                int(node.is_quarantined),
                int(node.is_killswitched),
                node.last_heartbeat,
                json.dumps(node.metadata),
            ),
        )
        conn.commit()

    def get_agent(self, agent_id: str) -> AgentNode | None:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_agent(row)

    def get_all_agents(self) -> list[AgentNode]:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM agents").fetchall()
        return [self._row_to_agent(r) for r in rows]

    @staticmethod
    def _row_to_agent(row: sqlite3.Row) -> AgentNode:
        return AgentNode(
            agent_id=row["agent_id"],
            operator_id=row["operator_id"],
            trust_tier=row["trust_tier"],
            trust_score=row["trust_score"],
            is_compromised=bool(row["is_compromised"]),
            is_quarantined=bool(row["is_quarantined"]),
            is_killswitched=bool(row["is_killswitched"]),
            last_heartbeat=row["last_heartbeat"],
            metadata=json.loads(row["metadata"]),
        )

    # ---- Edges ----

    def upsert_edge(self, edge: AgentEdge) -> None:
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO edges
                   (source_agent_id, target_agent_id, direction, last_seen, message_count)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(source_agent_id, target_agent_id) DO UPDATE SET
                   direction     = excluded.direction,
                   last_seen     = excluded.last_seen,
                   message_count = excluded.message_count
            """,
            (
                edge.source_agent_id,
                edge.target_agent_id,
                edge.direction,
                edge.last_seen,
                edge.message_count,
            ),
        )
        conn.commit()

    def get_all_edges(self) -> list[AgentEdge]:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM edges").fetchall()
        return [
            AgentEdge(
                source_agent_id=r["source_agent_id"],
                target_agent_id=r["target_agent_id"],
                direction=r["direction"],
                last_seen=r["last_seen"],
                message_count=r["message_count"],
            )
            for r in rows
        ]

    # ---- Events ----

    def insert_event(self, event: StoredEvent) -> None:
        conn = self._get_conn()
        conn.execute(
            """INSERT OR REPLACE INTO events
                   (event_id, event_type, agent_id, operator_id, timestamp, payload)
               VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.event_type,
                event.agent_id,
                event.operator_id,
                event.timestamp,
                json.dumps(event.payload),
            ),
        )
        conn.commit()

    def get_events(
        self,
        event_type: str | None = None,
        since: float | None = None,
        limit: int = 1000,
    ) -> list[StoredEvent]:
        conn = self._get_conn()
        clauses: list[str] = []
        params: list[Any] = []
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        where = " AND ".join(clauses) if clauses else "1=1"
        rows = conn.execute(
            f"SELECT * FROM events WHERE {where} ORDER BY timestamp DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [
            StoredEvent(
                event_id=r["event_id"],
                event_type=r["event_type"],
                agent_id=r["agent_id"],
                operator_id=r["operator_id"],
                timestamp=r["timestamp"],
                payload=json.loads(r["payload"]),
            )
            for r in rows
        ]

    # ---- Compromises ----

    def insert_compromise(self, record: CompromiseRecord) -> None:
        conn = self._get_conn()
        conn.execute(
            """INSERT OR REPLACE INTO compromises
                   (record_id, reporter_agent_id, compromised_agent_id,
                    source, nk_score, nk_verdict, recommended_action, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.record_id,
                record.reporter_agent_id,
                record.compromised_agent_id,
                record.source,
                record.nk_score,
                record.nk_verdict,
                record.recommended_action,
                record.timestamp,
            ),
        )
        conn.commit()

    def get_compromises(
        self, since: float | None = None, limit: int = 1000
    ) -> list[CompromiseRecord]:
        conn = self._get_conn()
        if since is not None:
            rows = conn.execute(
                "SELECT * FROM compromises WHERE timestamp >= ? "
                "ORDER BY timestamp DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM compromises ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            CompromiseRecord(
                record_id=r["record_id"],
                reporter_agent_id=r["reporter_agent_id"],
                compromised_agent_id=r["compromised_agent_id"],
                source=r["source"],
                nk_score=r["nk_score"],
                nk_verdict=r["nk_verdict"],
                recommended_action=r["recommended_action"],
                timestamp=r["timestamp"],
            )
            for r in rows
        ]

    def set_agent_killswitched(self, agent_id: str, killswitched: bool) -> None:
        """Set the is_killswitched flag on an agent (creates agent if needed)."""
        conn = self._get_conn()
        # Try update first
        cur = conn.execute(
            "UPDATE agents SET is_killswitched = ? WHERE agent_id = ?",
            (int(killswitched), agent_id),
        )
        if cur.rowcount == 0 and killswitched:
            # Agent doesn't exist yet — create it with killswitched flag
            conn.execute(
                """INSERT INTO agents
                       (agent_id, operator_id, trust_tier, trust_score,
                        is_compromised, is_quarantined, is_killswitched,
                        last_heartbeat, metadata)
                   VALUES (?, '', 0, 0.0, 0, 0, ?, 0, '{}')
                """,
                (agent_id, int(killswitched)),
            )
        conn.commit()

    # ---- Killswitch Rules ----

    def insert_killswitch_rule(self, rule: KillswitchRule) -> None:
        conn = self._get_conn()
        conn.execute(
            """INSERT OR REPLACE INTO killswitch_rules
                   (rule_id, scope, target, blocked, reason, created_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rule.rule_id,
                rule.scope,
                rule.target,
                int(rule.blocked),
                rule.reason,
                rule.created_at,
                rule.created_by,
            ),
        )
        conn.commit()

    def get_killswitch_rules(self) -> list[KillswitchRule]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM killswitch_rules ORDER BY created_at DESC"
        ).fetchall()
        return [
            KillswitchRule(
                rule_id=r["rule_id"],
                scope=r["scope"],
                target=r["target"],
                blocked=bool(r["blocked"]),
                reason=r["reason"],
                created_at=r["created_at"],
                created_by=r["created_by"],
            )
            for r in rows
        ]

    def delete_killswitch_rule(self, rule_id: str) -> bool:
        conn = self._get_conn()
        cur = conn.execute(
            "DELETE FROM killswitch_rules WHERE rule_id = ?", (rule_id,)
        )
        conn.commit()
        return cur.rowcount > 0

    def check_killswitch(self, agent_id: str, operator_id: str) -> tuple[bool, str, str]:
        """Check killswitch status for an agent.

        Priority: swarm rules first, then operator, then agent.
        Returns (blocked, reason, scope).
        """
        conn = self._get_conn()
        # Check swarm-level first
        row = conn.execute(
            "SELECT * FROM killswitch_rules WHERE scope = 'swarm' AND blocked = 1 LIMIT 1"
        ).fetchone()
        if row:
            return True, row["reason"], "swarm"

        # Check operator-level
        if operator_id:
            row = conn.execute(
                "SELECT * FROM killswitch_rules WHERE scope = 'operator' AND target = ? AND blocked = 1 LIMIT 1",
                (operator_id,),
            ).fetchone()
            if row:
                return True, row["reason"], "operator"

        # Check agent-level
        if agent_id:
            row = conn.execute(
                "SELECT * FROM killswitch_rules WHERE scope = 'agent' AND target = ? AND blocked = 1 LIMIT 1",
                (agent_id,),
            ).fetchone()
            if row:
                return True, row["reason"], "agent"

        return False, "", ""

    # ---- Quarantine Rules ----

    def insert_quarantine_rule(self, rule: QuarantineRule) -> None:
        conn = self._get_conn()
        conn.execute(
            """INSERT OR REPLACE INTO quarantine_rules
                   (rule_id, scope, target, quarantined, reason, severity, created_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rule.rule_id,
                rule.scope,
                rule.target,
                int(rule.quarantined),
                rule.reason,
                rule.severity,
                rule.created_at,
                rule.created_by,
            ),
        )
        conn.commit()

    def get_quarantine_rules(self) -> list[QuarantineRule]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM quarantine_rules ORDER BY created_at DESC"
        ).fetchall()
        return [
            QuarantineRule(
                rule_id=r["rule_id"],
                scope=r["scope"],
                target=r["target"],
                quarantined=bool(r["quarantined"]),
                reason=r["reason"],
                severity=r["severity"],
                created_at=r["created_at"],
                created_by=r["created_by"],
            )
            for r in rows
        ]

    def delete_quarantine_rule(self, rule_id: str) -> bool:
        conn = self._get_conn()
        cur = conn.execute(
            "DELETE FROM quarantine_rules WHERE rule_id = ?", (rule_id,)
        )
        conn.commit()
        return cur.rowcount > 0

    def check_quarantine(self, agent_id: str, operator_id: str) -> tuple[bool, str, str, str]:
        """Check quarantine status for an agent.

        Priority: swarm rules first, then operator, then agent.
        Returns (quarantined, reason, scope, severity).
        """
        conn = self._get_conn()
        # Check swarm-level first
        row = conn.execute(
            "SELECT * FROM quarantine_rules WHERE scope = 'swarm' AND quarantined = 1 LIMIT 1"
        ).fetchone()
        if row:
            return True, row["reason"], "swarm", row["severity"]

        # Check operator-level
        if operator_id:
            row = conn.execute(
                "SELECT * FROM quarantine_rules WHERE scope = 'operator' AND target = ? AND quarantined = 1 LIMIT 1",
                (operator_id,),
            ).fetchone()
            if row:
                return True, row["reason"], "operator", row["severity"]

        # Check agent-level
        if agent_id:
            row = conn.execute(
                "SELECT * FROM quarantine_rules WHERE scope = 'agent' AND target = ? AND quarantined = 1 LIMIT 1",
                (agent_id,),
            ).fetchone()
            if row:
                return True, row["reason"], "agent", row["severity"]

        return False, "", "", ""

    def set_agent_quarantined(self, agent_id: str, quarantined: bool) -> None:
        """Set the is_quarantined flag on an agent (creates agent if needed)."""
        conn = self._get_conn()
        cur = conn.execute(
            "UPDATE agents SET is_quarantined = ? WHERE agent_id = ?",
            (int(quarantined), agent_id),
        )
        if cur.rowcount == 0 and quarantined:
            conn.execute(
                """INSERT INTO agents
                       (agent_id, operator_id, trust_tier, trust_score,
                        is_compromised, is_quarantined, is_killswitched,
                        last_heartbeat, metadata)
                   VALUES (?, '', 0, 0.0, 0, ?, 0, 0, '{}')
                """,
                (agent_id, int(quarantined)),
            )
        conn.commit()

    def count_compromised_agents(self) -> int:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COUNT(DISTINCT compromised_agent_id) as cnt FROM compromises"
        ).fetchone()
        return row["cnt"] if row else 0
