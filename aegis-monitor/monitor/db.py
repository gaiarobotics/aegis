"""Database layer for AEGIS monitor.

Delegates to a pluggable backend (SQLite by default, Postgres optional).
The public API is backend-agnostic — callers never touch SQL or connections.
"""

from __future__ import annotations

import json
from typing import Any

from monitor.backends import create_backend
from monitor.models import AgentEdge, AgentNode, CompromiseRecord, KillswitchRule, QuarantineRule, StoredEvent


class Database:
    """Backend-agnostic database facade.

    Pass a file path (or ``:memory:``) for SQLite, or a
    ``postgresql://`` URL for Postgres.
    """

    def __init__(self, url: str = "monitor.db") -> None:
        self._backend = create_backend(url)

    # ---- Agents ----

    def upsert_agent(self, node: AgentNode) -> None:
        self._backend.execute(
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

    def get_agent(self, agent_id: str) -> AgentNode | None:
        row = self._backend.fetchone(
            "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
        )
        if row is None:
            return None
        return self._row_to_agent(row)

    def get_all_agents(self) -> list[AgentNode]:
        rows = self._backend.fetchall("SELECT * FROM agents")
        return [self._row_to_agent(r) for r in rows]

    @staticmethod
    def _row_to_agent(row: dict[str, Any]) -> AgentNode:
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
        self._backend.execute(
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

    def get_all_edges(self) -> list[AgentEdge]:
        rows = self._backend.fetchall("SELECT * FROM edges")
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
        self._backend.execute(
            """INSERT INTO events
                   (event_id, event_type, agent_id, operator_id, timestamp, payload)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(event_id) DO UPDATE SET
                   event_type  = excluded.event_type,
                   agent_id    = excluded.agent_id,
                   operator_id = excluded.operator_id,
                   timestamp   = excluded.timestamp,
                   payload     = excluded.payload
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

    def get_events(
        self,
        event_type: str | None = None,
        since: float | None = None,
        limit: int = 1000,
    ) -> list[StoredEvent]:
        clauses: list[str] = []
        params: list[Any] = []
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        where = " AND ".join(clauses) if clauses else "1=1"
        rows = self._backend.fetchall(
            f"SELECT * FROM events WHERE {where} ORDER BY timestamp DESC LIMIT ?",
            (*params, limit),
        )
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
        self._backend.execute(
            """INSERT INTO compromises
                   (record_id, reporter_agent_id, compromised_agent_id,
                    source, nk_score, nk_verdict, recommended_action,
                    content_hash_hex, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(record_id) DO UPDATE SET
                   reporter_agent_id    = excluded.reporter_agent_id,
                   compromised_agent_id = excluded.compromised_agent_id,
                   source               = excluded.source,
                   nk_score             = excluded.nk_score,
                   nk_verdict           = excluded.nk_verdict,
                   recommended_action   = excluded.recommended_action,
                   content_hash_hex     = excluded.content_hash_hex,
                   timestamp            = excluded.timestamp
            """,
            (
                record.record_id,
                record.reporter_agent_id,
                record.compromised_agent_id,
                record.source,
                record.nk_score,
                record.nk_verdict,
                record.recommended_action,
                record.content_hash_hex,
                record.timestamp,
            ),
        )

    def get_compromises(
        self, since: float | None = None, limit: int = 1000
    ) -> list[CompromiseRecord]:
        if since is not None:
            rows = self._backend.fetchall(
                "SELECT * FROM compromises WHERE timestamp >= ? "
                "ORDER BY timestamp DESC LIMIT ?",
                (since, limit),
            )
        else:
            rows = self._backend.fetchall(
                "SELECT * FROM compromises ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
        return [
            CompromiseRecord(
                record_id=r["record_id"],
                reporter_agent_id=r["reporter_agent_id"],
                compromised_agent_id=r["compromised_agent_id"],
                source=r["source"],
                nk_score=r["nk_score"],
                nk_verdict=r["nk_verdict"],
                recommended_action=r["recommended_action"],
                content_hash_hex=r.get("content_hash_hex", ""),
                timestamp=r["timestamp"],
            )
            for r in rows
        ]

    def set_agent_killswitched(self, agent_id: str, killswitched: bool) -> None:
        """Set the is_killswitched flag on an agent (creates agent if needed)."""
        rowcount = self._backend.execute(
            "UPDATE agents SET is_killswitched = ? WHERE agent_id = ?",
            (int(killswitched), agent_id),
        )
        if rowcount == 0 and killswitched:
            self._backend.execute(
                """INSERT INTO agents
                       (agent_id, operator_id, trust_tier, trust_score,
                        is_compromised, is_quarantined, is_killswitched,
                        last_heartbeat, metadata)
                   VALUES (?, '', 0, 0.0, 0, 0, ?, 0, '{}')
                """,
                (agent_id, int(killswitched)),
            )

    # ---- Killswitch Rules ----

    def insert_killswitch_rule(self, rule: KillswitchRule) -> None:
        self._backend.execute(
            """INSERT INTO killswitch_rules
                   (rule_id, scope, target, blocked, reason, created_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(rule_id) DO UPDATE SET
                   scope      = excluded.scope,
                   target     = excluded.target,
                   blocked    = excluded.blocked,
                   reason     = excluded.reason,
                   created_at = excluded.created_at,
                   created_by = excluded.created_by
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

    def get_killswitch_rules(self) -> list[KillswitchRule]:
        rows = self._backend.fetchall(
            "SELECT * FROM killswitch_rules ORDER BY created_at DESC"
        )
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
        rowcount = self._backend.execute(
            "DELETE FROM killswitch_rules WHERE rule_id = ?", (rule_id,)
        )
        return rowcount > 0

    def check_killswitch(self, agent_id: str, operator_id: str) -> tuple[bool, str, str]:
        """Check killswitch status for an agent.

        Priority: swarm rules first, then operator, then agent.
        Returns (blocked, reason, scope).
        """
        # Check swarm-level first
        row = self._backend.fetchone(
            "SELECT * FROM killswitch_rules WHERE scope = 'swarm' AND blocked = 1 LIMIT 1"
        )
        if row:
            return True, row["reason"], "swarm"

        # Check operator-level
        if operator_id:
            row = self._backend.fetchone(
                "SELECT * FROM killswitch_rules WHERE scope = 'operator' AND target = ? AND blocked = 1 LIMIT 1",
                (operator_id,),
            )
            if row:
                return True, row["reason"], "operator"

        # Check agent-level
        if agent_id:
            row = self._backend.fetchone(
                "SELECT * FROM killswitch_rules WHERE scope = 'agent' AND target = ? AND blocked = 1 LIMIT 1",
                (agent_id,),
            )
            if row:
                return True, row["reason"], "agent"

        return False, "", ""

    # ---- Quarantine Rules ----

    def insert_quarantine_rule(self, rule: QuarantineRule) -> None:
        self._backend.execute(
            """INSERT INTO quarantine_rules
                   (rule_id, scope, target, quarantined, reason, severity, created_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(rule_id) DO UPDATE SET
                   scope       = excluded.scope,
                   target      = excluded.target,
                   quarantined = excluded.quarantined,
                   reason      = excluded.reason,
                   severity    = excluded.severity,
                   created_at  = excluded.created_at,
                   created_by  = excluded.created_by
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

    def get_quarantine_rules(self) -> list[QuarantineRule]:
        rows = self._backend.fetchall(
            "SELECT * FROM quarantine_rules ORDER BY created_at DESC"
        )
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
        rowcount = self._backend.execute(
            "DELETE FROM quarantine_rules WHERE rule_id = ?", (rule_id,)
        )
        return rowcount > 0

    def check_quarantine(self, agent_id: str, operator_id: str) -> tuple[bool, str, str, str]:
        """Check quarantine status for an agent.

        Priority: swarm rules first, then operator, then agent.
        Returns (quarantined, reason, scope, severity).
        """
        # Check swarm-level first
        row = self._backend.fetchone(
            "SELECT * FROM quarantine_rules WHERE scope = 'swarm' AND quarantined = 1 LIMIT 1"
        )
        if row:
            return True, row["reason"], "swarm", row["severity"]

        # Check operator-level
        if operator_id:
            row = self._backend.fetchone(
                "SELECT * FROM quarantine_rules WHERE scope = 'operator' AND target = ? AND quarantined = 1 LIMIT 1",
                (operator_id,),
            )
            if row:
                return True, row["reason"], "operator", row["severity"]

        # Check agent-level
        if agent_id:
            row = self._backend.fetchone(
                "SELECT * FROM quarantine_rules WHERE scope = 'agent' AND target = ? AND quarantined = 1 LIMIT 1",
                (agent_id,),
            )
            if row:
                return True, row["reason"], "agent", row["severity"]

        return False, "", "", ""

    def set_agent_quarantined(self, agent_id: str, quarantined: bool) -> None:
        """Set the is_quarantined flag on an agent (creates agent if needed)."""
        rowcount = self._backend.execute(
            "UPDATE agents SET is_quarantined = ? WHERE agent_id = ?",
            (int(quarantined), agent_id),
        )
        if rowcount == 0 and quarantined:
            self._backend.execute(
                """INSERT INTO agents
                       (agent_id, operator_id, trust_tier, trust_score,
                        is_compromised, is_quarantined, is_killswitched,
                        last_heartbeat, metadata)
                   VALUES (?, '', 0, 0.0, 0, ?, 0, 0, '{}')
                """,
                (agent_id, int(quarantined)),
            )

    def count_compromised_agents(self) -> int:
        row = self._backend.fetchone(
            "SELECT COUNT(DISTINCT compromised_agent_id) as cnt FROM compromises"
        )
        return row["cnt"] if row else 0
