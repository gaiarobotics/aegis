"""Tests for the Postgres database backend.

Skipped by default — set TEST_POSTGRES_URL to run:

    TEST_POSTGRES_URL="postgresql://user:pass@localhost:5432/aegis_test" pytest tests/test_db_postgres.py -v
"""

import os
import time

import pytest

pytestmark = pytest.mark.postgres

_TABLES = [
    "agents", "edges", "events", "compromises",
    "killswitch_rules", "quarantine_rules",
]


@pytest.fixture
def db():
    """Create a Database backed by Postgres, clean up tables after test."""
    from monitor.db import Database

    url = os.environ["TEST_POSTGRES_URL"]
    d = Database(url)
    yield d

    # Clean up all tables after each test
    for table in _TABLES:
        d._backend.execute(f"DELETE FROM {table}")
    d._backend.close()


class TestPostgresAgents:
    def test_upsert_and_get_agent(self, db):
        from monitor.models import AgentNode

        node = AgentNode(agent_id="pg-1", trust_tier=2, trust_score=0.8)
        db.upsert_agent(node)
        result = db.get_agent("pg-1")
        assert result is not None
        assert result.agent_id == "pg-1"
        assert result.trust_tier == 2
        assert result.trust_score == 0.8

    def test_get_all_agents(self, db):
        from monitor.models import AgentNode

        db.upsert_agent(AgentNode(agent_id="pg-a"))
        db.upsert_agent(AgentNode(agent_id="pg-b"))
        agents = db.get_all_agents()
        ids = {a.agent_id for a in agents}
        assert "pg-a" in ids
        assert "pg-b" in ids

    def test_upsert_updates_existing(self, db):
        from monitor.models import AgentNode

        db.upsert_agent(AgentNode(agent_id="pg-u", trust_tier=1))
        db.upsert_agent(AgentNode(agent_id="pg-u", trust_tier=3))
        result = db.get_agent("pg-u")
        assert result.trust_tier == 3

    def test_get_nonexistent_agent(self, db):
        assert db.get_agent("does-not-exist") is None


class TestPostgresEdges:
    def test_upsert_and_get_edges(self, db):
        from monitor.models import AgentEdge

        edge = AgentEdge(
            source_agent_id="a", target_agent_id="b",
            direction="outbound", last_seen=1.0, message_count=5,
        )
        db.upsert_edge(edge)
        edges = db.get_all_edges()
        assert len(edges) == 1
        assert edges[0].source_agent_id == "a"
        assert edges[0].message_count == 5


class TestPostgresEvents:
    def test_insert_and_get_events(self, db):
        from monitor.models import StoredEvent

        event = StoredEvent(
            event_id="ev-1", event_type="threat", agent_id="a1",
            timestamp=time.time(), payload={"detail": "test"},
        )
        db.insert_event(event)
        events = db.get_events(event_type="threat")
        assert len(events) == 1
        assert events[0].event_id == "ev-1"
        assert events[0].payload["detail"] == "test"


class TestPostgresCompromises:
    def test_insert_and_get_compromises(self, db):
        from monitor.models import CompromiseRecord

        record = CompromiseRecord(
            record_id="cr-1", reporter_agent_id="r1",
            compromised_agent_id="c1", timestamp=time.time(),
        )
        db.insert_compromise(record)
        records = db.get_compromises()
        assert len(records) == 1
        assert records[0].compromised_agent_id == "c1"

    def test_count_compromised_agents(self, db):
        from monitor.models import CompromiseRecord

        db.insert_compromise(CompromiseRecord(
            record_id="cr-2", reporter_agent_id="r1",
            compromised_agent_id="c1", timestamp=time.time(),
        ))
        db.insert_compromise(CompromiseRecord(
            record_id="cr-3", reporter_agent_id="r1",
            compromised_agent_id="c2", timestamp=time.time(),
        ))
        assert db.count_compromised_agents() == 2


class TestPostgresKillswitch:
    def test_killswitch_crud(self, db):
        from monitor.models import KillswitchRule

        rule = KillswitchRule(
            rule_id="ks-1", scope="swarm", blocked=True,
            reason="test", created_at=time.time(),
        )
        db.insert_killswitch_rule(rule)
        rules = db.get_killswitch_rules()
        assert len(rules) == 1

        blocked, reason, scope = db.check_killswitch("any", "any")
        assert blocked is True
        assert scope == "swarm"

        assert db.delete_killswitch_rule("ks-1") is True
        blocked, _, _ = db.check_killswitch("any", "any")
        assert blocked is False

    def test_set_agent_killswitched(self, db):
        db.set_agent_killswitched("ks-agent", True)
        agent = db.get_agent("ks-agent")
        assert agent is not None
        assert agent.is_killswitched is True


class TestPostgresQuarantine:
    def test_quarantine_crud(self, db):
        from monitor.models import QuarantineRule

        rule = QuarantineRule(
            rule_id="qr-1", scope="agent", target="a1",
            quarantined=True, reason="suspicious",
            severity="medium", created_at=time.time(),
        )
        db.insert_quarantine_rule(rule)
        rules = db.get_quarantine_rules()
        assert len(rules) == 1

        q, reason, scope, severity = db.check_quarantine("a1", "")
        assert q is True
        assert scope == "agent"
        assert severity == "medium"

        assert db.delete_quarantine_rule("qr-1") is True
        q, _, _, _ = db.check_quarantine("a1", "")
        assert q is False

    def test_set_agent_quarantined(self, db):
        db.set_agent_quarantined("qr-agent", True)
        agent = db.get_agent("qr-agent")
        assert agent is not None
        assert agent.is_quarantined is True
