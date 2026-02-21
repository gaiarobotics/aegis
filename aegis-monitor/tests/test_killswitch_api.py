"""Tests for the killswitch API endpoints in the monitor."""

import os
import time

import pytest

from monitor.app import app


@pytest.fixture
def client(tmp_path):
    """Create a test client with a temp database."""
    from fastapi.testclient import TestClient

    db_path = str(tmp_path / "test_ks.db")
    os.environ["MONITOR_DATABASE_PATH"] = db_path
    os.environ.pop("MONITOR_API_KEYS", None)

    with TestClient(app) as c:
        app.state.config.api_keys = []
        yield c

    os.environ.pop("MONITOR_DATABASE_PATH", None)


class TestKillswitchStatus:
    def test_status_no_rules(self, client):
        resp = client.get("/api/v1/killswitch/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["blocked"] is False
        assert data["reason"] == ""
        assert data["scope"] == ""

    def test_status_with_swarm_block(self, client):
        client.post("/api/v1/killswitch/rules", json={
            "scope": "swarm",
            "blocked": True,
            "reason": "Emergency shutdown",
        })
        resp = client.get("/api/v1/killswitch/status?agent_id=a1&operator_id=op1")
        data = resp.json()
        assert data["blocked"] is True
        assert data["reason"] == "Emergency shutdown"
        assert data["scope"] == "swarm"

    def test_status_with_agent_block(self, client):
        client.post("/api/v1/killswitch/rules", json={
            "scope": "agent",
            "target": "agent-1",
            "blocked": True,
            "reason": "Agent compromised",
        })
        # Blocked agent
        resp = client.get("/api/v1/killswitch/status?agent_id=agent-1")
        assert resp.json()["blocked"] is True

        # Different agent not blocked
        resp = client.get("/api/v1/killswitch/status?agent_id=agent-2")
        assert resp.json()["blocked"] is False

    def test_status_with_operator_block(self, client):
        client.post("/api/v1/killswitch/rules", json={
            "scope": "operator",
            "target": "op-bad",
            "blocked": True,
            "reason": "Operator suspended",
        })
        resp = client.get("/api/v1/killswitch/status?agent_id=a1&operator_id=op-bad")
        data = resp.json()
        assert data["blocked"] is True
        assert data["scope"] == "operator"

        # Different operator not blocked
        resp = client.get("/api/v1/killswitch/status?agent_id=a1&operator_id=op-good")
        assert resp.json()["blocked"] is False

    def test_swarm_overrides_agent(self, client):
        """Swarm block takes priority over agent-specific rules."""
        client.post("/api/v1/killswitch/rules", json={
            "scope": "swarm",
            "blocked": True,
            "reason": "Swarm block",
        })
        resp = client.get("/api/v1/killswitch/status?agent_id=any-agent")
        data = resp.json()
        assert data["blocked"] is True
        assert data["scope"] == "swarm"


class TestKillswitchRulesCRUD:
    def test_create_rule(self, client):
        resp = client.post("/api/v1/killswitch/rules", json={
            "scope": "agent",
            "target": "agent-1",
            "blocked": True,
            "reason": "Test block",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "rule_id" in data

    def test_list_rules_empty(self, client):
        resp = client.get("/api/v1/killswitch/rules")
        assert resp.status_code == 200
        assert resp.json()["rules"] == []

    def test_list_rules_after_create(self, client):
        client.post("/api/v1/killswitch/rules", json={
            "scope": "swarm",
            "blocked": True,
            "reason": "All blocked",
        })
        resp = client.get("/api/v1/killswitch/rules")
        rules = resp.json()["rules"]
        assert len(rules) == 1
        assert rules[0]["scope"] == "swarm"
        assert rules[0]["blocked"] is True
        assert rules[0]["reason"] == "All blocked"

    def test_delete_rule(self, client):
        create_resp = client.post("/api/v1/killswitch/rules", json={
            "scope": "agent",
            "target": "agent-1",
            "blocked": True,
        })
        rule_id = create_resp.json()["rule_id"]

        # Verify it blocks
        resp = client.get("/api/v1/killswitch/status?agent_id=agent-1")
        assert resp.json()["blocked"] is True

        # Delete
        del_resp = client.delete(f"/api/v1/killswitch/rules/{rule_id}")
        assert del_resp.json()["status"] == "ok"

        # Verify unblocked
        resp = client.get("/api/v1/killswitch/status?agent_id=agent-1")
        assert resp.json()["blocked"] is False

    def test_delete_nonexistent_rule(self, client):
        resp = client.delete("/api/v1/killswitch/rules/nonexistent-id")
        assert resp.json()["status"] == "not_found"

    def test_multiple_rules(self, client):
        client.post("/api/v1/killswitch/rules", json={
            "scope": "agent", "target": "a1", "blocked": True, "reason": "r1",
        })
        client.post("/api/v1/killswitch/rules", json={
            "scope": "agent", "target": "a2", "blocked": True, "reason": "r2",
        })
        client.post("/api/v1/killswitch/rules", json={
            "scope": "operator", "target": "op1", "blocked": True, "reason": "r3",
        })
        resp = client.get("/api/v1/killswitch/rules")
        assert len(resp.json()["rules"]) == 3

    def test_custom_rule_id(self, client):
        resp = client.post("/api/v1/killswitch/rules", json={
            "rule_id": "my-custom-id",
            "scope": "swarm",
            "blocked": True,
        })
        assert resp.json()["rule_id"] == "my-custom-id"

        rules = client.get("/api/v1/killswitch/rules").json()["rules"]
        assert rules[0]["rule_id"] == "my-custom-id"


class TestKillswitchAgentStatus:
    def test_agent_marked_killswitched_on_block(self, client):
        """Blocking an agent should set is_killswitched on the agent."""
        # Create agent first
        client.post("/api/v1/heartbeat", json={
            "agent_id": "agent-ks",
            "trust_tier": 2,
        })

        # Block agent
        client.post("/api/v1/killswitch/rules", json={
            "scope": "agent",
            "target": "agent-ks",
            "blocked": True,
            "reason": "test block",
        })

        # Check trust endpoint shows killswitched
        resp = client.get("/api/v1/trust/agent-ks")
        data = resp.json()
        assert data["is_killswitched"] is True

        # Check graph shows killswitched
        resp = client.get("/api/v1/graph")
        nodes = {n["id"]: n for n in resp.json()["nodes"]}
        assert nodes["agent-ks"]["is_killswitched"] is True
        assert nodes["agent-ks"]["color"] == "#e67e22"  # orange

    def test_agent_unkillswitched_on_rule_delete(self, client):
        """Deleting the rule should clear is_killswitched."""
        client.post("/api/v1/heartbeat", json={
            "agent_id": "agent-ks2",
            "trust_tier": 1,
        })

        create_resp = client.post("/api/v1/killswitch/rules", json={
            "scope": "agent",
            "target": "agent-ks2",
            "blocked": True,
        })
        rule_id = create_resp.json()["rule_id"]

        # Verify killswitched
        resp = client.get("/api/v1/trust/agent-ks2")
        assert resp.json()["is_killswitched"] is True

        # Delete rule
        client.delete(f"/api/v1/killswitch/rules/{rule_id}")

        # Verify unkillswitched
        resp = client.get("/api/v1/trust/agent-ks2")
        assert resp.json()["is_killswitched"] is False

        # Graph node too
        resp = client.get("/api/v1/graph")
        nodes = {n["id"]: n for n in resp.json()["nodes"]}
        assert nodes["agent-ks2"]["is_killswitched"] is False

    def test_killswitched_distinct_from_quarantined(self, client):
        """Killswitched and quarantined are independent statuses."""
        client.post("/api/v1/heartbeat", json={
            "agent_id": "agent-q",
            "trust_tier": 2,
            "is_quarantined": True,
        })
        client.post("/api/v1/killswitch/rules", json={
            "scope": "agent",
            "target": "agent-q",
            "blocked": True,
        })

        resp = client.get("/api/v1/trust/agent-q")
        data = resp.json()
        assert data["is_quarantined"] is True
        assert data["is_killswitched"] is True

    def test_metrics_include_killswitched_count(self, client):
        client.post("/api/v1/heartbeat", json={"agent_id": "a1"})
        client.post("/api/v1/heartbeat", json={"agent_id": "a2"})
        client.post("/api/v1/killswitch/rules", json={
            "scope": "agent", "target": "a1", "blocked": True,
        })

        resp = client.get("/api/v1/metrics")
        data = resp.json()
        assert data["killswitched_agents"] == 1

    def test_swarm_block_marks_all_agents(self, client):
        """A swarm block should mark all known agents as killswitched."""
        client.post("/api/v1/heartbeat", json={"agent_id": "s1"})
        client.post("/api/v1/heartbeat", json={"agent_id": "s2"})

        client.post("/api/v1/killswitch/rules", json={
            "scope": "swarm",
            "blocked": True,
            "reason": "Emergency",
        })

        resp = client.get("/api/v1/trust/s1")
        assert resp.json()["is_killswitched"] is True
        resp = client.get("/api/v1/trust/s2")
        assert resp.json()["is_killswitched"] is True


class TestKillswitchDB:
    def test_db_check_killswitch_empty(self, client):
        """Direct DB check with no rules."""
        db = app.state.db
        blocked, reason, scope = db.check_killswitch("a1", "op1")
        assert blocked is False

    def test_db_check_killswitch_swarm(self, client):
        from monitor.models import KillswitchRule
        db = app.state.db
        db.insert_killswitch_rule(KillswitchRule(
            rule_id="r1", scope="swarm", blocked=True, reason="swarm block",
        ))
        blocked, reason, scope = db.check_killswitch("a1", "op1")
        assert blocked is True
        assert scope == "swarm"

    def test_db_check_killswitch_agent(self, client):
        from monitor.models import KillswitchRule
        db = app.state.db
        db.insert_killswitch_rule(KillswitchRule(
            rule_id="r2", scope="agent", target="a1",
            blocked=True, reason="agent block",
        ))
        blocked, reason, scope = db.check_killswitch("a1", "op1")
        assert blocked is True
        assert scope == "agent"

        # Different agent not blocked
        blocked, reason, scope = db.check_killswitch("a2", "op1")
        assert blocked is False

    def test_db_delete_killswitch_rule(self, client):
        from monitor.models import KillswitchRule
        db = app.state.db
        db.insert_killswitch_rule(KillswitchRule(
            rule_id="r3", scope="swarm", blocked=True,
        ))
        assert db.delete_killswitch_rule("r3") is True
        assert db.delete_killswitch_rule("r3") is False

        blocked, _, _ = db.check_killswitch("a1", "op1")
        assert blocked is False
