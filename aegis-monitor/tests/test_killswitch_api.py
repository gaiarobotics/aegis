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
