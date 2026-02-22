"""Tests for the quarantine API endpoints in the monitor."""

import os

import pytest

from monitor.app import app


@pytest.fixture
def client(tmp_path):
    """Create a test client with a temp database."""
    from fastapi.testclient import TestClient

    db_path = str(tmp_path / "test_qr.db")
    os.environ["MONITOR_DATABASE_PATH"] = db_path
    os.environ.pop("MONITOR_API_KEYS", None)

    with TestClient(app) as c:
        app.state.config.api_keys = []
        yield c

    os.environ.pop("MONITOR_DATABASE_PATH", None)


class TestQuarantineStatus:
    def test_status_no_rules(self, client):
        resp = client.get("/api/v1/quarantine/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["quarantined"] is False
        assert data["reason"] == ""
        assert data["scope"] == ""
        assert data["severity"] == ""

    def test_status_with_swarm_quarantine(self, client):
        client.post("/api/v1/quarantine/rules", json={
            "scope": "swarm",
            "quarantined": True,
            "reason": "Swarm-wide quarantine",
            "severity": "high",
        })
        resp = client.get("/api/v1/quarantine/status?agent_id=a1&operator_id=op1")
        data = resp.json()
        assert data["quarantined"] is True
        assert data["reason"] == "Swarm-wide quarantine"
        assert data["scope"] == "swarm"
        assert data["severity"] == "high"

    def test_status_with_agent_quarantine(self, client):
        client.post("/api/v1/quarantine/rules", json={
            "scope": "agent",
            "target": "agent-1",
            "quarantined": True,
            "reason": "Suspicious behavior",
            "severity": "medium",
        })
        # Quarantined agent
        resp = client.get("/api/v1/quarantine/status?agent_id=agent-1")
        assert resp.json()["quarantined"] is True

        # Different agent not quarantined
        resp = client.get("/api/v1/quarantine/status?agent_id=agent-2")
        assert resp.json()["quarantined"] is False

    def test_status_with_operator_quarantine(self, client):
        client.post("/api/v1/quarantine/rules", json={
            "scope": "operator",
            "target": "op-bad",
            "quarantined": True,
            "reason": "Operator suspended",
            "severity": "high",
        })
        resp = client.get("/api/v1/quarantine/status?agent_id=a1&operator_id=op-bad")
        data = resp.json()
        assert data["quarantined"] is True
        assert data["scope"] == "operator"

        # Different operator not quarantined
        resp = client.get("/api/v1/quarantine/status?agent_id=a1&operator_id=op-good")
        assert resp.json()["quarantined"] is False

    def test_swarm_overrides_agent(self, client):
        """Swarm quarantine takes priority over agent-specific rules."""
        client.post("/api/v1/quarantine/rules", json={
            "scope": "swarm",
            "quarantined": True,
            "reason": "Swarm quarantine",
            "severity": "high",
        })
        resp = client.get("/api/v1/quarantine/status?agent_id=any-agent")
        data = resp.json()
        assert data["quarantined"] is True
        assert data["scope"] == "swarm"


class TestQuarantineRulesCRUD:
    def test_create_rule(self, client):
        resp = client.post("/api/v1/quarantine/rules", json={
            "scope": "agent",
            "target": "agent-1",
            "quarantined": True,
            "reason": "Test quarantine",
            "severity": "low",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "rule_id" in data

    def test_list_rules_empty(self, client):
        resp = client.get("/api/v1/quarantine/rules")
        assert resp.status_code == 200
        assert resp.json()["rules"] == []

    def test_list_rules_after_create(self, client):
        client.post("/api/v1/quarantine/rules", json={
            "scope": "swarm",
            "quarantined": True,
            "reason": "All quarantined",
            "severity": "high",
        })
        resp = client.get("/api/v1/quarantine/rules")
        rules = resp.json()["rules"]
        assert len(rules) == 1
        assert rules[0]["scope"] == "swarm"
        assert rules[0]["quarantined"] is True
        assert rules[0]["reason"] == "All quarantined"
        assert rules[0]["severity"] == "high"

    def test_delete_rule(self, client):
        create_resp = client.post("/api/v1/quarantine/rules", json={
            "scope": "agent",
            "target": "agent-1",
            "quarantined": True,
        })
        rule_id = create_resp.json()["rule_id"]

        # Verify it quarantines
        resp = client.get("/api/v1/quarantine/status?agent_id=agent-1")
        assert resp.json()["quarantined"] is True

        # Delete (release)
        del_resp = client.delete(f"/api/v1/quarantine/rules/{rule_id}")
        assert del_resp.json()["status"] == "ok"

        # Verify released
        resp = client.get("/api/v1/quarantine/status?agent_id=agent-1")
        assert resp.json()["quarantined"] is False

    def test_delete_nonexistent_rule(self, client):
        resp = client.delete("/api/v1/quarantine/rules/nonexistent-id")
        assert resp.json()["status"] == "not_found"

    def test_multiple_rules(self, client):
        client.post("/api/v1/quarantine/rules", json={
            "scope": "agent", "target": "a1", "quarantined": True, "reason": "r1",
        })
        client.post("/api/v1/quarantine/rules", json={
            "scope": "agent", "target": "a2", "quarantined": True, "reason": "r2",
        })
        client.post("/api/v1/quarantine/rules", json={
            "scope": "operator", "target": "op1", "quarantined": True, "reason": "r3",
        })
        resp = client.get("/api/v1/quarantine/rules")
        assert len(resp.json()["rules"]) == 3

    def test_custom_rule_id(self, client):
        resp = client.post("/api/v1/quarantine/rules", json={
            "rule_id": "my-custom-id",
            "scope": "swarm",
            "quarantined": True,
        })
        assert resp.json()["rule_id"] == "my-custom-id"

        rules = client.get("/api/v1/quarantine/rules").json()["rules"]
        assert rules[0]["rule_id"] == "my-custom-id"


class TestQuarantineAgentStatus:
    def test_agent_marked_quarantined_on_rule(self, client):
        """Creating a quarantine rule should set is_quarantined on the agent."""
        client.post("/api/v1/heartbeat", json={
            "agent_id": "agent-q",
            "trust_tier": 2,
        })

        client.post("/api/v1/quarantine/rules", json={
            "scope": "agent",
            "target": "agent-q",
            "quarantined": True,
            "reason": "test quarantine",
        })

        resp = client.get("/api/v1/trust/agent-q")
        data = resp.json()
        assert data["is_quarantined"] is True

    def test_agent_unquarantined_on_rule_delete(self, client):
        """Deleting the rule should clear is_quarantined."""
        client.post("/api/v1/heartbeat", json={
            "agent_id": "agent-q2",
            "trust_tier": 1,
        })

        create_resp = client.post("/api/v1/quarantine/rules", json={
            "scope": "agent",
            "target": "agent-q2",
            "quarantined": True,
        })
        rule_id = create_resp.json()["rule_id"]

        # Verify quarantined
        resp = client.get("/api/v1/trust/agent-q2")
        assert resp.json()["is_quarantined"] is True

        # Delete rule
        client.delete(f"/api/v1/quarantine/rules/{rule_id}")

        # Verify unquarantined
        resp = client.get("/api/v1/trust/agent-q2")
        assert resp.json()["is_quarantined"] is False

    def test_swarm_quarantine_marks_all_agents(self, client):
        """A swarm quarantine should mark all known agents as quarantined."""
        client.post("/api/v1/heartbeat", json={"agent_id": "s1"})
        client.post("/api/v1/heartbeat", json={"agent_id": "s2"})

        client.post("/api/v1/quarantine/rules", json={
            "scope": "swarm",
            "quarantined": True,
            "reason": "Emergency",
        })

        resp = client.get("/api/v1/trust/s1")
        assert resp.json()["is_quarantined"] is True
        resp = client.get("/api/v1/trust/s2")
        assert resp.json()["is_quarantined"] is True


class TestQuarantineDB:
    def test_db_check_quarantine_empty(self, client):
        db = app.state.db
        quarantined, reason, scope, severity = db.check_quarantine("a1", "op1")
        assert quarantined is False

    def test_db_check_quarantine_swarm(self, client):
        from monitor.models import QuarantineRule
        db = app.state.db
        db.insert_quarantine_rule(QuarantineRule(
            rule_id="r1", scope="swarm", quarantined=True,
            reason="swarm quarantine", severity="high",
        ))
        quarantined, reason, scope, severity = db.check_quarantine("a1", "op1")
        assert quarantined is True
        assert scope == "swarm"
        assert severity == "high"

    def test_db_check_quarantine_agent(self, client):
        from monitor.models import QuarantineRule
        db = app.state.db
        db.insert_quarantine_rule(QuarantineRule(
            rule_id="r2", scope="agent", target="a1",
            quarantined=True, reason="agent quarantine", severity="medium",
        ))
        quarantined, reason, scope, severity = db.check_quarantine("a1", "op1")
        assert quarantined is True
        assert scope == "agent"

        # Different agent not quarantined
        quarantined, reason, scope, severity = db.check_quarantine("a2", "op1")
        assert quarantined is False

    def test_db_delete_quarantine_rule(self, client):
        from monitor.models import QuarantineRule
        db = app.state.db
        db.insert_quarantine_rule(QuarantineRule(
            rule_id="r3", scope="swarm", quarantined=True, severity="low",
        ))
        assert db.delete_quarantine_rule("r3") is True
        assert db.delete_quarantine_rule("r3") is False

        quarantined, _, _, _ = db.check_quarantine("a1", "op1")
        assert quarantined is False
