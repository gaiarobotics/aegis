"""Tests for the monitor FastAPI application."""

import os
import time

import pytest

from monitor.app import app
from monitor.config import MonitorConfig


@pytest.fixture
def client(tmp_path):
    """Create a test client with a temp database."""
    from fastapi.testclient import TestClient

    db_path = str(tmp_path / "test.db")
    os.environ["MONITOR_DATABASE_PATH"] = db_path
    os.environ.pop("MONITOR_API_KEYS", None)

    with TestClient(app) as c:
        # Ensure open auth mode for most tests
        app.state.config.api_keys = []
        yield c

    os.environ.pop("MONITOR_DATABASE_PATH", None)


class TestDashboard:
    def test_root_returns_html(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "AEGIS Monitor" in resp.text


class TestHeartbeat:
    def test_receive_heartbeat(self, client):
        resp = client.post("/api/v1/heartbeat", json={
            "agent_id": "agent-1",
            "operator_id": "op-1",
            "trust_tier": 2,
            "trust_score": 55.0,
            "edges": [
                {"target_agent_id": "agent-2", "direction": "outbound",
                 "last_seen": time.time(), "message_count": 3},
            ],
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_heartbeat_updates_graph(self, client):
        client.post("/api/v1/heartbeat", json={
            "agent_id": "agent-1",
            "trust_tier": 2,
        })
        resp = client.get("/api/v1/graph")
        data = resp.json()
        assert len(data["nodes"]) >= 1
        assert any(n["id"] == "agent-1" for n in data["nodes"])


class TestCompromise:
    def test_receive_compromise(self, client):
        resp = client.post("/api/v1/reports/compromise", json={
            "report_id": "r1",
            "agent_id": "reporter-1",
            "compromised_agent_id": "victim-1",
            "source": "nk_cell",
            "nk_score": 0.95,
            "nk_verdict": "hostile",
            "timestamp": time.time(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_compromise_marks_graph(self, client):
        client.post("/api/v1/heartbeat", json={"agent_id": "victim-1", "trust_tier": 2})
        client.post("/api/v1/reports/compromise", json={
            "agent_id": "reporter-1",
            "compromised_agent_id": "victim-1",
        })
        resp = client.get("/api/v1/graph")
        nodes = {n["id"]: n for n in resp.json()["nodes"]}
        assert nodes["victim-1"]["is_compromised"] is True


class TestTrust:
    def test_trust_endpoint(self, client):
        client.post("/api/v1/heartbeat", json={
            "agent_id": "a1",
            "trust_tier": 2,
            "trust_score": 55.0,
        })
        resp = client.get("/api/v1/trust/a1")
        data = resp.json()
        assert data["found"] is True
        assert data["trust_tier"] == 2

    def test_trust_unknown_agent(self, client):
        resp = client.get("/api/v1/trust/nonexistent")
        data = resp.json()
        assert data["found"] is False


class TestThreat:
    def test_receive_threat(self, client):
        resp = client.post("/api/v1/reports/threat", json={
            "report_id": "t1",
            "agent_id": "a1",
            "threat_score": 0.85,
            "is_threat": True,
            "scanner_match_count": 3,
        })
        assert resp.status_code == 200


class TestMetrics:
    def test_metrics_endpoint(self, client):
        resp = client.get("/api/v1/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert "r0" in data
        assert "active_threats" in data
        assert "quarantined_agents" in data
        assert "cluster_count" in data
        assert "total_agents" in data


class TestGraph:
    def test_empty_graph(self, client):
        resp = client.get("/api/v1/graph")
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data
        assert "edges" in data


class TestAuth:
    def test_open_mode_allows_all(self, client):
        """With no API keys configured, all requests should pass."""
        resp = client.get("/api/v1/graph")
        assert resp.status_code == 200

    def test_auth_rejects_invalid_key(self, client):
        app.state.config.api_keys = ["valid-key"]
        resp = client.get("/api/v1/graph", headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 403

    def test_auth_accepts_valid_key(self, client):
        app.state.config.api_keys = ["valid-key"]
        resp = client.get("/api/v1/graph", headers={"Authorization": "Bearer valid-key"})
        assert resp.status_code == 200

    def test_auth_rejects_missing_header(self, client):
        app.state.config.api_keys = ["valid-key"]
        resp = client.get("/api/v1/graph")
        assert resp.status_code == 401
