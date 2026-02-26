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


class TestThreatIntel:
    def test_empty_threat_intel(self, client):
        resp = client.get("/api/v1/threat-intel")
        assert resp.status_code == 200
        data = resp.json()
        assert data["compromised_agents"] == []
        assert data["compromised_hashes"] == []
        assert data["quarantined_agents"] == []
        assert "generated_at" in data

    def test_compromised_agent_in_threat_intel(self, client):
        # Register agent then mark compromised
        client.post("/api/v1/heartbeat", json={
            "agent_id": "victim-1",
            "trust_tier": 2,
            "content_hash": "abcdef01" * 4,
        })
        client.post("/api/v1/reports/compromise", json={
            "agent_id": "reporter-1",
            "compromised_agent_id": "victim-1",
        })
        resp = client.get("/api/v1/threat-intel")
        data = resp.json()
        assert "victim-1" in data["compromised_agents"]

    def test_compromised_hash_in_threat_intel(self, client):
        # Register agent with a content hash, then compromise it
        client.post("/api/v1/heartbeat", json={
            "agent_id": "victim-1",
            "trust_tier": 2,
            "content_hash": "abcdef01" * 4,
        })
        client.post("/api/v1/reports/compromise", json={
            "agent_id": "reporter-1",
            "compromised_agent_id": "victim-1",
        })
        resp = client.get("/api/v1/threat-intel")
        data = resp.json()
        assert len(data["compromised_hashes"]) >= 1

    def test_report_hash_stored_without_heartbeat(self, client):
        """Hash from compromise report is stored in contagion detector
        even without a prior heartbeat (no graph node needed)."""
        hash_hex = "abcdef01" * 4
        client.post("/api/v1/reports/compromise", json={
            "agent_id": "reporter-1",
            "compromised_agent_id": "victim-new",
            "content_hash_hex": hash_hex,
        })
        resp = client.get("/api/v1/threat-intel")
        data = resp.json()
        assert hash_hex in data["compromised_hashes"]

    def test_fallback_to_graph_node_hash(self, client):
        """When report has no hash, falls back to graph node's content_hash."""
        client.post("/api/v1/heartbeat", json={
            "agent_id": "victim-fb",
            "trust_tier": 2,
            "content_hash": "deadbeef" * 4,
        })
        client.post("/api/v1/reports/compromise", json={
            "agent_id": "reporter-1",
            "compromised_agent_id": "victim-fb",
            # No content_hash_hex — should fall back
        })
        resp = client.get("/api/v1/threat-intel")
        data = resp.json()
        assert len(data["compromised_hashes"]) >= 1

    def test_quarantined_agent_in_threat_intel(self, client):
        # Register agent then quarantine it
        client.post("/api/v1/heartbeat", json={
            "agent_id": "q-agent",
            "trust_tier": 2,
        })
        client.post("/api/v1/quarantine/rules", json={
            "scope": "agent",
            "target": "q-agent",
            "quarantined": True,
            "reason": "test",
            "severity": "high",
        })
        resp = client.get("/api/v1/threat-intel")
        data = resp.json()
        assert "q-agent" in data["quarantined_agents"]


class TestHashCloudGrowth:
    def test_multiple_hashes_grow_compromised_set(self, client):
        """Multiple compromise reports with different hashes grow the set."""
        hashes = [f"{i:0>8}" * 4 for i in range(3)]
        for i, h in enumerate(hashes):
            client.post("/api/v1/reports/compromise", json={
                "agent_id": f"reporter-{i}",
                "compromised_agent_id": f"victim-{i}",
                "content_hash_hex": h,
            })
        resp = client.get("/api/v1/threat-intel")
        data = resp.json()
        assert len(data["compromised_hashes"]) >= 3

    def test_similar_hash_scores_high_contagion(self, client):
        """A hash similar to a compromised variant scores high contagion."""
        from monitor.contagion import ContagionDetector

        detector: ContagionDetector = app.state.contagion_detector
        # Mark a known hash as compromised
        known_hash = "a" * 32
        detector.mark_compromised("victim-sim", known_hash)
        # Check same hash — should score 1.0 (identical)
        score = detector.check("other-agent", known_hash)
        assert score == 1.0

    def test_dissimilar_hash_scores_low_contagion(self, client):
        """A hash dissimilar to all compromised variants scores low."""
        from monitor.contagion import ContagionDetector

        detector: ContagionDetector = app.state.contagion_detector
        # Mark a known hash
        detector.mark_compromised("victim-dis", "a" * 32)
        # Check a very different hash — inverted bits
        different_hash = "5" * 32  # very different bit pattern from 'a' * 32
        score = detector.check("clean-agent", different_hash)
        # Should be well below 1.0
        assert score < 0.9
