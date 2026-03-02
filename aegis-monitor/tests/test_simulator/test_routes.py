"""Tests for simulator API routes."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path):
    """Create a TestClient with a temporary preset directory."""
    from monitor.simulator.routes import create_simulator_app

    app = create_simulator_app(preset_dir=str(tmp_path))
    return TestClient(app)


# Config dict with all modules disabled — required for all simulation tests
_DISABLED_MODULES_CONFIG = {
    "num_agents": 10,
    "seed": 42,
    "modules": {
        "scanner": False,
        "broker": False,
        "identity": False,
        "behavior": False,
        "recovery": False,
    },
}


# ---------------------------------------------------------------------------
# TestPresetEndpoints
# ---------------------------------------------------------------------------


class TestPresetEndpoints:
    """Test preset CRUD endpoints."""

    def test_list_presets(self, client):
        resp = client.get("/api/v1/simulator/presets")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    def test_save_and_load_preset(self, client):
        config = {"num_agents": 50, "seed": 7}
        resp = client.post("/api/v1/simulator/presets/my-test", json=config)
        assert resp.status_code == 200

        resp = client.get("/api/v1/simulator/presets/my-test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["num_agents"] == 50
        assert data["seed"] == 7

    def test_delete_preset(self, client):
        config = {"num_agents": 25}
        client.post("/api/v1/simulator/presets/to-delete", json=config)
        resp = client.delete("/api/v1/simulator/presets/to-delete")
        assert resp.status_code == 200

        # Should be gone now
        resp = client.get("/api/v1/simulator/presets/to-delete")
        assert resp.status_code == 404

    def test_load_nonexistent(self, client):
        resp = client.get("/api/v1/simulator/presets/does-not-exist")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# TestSimulationControl
# ---------------------------------------------------------------------------


class TestSimulationControl:
    """Test simulation control endpoints."""

    def test_generate(self, client):
        resp = client.post(
            "/api/v1/simulator/generate", json=_DISABLED_MODULES_CONFIG
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["state"] == "ready"
        assert data["num_agents"] == 10

    def test_start(self, client):
        client.post("/api/v1/simulator/generate", json=_DISABLED_MODULES_CONFIG)
        resp = client.post("/api/v1/simulator/start")
        assert resp.status_code == 200
        data = resp.json()
        assert data["state"] == "running"

    def test_tick(self, client):
        client.post("/api/v1/simulator/generate", json=_DISABLED_MODULES_CONFIG)
        client.post("/api/v1/simulator/start")
        resp = client.post("/api/v1/simulator/tick")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tick"] == 1
        assert "counts" in data

    def test_pause_resume(self, client):
        client.post("/api/v1/simulator/generate", json=_DISABLED_MODULES_CONFIG)
        client.post("/api/v1/simulator/start")

        resp = client.post("/api/v1/simulator/pause")
        assert resp.status_code == 200
        assert resp.json()["state"] == "paused"

        resp = client.post("/api/v1/simulator/resume")
        assert resp.status_code == 200
        assert resp.json()["state"] == "running"

    def test_reset(self, client):
        client.post("/api/v1/simulator/generate", json=_DISABLED_MODULES_CONFIG)
        resp = client.post("/api/v1/simulator/reset")
        assert resp.status_code == 200
        assert resp.json()["state"] == "idle"

    def test_status(self, client):
        resp = client.get("/api/v1/simulator/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["state"] == "idle"

    def test_export(self, client):
        client.post("/api/v1/simulator/generate", json=_DISABLED_MODULES_CONFIG)
        client.post("/api/v1/simulator/start")
        client.post("/api/v1/simulator/tick")
        resp = client.get("/api/v1/simulator/export")
        assert resp.status_code == 200
        data = resp.json()
        assert "snapshots" in data

    def test_agents(self, client):
        client.post("/api/v1/simulator/generate", json=_DISABLED_MODULES_CONFIG)
        resp = client.get("/api/v1/simulator/agents")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 10

    def test_graph(self, client):
        client.post("/api/v1/simulator/generate", json=_DISABLED_MODULES_CONFIG)
        resp = client.get("/api/v1/simulator/graph")
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data
        assert "edges" in data
