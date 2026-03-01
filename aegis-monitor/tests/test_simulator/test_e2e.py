"""End-to-end smoke tests for the AEGIS epidemic simulator."""

from __future__ import annotations

from fastapi.testclient import TestClient

from monitor.simulator.routes import create_simulator_app


def test_full_simulation_lifecycle(tmp_path):
    """Run a complete simulation: generate -> start -> tick N times -> export."""
    app = create_simulator_app(preset_dir=str(tmp_path))
    client = TestClient(app)

    # Generate with 30 agents, 10% infected, seed=42, all modules disabled
    config = {
        "num_agents": 30,
        "initial_infected_pct": 0.1,
        "max_ticks": 50,
        "seed": 42,
        "background_message_rate": 1.0,
        "topology": {"type": "scale_free", "m": 2},
        "corpus": {
            "sources": [{"type": "builtin"}],
            "technique_probabilities": {
                "worm_propagation": 0.5,
                "memory_poisoning": 0.2,
                "role_hijacking": 0.1,
                "credential_extraction": 0.1,
                "shell_injection": 0.1,
            },
        },
        "modules": {
            "scanner": False,
            "broker": False,
            "identity": False,
            "behavior": False,
            "recovery": False,
        },
    }

    # Generate -> state=ready
    resp = client.post("/api/v1/simulator/generate", json=config)
    assert resp.status_code == 200
    assert resp.json()["state"] == "ready"

    # Start -> state=running
    resp = client.post("/api/v1/simulator/start")
    assert resp.json()["state"] == "running"

    # Tick 20 times, verify each tick
    for i in range(20):
        resp = client.post("/api/v1/simulator/tick")
        assert resp.status_code == 200
        snap = resp.json()
        assert snap["tick"] == i + 1
        assert sum(snap["counts"].values()) == 30  # population constant

    # Verify infection spread
    resp = client.get("/api/v1/simulator/status")
    counts = resp.json()["counts"]
    total_ever_infected = (
        counts.get("infected", 0)
        + counts.get("quarantined", 0)
        + counts.get("recovered", 0)
    )
    assert total_ever_infected >= 3  # at least initial infections remain

    # Verify graph
    resp = client.get("/api/v1/simulator/graph")
    assert len(resp.json()["nodes"]) == 30

    # Verify confusion matrix in export
    resp = client.get("/api/v1/simulator/export")
    export = resp.json()
    assert len(export["snapshots"]) == 20
    assert "aggregate" in export["confusion_matrix"]

    # Pause and resume
    resp = client.post("/api/v1/simulator/pause")
    assert resp.json()["state"] == "paused"
    resp = client.post("/api/v1/simulator/resume")
    assert resp.json()["state"] == "running"

    # Reset
    resp = client.post("/api/v1/simulator/reset")
    assert resp.json()["state"] == "idle"


def test_preset_roundtrip(tmp_path):
    """Save a preset, reload, generate from it."""
    app = create_simulator_app(preset_dir=str(tmp_path))
    client = TestClient(app)

    config = {
        "num_agents": 25,
        "seed": 99,
        "modules": {
            "scanner": False,
            "broker": False,
            "identity": False,
            "behavior": False,
            "recovery": False,
        },
    }
    client.post("/api/v1/simulator/presets/my-test", json=config)
    resp = client.get("/api/v1/simulator/presets/my-test")
    assert resp.json()["num_agents"] == 25

    # Generate from loaded preset
    resp = client.post("/api/v1/simulator/generate", json=resp.json())
    assert resp.json()["state"] == "ready"
    assert resp.json()["num_agents"] == 25
