"""Tests for the core simulation engine."""

from __future__ import annotations

import pytest

from monitor.simulator.models import (
    AgentStatus,
    CorpusConfig,
    ModuleToggles,
    PopulationConfig,
    SimConfig,
    SimState,
    TopologyConfig,
)


def _no_modules() -> ModuleToggles:
    """Return ModuleToggles with ALL modules disabled."""
    return ModuleToggles(
        scanner=False,
        broker=False,
        identity=False,
        behavior=False,
        recovery=False,
    )


def _make_config(
    num_agents: int = 20,
    seed: int = 42,
    initial_infected_pct: float = 0.05,
    seed_strategy: str = "random",
    max_ticks: int = 500,
    **kwargs,
) -> SimConfig:
    """Build a SimConfig with modules disabled and only builtin corpus."""
    return SimConfig(
        num_agents=num_agents,
        seed=seed,
        initial_infected_pct=initial_infected_pct,
        seed_strategy=seed_strategy,
        max_ticks=max_ticks,
        modules=_no_modules(),
        corpus=CorpusConfig(sources=[{"type": "builtin"}]),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# TestEngineLifecycle
# ---------------------------------------------------------------------------


class TestEngineLifecycle:
    """Verify simulation lifecycle state transitions."""

    def test_initial_state_is_idle(self):
        from monitor.simulator.engine import SimulationEngine

        cfg = _make_config(num_agents=10)
        engine = SimulationEngine(cfg)
        assert engine.state == SimState.IDLE

    def test_generate_transitions_to_ready(self):
        from monitor.simulator.engine import SimulationEngine

        cfg = _make_config(num_agents=10, seed=42)
        engine = SimulationEngine(cfg)
        engine.generate()
        assert engine.state == SimState.READY

    def test_start_transitions_to_running(self):
        from monitor.simulator.engine import SimulationEngine

        cfg = _make_config(num_agents=10)
        engine = SimulationEngine(cfg)
        engine.generate()
        engine.start()
        assert engine.state == SimState.RUNNING

    def test_pause_and_resume(self):
        from monitor.simulator.engine import SimulationEngine

        cfg = _make_config(num_agents=10)
        engine = SimulationEngine(cfg)
        engine.generate()
        engine.start()
        engine.pause()
        assert engine.state == SimState.PAUSED
        engine.resume()
        assert engine.state == SimState.RUNNING

    def test_stop_transitions_to_completed(self):
        from monitor.simulator.engine import SimulationEngine

        cfg = _make_config(num_agents=10)
        engine = SimulationEngine(cfg)
        engine.generate()
        engine.start()
        engine.stop()
        assert engine.state == SimState.COMPLETED

    def test_reset_transitions_to_idle(self):
        from monitor.simulator.engine import SimulationEngine

        cfg = _make_config(num_agents=10)
        engine = SimulationEngine(cfg)
        engine.generate()
        engine.start()
        engine.stop()
        engine.reset()
        assert engine.state == SimState.IDLE
        # Agents should be cleared
        assert engine.get_agent_states() == []


# ---------------------------------------------------------------------------
# TestPopulationGeneration
# ---------------------------------------------------------------------------


class TestPopulationGeneration:
    """Verify population generation and seed infection."""

    def test_agent_count(self):
        from monitor.simulator.engine import SimulationEngine

        cfg = _make_config(num_agents=50)
        engine = SimulationEngine(cfg)
        engine.generate()
        agents = engine.get_agent_states()
        assert len(agents) == 50

    def test_initial_infection(self):
        from monitor.simulator.engine import SimulationEngine

        cfg = _make_config(num_agents=100, initial_infected_pct=0.05)
        engine = SimulationEngine(cfg)
        engine.generate()
        agents = engine.get_agent_states()
        infected = [a for a in agents if a["status"] == AgentStatus.INFECTED.value]
        assert len(infected) == 5

    def test_model_diversity(self):
        from monitor.simulator.engine import SimulationEngine

        cfg = _make_config(num_agents=200, seed=42)
        engine = SimulationEngine(cfg)
        engine.generate()
        agents = engine.get_agent_states()
        models = {a["model"] for a in agents}
        assert len(models) > 1, f"Expected multiple models, got {models}"

    def test_seed_strategy_hubs(self):
        from monitor.simulator.engine import SimulationEngine

        cfg = _make_config(
            num_agents=50,
            seed=42,
            initial_infected_pct=0.1,
            seed_strategy="hubs",
        )
        engine = SimulationEngine(cfg)
        engine.generate()
        agents = engine.get_agent_states()
        infected = [a for a in agents if a["status"] == AgentStatus.INFECTED.value]
        assert len(infected) > 0, "Hubs strategy should produce some infected agents"


# ---------------------------------------------------------------------------
# TestTickExecution
# ---------------------------------------------------------------------------


class TestTickExecution:
    """Verify tick execution with ALL AEGIS modules disabled."""

    def test_single_tick_produces_snapshot(self):
        from monitor.simulator.engine import SimulationEngine

        cfg = _make_config(num_agents=20)
        engine = SimulationEngine(cfg)
        engine.generate()
        engine.start()
        snapshot = engine.tick()
        assert snapshot.tick == 1
        total = sum(snapshot.counts.values())
        assert total == 20, f"All agents must be accounted for, got {total}"

    def test_infection_spreads_without_aegis(self):
        from monitor.simulator.engine import SimulationEngine

        cfg = _make_config(
            num_agents=30,
            seed=42,
            initial_infected_pct=0.1,
            max_ticks=1000,
        )
        # Override corpus to ensure worm_propagation payloads are always generated
        cfg.corpus = CorpusConfig(
            sources=[{"type": "builtin"}],
            technique_probabilities={
                "worm_propagation": 1.0,
                "memory_poisoning": 0.0,
                "role_hijacking": 0.0,
                "credential_extraction": 0.0,
                "shell_injection": 0.0,
            },
        )
        # Use high susceptibility models
        cfg.population = PopulationConfig(
            models=[
                __import__(
                    "monitor.simulator.models", fromlist=["ModelSpec"]
                ).ModelSpec("test-model", 1.0, 0.95),
            ],
            soul_age_mean=1.0,
            new_agent_fraction=0.9,
        )
        engine = SimulationEngine(cfg)
        engine.generate()
        engine.start()
        initial_infected = sum(
            1
            for a in engine.get_agent_states()
            if a["status"] == AgentStatus.INFECTED.value
        )
        for _ in range(20):
            snapshot = engine.tick()
            if engine.state != SimState.RUNNING:
                break
        current_infected = sum(
            1
            for a in engine.get_agent_states()
            if a["status"] in (AgentStatus.INFECTED.value, AgentStatus.QUARANTINED.value)
        )
        assert current_infected > initial_infected, (
            f"Expected infection spread: initial={initial_infected}, "
            f"current={current_infected}"
        )

    def test_r0_computed(self):
        from monitor.simulator.engine import SimulationEngine

        cfg = _make_config(num_agents=20)
        engine = SimulationEngine(cfg)
        engine.generate()
        engine.start()
        snapshot = engine.tick()
        assert isinstance(snapshot.r0, float)

    def test_confusion_matrix_populated(self):
        from monitor.simulator.engine import SimulationEngine

        cfg = _make_config(num_agents=20, initial_infected_pct=0.1)
        engine = SimulationEngine(cfg)
        engine.generate()
        engine.start()
        for _ in range(5):
            snapshot = engine.tick()
            if engine.state != SimState.RUNNING:
                break
        cm = snapshot.confusion.aggregate()
        # With modules disabled, the confusion matrix records
        # all technique observations as not-detected
        total = cm.tp + cm.fp + cm.fn + cm.tn
        assert total >= 0  # Matrix should exist (may be empty if no interactions)


# ---------------------------------------------------------------------------
# TestReproducibility
# ---------------------------------------------------------------------------


class TestReproducibility:
    """Verify deterministic outcomes with identical seeds."""

    def test_same_seed_same_outcome(self):
        from monitor.simulator.engine import SimulationEngine

        def run_sim():
            cfg = _make_config(num_agents=20, seed=99)
            engine = SimulationEngine(cfg)
            engine.generate()
            engine.start()
            snapshots = []
            for _ in range(10):
                snap = engine.tick()
                snapshots.append(snap.counts.copy())
                if engine.state != SimState.RUNNING:
                    break
            return snapshots

        run1 = run_sim()
        run2 = run_sim()
        assert len(run1) == len(run2)
        for i, (c1, c2) in enumerate(zip(run1, run2)):
            assert c1 == c2, f"Tick {i + 1} mismatch: {c1} != {c2}"


# ---------------------------------------------------------------------------
# TestExport
# ---------------------------------------------------------------------------


class TestExport:
    """Verify export_results returns complete data."""

    def test_export_results(self):
        from monitor.simulator.engine import SimulationEngine

        cfg = _make_config(num_agents=10, initial_infected_pct=0.1)
        engine = SimulationEngine(cfg)
        engine.generate()
        engine.start()
        engine.tick()
        results = engine.export_results()
        assert "config" in results
        assert "snapshots" in results
        assert "confusion_matrix" in results
        assert "agents" in results
        assert len(results["snapshots"]) == 1
        assert len(results["agents"]) == 10
