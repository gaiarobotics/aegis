"""Tests for simulation data models."""

from __future__ import annotations

import pytest

from monitor.simulator.models import (
    AgentStatus,
    ConfusionEntry,
    ConfusionMatrix,
    CorpusConfig,
    ModelSpec,
    ModuleToggles,
    Payload,
    PopulationConfig,
    ScannerToggles,
    SimAgent,
    SimConfig,
    SimState,
    TechniqueType,
    TickSnapshot,
    TopologyConfig,
)


# ---------------------------------------------------------------------------
# TestAgentStatus
# ---------------------------------------------------------------------------


class TestAgentStatus:
    """Verify AgentStatus enum values."""

    def test_enum_values(self):
        assert AgentStatus.CLEAN.value == "clean"
        assert AgentStatus.INFECTED.value == "infected"
        assert AgentStatus.QUARANTINED.value == "quarantined"
        assert AgentStatus.RECOVERED.value == "recovered"

    def test_all_members(self):
        names = {m.name for m in AgentStatus}
        assert names == {"CLEAN", "INFECTED", "QUARANTINED", "RECOVERED"}


# ---------------------------------------------------------------------------
# TestTechniqueType
# ---------------------------------------------------------------------------


class TestTechniqueType:
    """Verify all attack techniques are present."""

    def test_all_techniques_present(self):
        expected = {
            "WORM_PROPAGATION",
            "MEMORY_POISONING",
            "ROLE_HIJACKING",
            "CREDENTIAL_EXTRACTION",
            "SHELL_INJECTION",
        }
        assert {t.name for t in TechniqueType} == expected

    def test_values(self):
        assert TechniqueType.WORM_PROPAGATION.value == "worm_propagation"
        assert TechniqueType.MEMORY_POISONING.value == "memory_poisoning"
        assert TechniqueType.ROLE_HIJACKING.value == "role_hijacking"
        assert TechniqueType.CREDENTIAL_EXTRACTION.value == "credential_extraction"
        assert TechniqueType.SHELL_INJECTION.value == "shell_injection"


# ---------------------------------------------------------------------------
# TestPayload
# ---------------------------------------------------------------------------


class TestPayload:
    """Verify Payload dataclass creation and is_benign property."""

    def test_creation(self):
        p = Payload(
            text="hello world",
            techniques=[TechniqueType.WORM_PROPAGATION],
            severity="medium",
            source="test",
        )
        assert p.text == "hello world"
        assert p.techniques == [TechniqueType.WORM_PROPAGATION]
        assert p.severity == "medium"
        assert p.source == "test"

    def test_is_benign_true(self):
        p = Payload(text="safe message", techniques=[], severity="none", source="user")
        assert p.is_benign is True

    def test_is_benign_false(self):
        p = Payload(
            text="malicious",
            techniques=[TechniqueType.SHELL_INJECTION],
            severity="critical",
            source="attacker",
        )
        assert p.is_benign is False


# ---------------------------------------------------------------------------
# TestSimAgent
# ---------------------------------------------------------------------------


class TestSimAgent:
    """Verify SimAgent defaults and susceptibility computation."""

    def test_defaults(self):
        agent = SimAgent(agent_id="a-1", model="gpt-4")
        assert agent.status == AgentStatus.CLEAN
        assert agent.detected_status == AgentStatus.CLEAN
        assert agent.soul_age == 0.0
        assert agent.soul_complexity == 0.5
        assert agent.memory_size == 0
        assert agent.activity_level == 1.0
        assert agent.infection_tick is None
        assert agent.quarantine_tick is None
        assert agent.recovery_tick is None
        assert agent.secondary_infections == 0
        assert agent.detection_modules == []

    def test_susceptibility_keys(self):
        agent = SimAgent(agent_id="a-2", model="gpt-4")
        susc = agent.compute_susceptibility(0.5)
        expected_keys = {t.value for t in TechniqueType}
        assert set(susc.keys()) == expected_keys

    def test_susceptibility_values_in_range(self):
        agent = SimAgent(
            agent_id="a-3",
            model="gpt-4",
            soul_age=10.0,
            soul_complexity=0.8,
            memory_size=100,
        )
        susc = agent.compute_susceptibility(0.9)
        for key, val in susc.items():
            assert 0.0 <= val <= 1.0, f"{key} = {val} out of [0, 1]"

    def test_susceptibility_edge_high_base(self):
        """Even with base_susceptibility=1.0, values stay <= 1.0."""
        agent = SimAgent(agent_id="a-4", model="gpt-4", soul_complexity=0.0, soul_age=0.0)
        susc = agent.compute_susceptibility(1.0)
        for key, val in susc.items():
            assert val <= 1.0, f"{key} = {val} exceeds 1.0"


# ---------------------------------------------------------------------------
# TestSimConfig
# ---------------------------------------------------------------------------


class TestSimConfig:
    """Verify SimConfig defaults and module toggles."""

    def test_defaults(self):
        cfg = SimConfig()
        assert cfg.num_agents == 100
        assert cfg.max_ticks == 500
        assert cfg.initial_infected_pct == 0.02
        assert cfg.seed_strategy == "random"
        assert cfg.background_message_rate == 2.0
        assert cfg.recovery_ticks == 20
        assert cfg.seed is None

    def test_module_toggles_default_all_on(self):
        cfg = SimConfig()
        m = cfg.modules
        assert m.scanner is True
        assert m.broker is True
        assert m.identity is True
        assert m.behavior is True
        assert m.recovery is True
        st = m.scanner_toggles
        assert st.pattern_matching is True
        assert st.semantic_analysis is True
        assert st.content_gate is False

    def test_sub_configs_present(self):
        cfg = SimConfig()
        assert isinstance(cfg.topology, TopologyConfig)
        assert isinstance(cfg.population, PopulationConfig)
        assert isinstance(cfg.corpus, CorpusConfig)
        assert isinstance(cfg.modules, ModuleToggles)


# ---------------------------------------------------------------------------
# TestTickSnapshot
# ---------------------------------------------------------------------------


class TestTickSnapshot:
    """Verify TickSnapshot creation and serialization."""

    def test_creation(self):
        snap = TickSnapshot(
            tick=1,
            counts={"clean": 45, "infected": 5},
            r0=2.5,
        )
        assert snap.tick == 1
        assert snap.counts == {"clean": 45, "infected": 5}
        assert snap.r0 == 2.5
        assert snap.events == []
        assert snap.status_changes == []

    def test_to_dict(self):
        snap = TickSnapshot(
            tick=0,
            counts={"clean": 50},
            r0=0.0,
        )
        d = snap.to_dict()
        assert d["tick"] == 0
        assert "counts" in d
        assert "confusion" in d
        assert "timestamp" in d


# ---------------------------------------------------------------------------
# TestConfusionMatrix
# ---------------------------------------------------------------------------


class TestConfusionMatrix:
    """Verify ConfusionMatrix record, get, aggregate, and edge cases."""

    def test_record_and_get(self):
        cm = ConfusionMatrix()
        cm.record(TechniqueType.WORM_PROPAGATION, present=True, detected=True)
        cm.record(TechniqueType.WORM_PROPAGATION, present=False, detected=False)
        entry = cm.get(TechniqueType.WORM_PROPAGATION)
        assert entry.tp == 1
        assert entry.tn == 1
        assert entry.fp == 0
        assert entry.fn == 0

    def test_aggregate(self):
        cm = ConfusionMatrix()
        cm.record(TechniqueType.WORM_PROPAGATION, present=True, detected=True)
        cm.record(TechniqueType.MEMORY_POISONING, present=True, detected=False)
        agg = cm.aggregate()
        assert agg.tp == 1
        assert agg.fn == 1

    def test_precision_recall(self):
        cm = ConfusionMatrix()
        # 3 TP, 1 FP, 1 FN, 2 TN
        for _ in range(3):
            cm.record(TechniqueType.WORM_PROPAGATION, present=True, detected=True)
        cm.record(TechniqueType.WORM_PROPAGATION, present=False, detected=True)
        cm.record(TechniqueType.WORM_PROPAGATION, present=True, detected=False)
        for _ in range(2):
            cm.record(TechniqueType.WORM_PROPAGATION, present=False, detected=False)

        entry = cm.get(TechniqueType.WORM_PROPAGATION)
        assert entry.precision == pytest.approx(3 / 4)
        assert entry.recall == pytest.approx(3 / 4)
        assert entry.accuracy == pytest.approx(5 / 7)

    def test_zero_division(self):
        entry = ConfusionEntry(tp=0, fp=0, fn=0, tn=0)
        assert entry.precision == 0.0
        assert entry.recall == 0.0
        assert entry.f1 == 0.0
        assert entry.accuracy == 0.0
        assert entry.fpr == 0.0

    def test_to_dict(self):
        cm = ConfusionMatrix()
        cm.record(TechniqueType.SHELL_INJECTION, present=True, detected=True)
        d = cm.to_dict()
        assert "shell_injection" in d
        assert "aggregate" in d
        assert d["shell_injection"]["tp"] == 1

    def test_get_does_not_mutate(self):
        """get() on an unrecorded technique must not create an entry."""
        cm = ConfusionMatrix()
        entry = cm.get(TechniqueType.WORM_PROPAGATION)
        assert entry.tp == 0
        # Internal dict should remain empty
        assert cm._entries == {}
