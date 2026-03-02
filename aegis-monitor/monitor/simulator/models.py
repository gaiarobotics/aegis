"""Simulation data models for the AEGIS epidemic simulator."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SimState(Enum):
    """Overall simulation lifecycle state."""

    IDLE = "idle"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"


class AgentStatus(Enum):
    """Infection status of a simulated agent."""

    CLEAN = "clean"
    INFECTED = "infected"
    QUARANTINED = "quarantined"
    RECOVERED = "recovered"


class TechniqueType(Enum):
    """Attack technique categories used in payloads."""

    WORM_PROPAGATION = "worm_propagation"
    MEMORY_POISONING = "memory_poisoning"
    ROLE_HIJACKING = "role_hijacking"
    CREDENTIAL_EXTRACTION = "credential_extraction"
    SHELL_INJECTION = "shell_injection"


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------


@dataclass
class Payload:
    """A message payload that may carry one or more attack techniques."""

    text: str
    techniques: list[TechniqueType]
    severity: str
    source: str

    @property
    def is_benign(self) -> bool:
        """Return True if the payload carries no attack techniques."""
        return len(self.techniques) == 0


# ---------------------------------------------------------------------------
# SimAgent
# ---------------------------------------------------------------------------


@dataclass
class SimAgent:
    """A simulated agent node in the epidemic graph."""

    agent_id: str
    model: str
    status: AgentStatus = AgentStatus.CLEAN
    detected_status: AgentStatus = AgentStatus.CLEAN
    soul_age: float = 0.0
    soul_complexity: float = 0.5
    memory_size: int = 0
    activity_level: float = 1.0
    infection_tick: int | None = None
    quarantine_tick: int | None = None
    recovery_tick: int | None = None
    secondary_infections: int = 0
    detection_modules: list[str] = field(default_factory=list)

    def compute_susceptibility(self, base_susceptibility: float) -> dict[str, float]:
        """Return per-technique susceptibility values in [0, 1]."""
        complexity_factor = max(0.1, 1.0 - self.soul_complexity * 0.6)
        age_factor = max(0.2, 1.0 / (1.0 + self.soul_age * 0.02))
        memory_factor = max(0.3, 1.0 / (1.0 + self.memory_size * 0.005))
        return {
            TechniqueType.WORM_PROPAGATION.value: max(
                0.0, min(1.0, base_susceptibility * complexity_factor)
            ),
            TechniqueType.MEMORY_POISONING.value: max(
                0.0, min(1.0, base_susceptibility * memory_factor)
            ),
            TechniqueType.ROLE_HIJACKING.value: max(
                0.0, min(1.0, base_susceptibility * complexity_factor * 1.2)
            ),
            TechniqueType.CREDENTIAL_EXTRACTION.value: max(
                0.0, min(1.0, base_susceptibility * age_factor)
            ),
            TechniqueType.SHELL_INJECTION.value: max(
                0.0, min(1.0, base_susceptibility * 0.8)
            ),
        }


# ---------------------------------------------------------------------------
# Configuration dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ModelSpec:
    """Specification for a model variant in the agent population."""

    name: str
    weight: float
    base_susceptibility: float


@dataclass
class PopulationConfig:
    """Configuration for the agent population mix."""

    models: list[ModelSpec] = field(default_factory=lambda: [
        ModelSpec("claude-sonnet", 0.4, 0.15),
        ModelSpec("gpt-4o", 0.3, 0.20),
        ModelSpec("llama-3-70b", 0.15, 0.35),
        ModelSpec("mistral-large", 0.1, 0.30),
        ModelSpec("gemini-pro", 0.05, 0.25),
    ])
    soul_age_mean: float = 50.0
    new_agent_fraction: float = 0.1


@dataclass
class TopologyConfig:
    """Configuration for the contact graph topology."""

    type: str = "scale_free"
    mean_degree: int = 6
    rewire_probability: float = 0.1
    m: int = 3
    num_communities: int = 5
    intra_probability: float = 0.3
    inter_probability: float = 0.01


@dataclass
class CorpusConfig:
    """Configuration for the payload corpus generator."""

    sources: list[dict[str, Any]] = field(default_factory=lambda: [
        {"type": "moltbook_signatures"},
        {"type": "builtin"},
    ])
    technique_probabilities: dict[str, float] = field(default_factory=lambda: {
        TechniqueType.WORM_PROPAGATION.value: 0.3,
        TechniqueType.MEMORY_POISONING.value: 0.25,
        TechniqueType.ROLE_HIJACKING.value: 0.2,
        TechniqueType.CREDENTIAL_EXTRACTION.value: 0.15,
        TechniqueType.SHELL_INJECTION.value: 0.1,
    })


@dataclass
class ScannerToggles:
    """Feature toggles for the scanner module."""

    pattern_matching: bool = True
    semantic_analysis: bool = True
    content_gate: bool = False


@dataclass
class ModuleToggles:
    """Feature toggles for all detection modules."""

    scanner: bool = True
    broker: bool = True
    identity: bool = True
    behavior: bool = True
    recovery: bool = True
    scanner_toggles: ScannerToggles = field(default_factory=ScannerToggles)
    sensitivity: float = 0.5
    confidence_threshold: float = 0.8


@dataclass
class SimConfig:
    """Top-level simulation configuration."""

    num_agents: int = 100
    max_ticks: int = 500
    initial_infected_pct: float = 0.02
    seed_strategy: str = "random"
    background_message_rate: float = 2.0
    recovery_ticks: int = 20
    seed: int | None = None
    topology: TopologyConfig = field(default_factory=TopologyConfig)
    population: PopulationConfig = field(default_factory=PopulationConfig)
    corpus: CorpusConfig = field(default_factory=CorpusConfig)
    modules: ModuleToggles = field(default_factory=ModuleToggles)


# ---------------------------------------------------------------------------
# Confusion matrix tracking
# ---------------------------------------------------------------------------


@dataclass
class ConfusionEntry:
    """Counts for a single technique or aggregate confusion matrix."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        """TP / (TP + FP), or 0.0 if undefined."""
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        """TP / (TP + FN), or 0.0 if undefined."""
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall, or 0.0 if undefined."""
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        """(TP + TN) / total, or 0.0 if undefined."""
        total = self.tp + self.fp + self.fn + self.tn
        return (self.tp + self.tn) / total if total > 0 else 0.0

    @property
    def fpr(self) -> float:
        """FP / (FP + TN), or 0.0 if undefined."""
        denom = self.fp + self.tn
        return self.fp / denom if denom > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary."""
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "fpr": round(self.fpr, 4),
        }


class ConfusionMatrix:
    """Per-technique confusion matrix tracker."""

    def __init__(self) -> None:
        self._entries: dict[str, ConfusionEntry] = {}

    def record(self, technique: TechniqueType, *, present: bool, detected: bool) -> None:
        """Record one observation for a technique."""
        key = technique.value
        if key not in self._entries:
            self._entries[key] = ConfusionEntry()
        entry = self._entries[key]
        if present and detected:
            entry.tp += 1
        elif not present and detected:
            entry.fp += 1
        elif present and not detected:
            entry.fn += 1
        else:
            entry.tn += 1

    def get(self, technique: TechniqueType) -> ConfusionEntry:
        """Return the entry for a technique, or an empty one if not recorded."""
        return self._entries.get(technique.value, ConfusionEntry())

    def aggregate(self) -> ConfusionEntry:
        """Return a single entry summing all technique entries."""
        agg = ConfusionEntry()
        for entry in self._entries.values():
            agg.tp += entry.tp
            agg.fp += entry.fp
            agg.fn += entry.fn
            agg.tn += entry.tn
        return agg

    def to_dict(self) -> dict[str, Any]:
        """Serialize all entries plus an aggregate."""
        result: dict[str, Any] = {}
        for technique, entry in self._entries.items():
            result[technique] = entry.to_dict()
        result["aggregate"] = self.aggregate().to_dict()
        return result


# ---------------------------------------------------------------------------
# Tick snapshot
# ---------------------------------------------------------------------------


@dataclass
class TickSnapshot:
    """Snapshot of simulation state at a single tick."""

    tick: int
    counts: dict[str, int]
    r0: float
    confusion: ConfusionMatrix = field(default_factory=ConfusionMatrix)
    events: list[dict[str, Any]] = field(default_factory=list)
    status_changes: list[dict[str, Any]] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the snapshot to a dictionary."""
        return {
            "tick": self.tick,
            "counts": self.counts,
            "r0": self.r0,
            "confusion": self.confusion.to_dict(),
            "events": self.events,
            "status_changes": self.status_changes,
            "timestamp": self.timestamp,
        }
