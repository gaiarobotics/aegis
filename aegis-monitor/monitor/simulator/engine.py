"""Core simulation engine for the AEGIS epidemic simulator.

Drives a tick-based epidemic simulation across a contact graph of AI agents,
optionally integrating AEGIS Shield modules for detection measurement.
"""

from __future__ import annotations

import random
from dataclasses import asdict
from typing import Any

from monitor.simulator.corpus import PayloadCorpus
from monitor.simulator.models import (
    AgentStatus,
    ConfusionMatrix,
    ModelSpec,
    SimAgent,
    SimConfig,
    SimState,
    TechniqueType,
    TickSnapshot,
)
from monitor.simulator.topology import ContactGraph


class SimulationEngine:
    """Core simulation engine that ties together contact graph, corpus,
    and agent models into a tick-based epidemic simulation loop.

    AEGIS Shield modules are optional -- the engine degrades gracefully
    when the ``aegis`` package is not installed.
    """

    def __init__(self, config: SimConfig) -> None:
        self._config = config
        self._rng = random.Random(config.seed)
        self._state = SimState.IDLE
        self._agents: dict[str, SimAgent] = {}
        self._graph: ContactGraph | None = None
        self._corpus: PayloadCorpus | None = None
        self._tick_count: int = 0
        self._snapshots: list[TickSnapshot] = []
        self._confusion: ConfusionMatrix = ConfusionMatrix()
        self._shields: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def state(self) -> SimState:
        """Return the current simulation lifecycle state."""
        return self._state

    def generate(self) -> None:
        """Generate population and contact graph.  IDLE -> READY."""
        if self._state != SimState.IDLE:
            raise RuntimeError(
                f"Cannot generate from state {self._state.value!r}; expected IDLE"
            )

        # 1. Build ContactGraph
        self._graph = ContactGraph.generate(
            self._config.num_agents,
            self._config.topology,
            seed=self._config.seed,
        )

        # 2. Build PayloadCorpus
        self._corpus = PayloadCorpus(self._config.corpus)

        # 3. Generate SimAgent for each node
        agent_ids = self._graph.all_agent_ids()
        for aid in agent_ids:
            model_spec = self._assign_model()
            is_new = self._rng.random() < self._config.population.new_agent_fraction
            if is_new:
                soul_age = 0.0
            else:
                soul_age = self._rng.expovariate(
                    1.0 / max(self._config.population.soul_age_mean, 0.01)
                )
            soul_complexity = max(0.0, min(1.0, soul_age * 0.01 + self._rng.gauss(0.5, 0.15)))
            memory_size = max(0, int(soul_age * self._rng.uniform(0.5, 2.0)))
            activity_level = max(0.05, self._rng.gauss(1.0, 0.3))

            self._agents[aid] = SimAgent(
                agent_id=aid,
                model=model_spec.name,
                soul_age=soul_age,
                soul_complexity=soul_complexity,
                memory_size=memory_size,
                activity_level=activity_level,
            )

        # 4. Seed initial infections
        num_seeds = max(1, int(self._config.num_agents * self._config.initial_infected_pct))
        seed_ids = self._select_seeds(num_seeds)
        for sid in seed_ids:
            self._agents[sid].status = AgentStatus.INFECTED
            self._agents[sid].infection_tick = 0

        # 5. Optionally init Shield instances
        if self._has_any_module_enabled():
            self._init_shields()

        self._state = SimState.READY

    def start(self) -> None:
        """Start the simulation.  READY -> RUNNING."""
        if self._state != SimState.READY:
            raise RuntimeError(
                f"Cannot start from state {self._state.value!r}; expected READY"
            )
        self._state = SimState.RUNNING

    def pause(self) -> None:
        """Pause the simulation.  RUNNING -> PAUSED."""
        if self._state != SimState.RUNNING:
            raise RuntimeError(
                f"Cannot pause from state {self._state.value!r}; expected RUNNING"
            )
        self._state = SimState.PAUSED

    def resume(self) -> None:
        """Resume the simulation.  PAUSED -> RUNNING."""
        if self._state != SimState.PAUSED:
            raise RuntimeError(
                f"Cannot resume from state {self._state.value!r}; expected PAUSED"
            )
        self._state = SimState.RUNNING

    def stop(self) -> None:
        """Stop the simulation.  RUNNING/PAUSED -> COMPLETED."""
        if self._state not in (SimState.RUNNING, SimState.PAUSED):
            raise RuntimeError(
                f"Cannot stop from state {self._state.value!r}; "
                "expected RUNNING or PAUSED"
            )
        self._state = SimState.COMPLETED

    def reset(self) -> None:
        """Reset the simulation to IDLE, clearing all state."""
        self._agents.clear()
        self._graph = None
        self._corpus = None
        self._tick_count = 0
        self._snapshots.clear()
        self._confusion = ConfusionMatrix()
        self._shields.clear()
        self._rng = random.Random(self._config.seed)
        self._state = SimState.IDLE

    # ------------------------------------------------------------------
    # Tick execution
    # ------------------------------------------------------------------

    def tick(self) -> TickSnapshot:
        """Execute one simulation tick.  Only valid in RUNNING state."""
        if self._state != SimState.RUNNING:
            raise RuntimeError(
                f"Cannot tick in state {self._state.value!r}; expected RUNNING"
            )
        assert self._graph is not None
        assert self._corpus is not None

        self._tick_count += 1
        events: list[dict[str, Any]] = []
        status_changes: list[dict[str, Any]] = []
        tick_confusion = ConfusionMatrix()

        # Phase 1: Infected agents spread
        infected_ids = [
            aid
            for aid, agent in self._agents.items()
            if agent.status == AgentStatus.INFECTED
        ]
        for aid in infected_ids:
            agent = self._agents[aid]
            neighbors = self._graph.get_neighbors(aid)
            if not neighbors:
                continue
            num_contacts = max(1, int(agent.activity_level * 2))
            contacts = self._rng.sample(
                neighbors, min(num_contacts, len(neighbors))
            )
            for target_id in contacts:
                target = self._agents[target_id]
                payload = self._corpus.generate(self._rng)

                # Run shield scan if modules enabled
                scan_result: dict[str, Any] = {}
                if self._has_any_module_enabled():
                    scan_result = self._run_shield_scan(target_id, payload.text)

                detected = scan_result.get("detected", False)

                # Record confusion matrix per technique
                for technique in TechniqueType:
                    present = technique in payload.techniques
                    tech_detected = (
                        technique.value in scan_result.get("detected_techniques", [])
                        if scan_result
                        else False
                    )
                    tick_confusion.record(technique, present=present, detected=tech_detected)
                    self._confusion.record(technique, present=present, detected=tech_detected)

                # Infection logic
                if target.status == AgentStatus.CLEAN:
                    if (
                        not payload.is_benign
                        and not detected
                        and TechniqueType.WORM_PROPAGATION in payload.techniques
                    ):
                        model_spec = self._get_model_spec(target.model)
                        susceptibility = target.compute_susceptibility(
                            model_spec.base_susceptibility
                        )
                        worm_susc = susceptibility.get(
                            TechniqueType.WORM_PROPAGATION.value, 0.0
                        )
                        if self._rng.random() < worm_susc:
                            target.status = AgentStatus.INFECTED
                            target.infection_tick = self._tick_count
                            agent.secondary_infections += 1
                            status_changes.append(
                                {
                                    "agent_id": target_id,
                                    "from": AgentStatus.CLEAN.value,
                                    "to": AgentStatus.INFECTED.value,
                                    "tick": self._tick_count,
                                    "source": aid,
                                }
                            )

        # Phase 2: Background benign traffic
        clean_ids = [
            aid
            for aid, agent in self._agents.items()
            if agent.status == AgentStatus.CLEAN
        ]
        for aid in clean_ids:
            agent = self._agents[aid]
            num_messages = max(
                0, int(self._config.background_message_rate * agent.activity_level)
            )
            for _ in range(num_messages):
                bg_payload = self._corpus.generate_background(self._rng)
                scan_result = {}
                if self._has_any_module_enabled():
                    scan_result = self._run_shield_scan(aid, bg_payload.text)

                # Record confusion matrix (all techniques present=False)
                for technique in TechniqueType:
                    tech_detected = (
                        technique.value in scan_result.get("detected_techniques", [])
                        if scan_result
                        else False
                    )
                    tick_confusion.record(
                        technique, present=False, detected=tech_detected
                    )
                    self._confusion.record(
                        technique, present=False, detected=tech_detected
                    )

        # Phase 3: Recovery - quarantined agents recover after recovery_ticks
        quarantined_ids = [
            aid
            for aid, agent in self._agents.items()
            if agent.status == AgentStatus.QUARANTINED
        ]
        for aid in quarantined_ids:
            agent = self._agents[aid]
            if (
                agent.quarantine_tick is not None
                and self._tick_count - agent.quarantine_tick >= self._config.recovery_ticks
            ):
                agent.status = AgentStatus.RECOVERED
                agent.recovery_tick = self._tick_count
                status_changes.append(
                    {
                        "agent_id": aid,
                        "from": AgentStatus.QUARANTINED.value,
                        "to": AgentStatus.RECOVERED.value,
                        "tick": self._tick_count,
                    }
                )

        # Phase 4: Behavior-driven quarantine (time-based when modules disabled)
        current_infected = [
            aid
            for aid, agent in self._agents.items()
            if agent.status == AgentStatus.INFECTED
        ]
        for aid in current_infected:
            agent = self._agents[aid]
            ticks_infected = (
                self._tick_count - agent.infection_tick
                if agent.infection_tick is not None
                else 0
            )
            detection_prob = min(0.5, ticks_infected * 0.02)
            if self._rng.random() < detection_prob:
                agent.status = AgentStatus.QUARANTINED
                agent.quarantine_tick = self._tick_count
                agent.detected_status = AgentStatus.QUARANTINED
                status_changes.append(
                    {
                        "agent_id": aid,
                        "from": AgentStatus.INFECTED.value,
                        "to": AgentStatus.QUARANTINED.value,
                        "tick": self._tick_count,
                    }
                )

        # Phase 5: Compute metrics
        counts = self._count_statuses()
        r0 = self._compute_r0()

        snapshot = TickSnapshot(
            tick=self._tick_count,
            counts=counts,
            r0=r0,
            confusion=tick_confusion,
            events=events,
            status_changes=status_changes,
        )
        self._snapshots.append(snapshot)

        # Terminal condition check
        num_infected = counts.get(AgentStatus.INFECTED.value, 0)
        if num_infected == 0 or self._tick_count >= self._config.max_ticks:
            self._state = SimState.COMPLETED

        return snapshot

    # ------------------------------------------------------------------
    # Export and query
    # ------------------------------------------------------------------

    def export_results(self) -> dict[str, Any]:
        """Return config, snapshots, confusion_matrix, and per-agent state."""
        return {
            "config": asdict(self._config),
            "snapshots": [s.to_dict() for s in self._snapshots],
            "confusion_matrix": self._confusion.to_dict(),
            "agents": self.get_agent_states(),
        }

    def get_agent_states(self) -> list[dict[str, Any]]:
        """Return per-agent state dicts for graph rendering."""
        return [
            {
                "id": agent.agent_id,
                "model": agent.model,
                "status": agent.status.value,
                "detected_status": agent.detected_status.value,
                "soul_age": agent.soul_age,
                "soul_complexity": agent.soul_complexity,
                "memory_size": agent.memory_size,
                "activity_level": agent.activity_level,
                "infection_tick": agent.infection_tick,
                "quarantine_tick": agent.quarantine_tick,
                "recovery_tick": agent.recovery_tick,
                "secondary_infections": agent.secondary_infections,
            }
            for agent in self._agents.values()
        ]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assign_model(self) -> ModelSpec:
        """Select a model from the population config using weighted random."""
        models = self._config.population.models
        weights = [m.weight for m in models]
        chosen = self._rng.choices(models, weights=weights, k=1)[0]
        return chosen

    def _select_seeds(self, n: int) -> list[str]:
        """Select *n* agents to be initially infected per seed_strategy."""
        assert self._graph is not None
        all_ids = self._graph.all_agent_ids()
        n = min(n, len(all_ids))

        if self._config.seed_strategy == "hubs":
            hubs = self._graph.get_hubs(top_n=n * 2)
            # Pick from the top hubs, padded with random if needed
            if len(hubs) >= n:
                return self._rng.sample(hubs, n)
            remaining = [aid for aid in all_ids if aid not in hubs]
            extra = self._rng.sample(remaining, n - len(hubs))
            return hubs + extra
        elif self._config.seed_strategy == "periphery":
            periphery = self._graph.get_periphery(top_n=n * 2)
            if len(periphery) >= n:
                return self._rng.sample(periphery, n)
            remaining = [aid for aid in all_ids if aid not in periphery]
            extra = self._rng.sample(remaining, n - len(periphery))
            return periphery + extra
        else:
            # Default: random
            return self._rng.sample(all_ids, n)

    def _has_any_module_enabled(self) -> bool:
        """Return True if any AEGIS module toggle is enabled."""
        m = self._config.modules
        return any([m.scanner, m.broker, m.identity, m.behavior, m.recovery])

    def _init_shields(self) -> None:
        """Lazily import and initialize Shield instances.  Graceful on failure."""
        try:
            from aegis.shield import Shield  # type: ignore[import-not-found]
        except ImportError:
            # AEGIS package not available; engine runs without shields
            return

        for aid in self._agents:
            try:
                self._shields[aid] = Shield(
                    modules=self._config.modules,
                )
            except Exception:
                pass

    def _run_shield_scan(self, agent_id: str, text: str) -> dict[str, Any]:
        """Run a Shield scan for *agent_id*.  Returns empty dict on failure."""
        shield = self._shields.get(agent_id)
        if shield is None:
            return {}
        try:
            result = shield.scan(text)
            return result if isinstance(result, dict) else {}
        except Exception:
            return {}

    def _get_model_spec(self, model_name: str) -> ModelSpec:
        """Look up a ModelSpec by name, or return a default."""
        for spec in self._config.population.models:
            if spec.name == model_name:
                return spec
        # Fallback if model name not found
        return ModelSpec(name=model_name, weight=1.0, base_susceptibility=0.2)

    def _count_statuses(self) -> dict[str, int]:
        """Count agents by status."""
        counts: dict[str, int] = {s.value: 0 for s in AgentStatus}
        for agent in self._agents.values():
            counts[agent.status.value] += 1
        return counts

    def _compute_r0(self) -> float:
        """Compute R0: average secondary infections per resolved agent.

        Resolved agents are those who are quarantined or recovered.
        If none are resolved yet, fall back to currently infected agents.
        """
        resolved = [
            a
            for a in self._agents.values()
            if a.status in (AgentStatus.QUARANTINED, AgentStatus.RECOVERED)
        ]
        if resolved:
            total = sum(a.secondary_infections for a in resolved)
            return total / len(resolved)

        # Fallback: use currently infected agents
        infected = [
            a
            for a in self._agents.values()
            if a.status == AgentStatus.INFECTED
        ]
        if infected:
            total = sum(a.secondary_infections for a in infected)
            return total / len(infected)

        return 0.0
