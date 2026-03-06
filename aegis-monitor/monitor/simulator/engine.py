"""Core simulation engine for the AEGIS epidemic simulator.

Drives a tick-based epidemic simulation across a contact graph of AI agents,
optionally integrating AEGIS Shield modules for detection measurement.
"""

from __future__ import annotations

import random
from dataclasses import asdict
from typing import Any

from monitor.contagion import (
    ContagionDetector,
    TopicClusterer,
    hamming_distance,
    hex_to_int,
)
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
        self._scanner: Any = None

        # Content hash integration
        self._topic_clusterer = TopicClusterer()
        self._contagion_detector = ContagionDetector()
        self._hash_available = False
        self._style_hasher: Any = None
        self._compute_profile_fn: Any = None
        try:
            from aegis.behavior.content_hash import StyleHasher
            from aegis.behavior.message_drift import MessageDriftDetector

            self._style_hasher = StyleHasher()
            self._compute_profile_fn = MessageDriftDetector.compute_profile
            self._hash_available = True
        except ImportError:
            pass

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

        # 3b. Assign per-agent AEGIS protection
        if self._has_any_module_enabled():
            for aid in agent_ids:
                if self._rng.random() < self._config.aegis_adoption_rate:
                    self._agents[aid].has_aegis = True

        # 4. Seed initial infections
        num_seeds = max(1, int(self._config.num_agents * self._config.initial_infected_pct))
        seed_ids = self._select_seeds(num_seeds)
        for sid in seed_ids:
            self._agents[sid].status = AgentStatus.INFECTED
            self._agents[sid].infection_tick = 0
            # Compute hash for seed agents
            if self._hash_available and self._corpus is not None:
                seed_payload = self._corpus.generate(self._rng)
                hash_hex = self._compute_hash(seed_payload.text)
                if hash_hex:
                    self._agents[sid].content_hash = hash_hex
                    self._topic_clusterer.update(sid, hash_hex)
                    self._contagion_detector.mark_compromised(sid, hash_hex)

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
        self._scanner = None
        self._topic_clusterer = TopicClusterer()
        self._contagion_detector = ContagionDetector()
        self._rng = random.Random(self._config.seed)
        self._state = SimState.IDLE

    # ------------------------------------------------------------------
    # Tick execution
    # ------------------------------------------------------------------

    def tick(self) -> TickSnapshot:
        """Execute one simulation tick.  Valid in RUNNING or READY state.

        If called from READY, auto-transitions to RUNNING first so that
        single-stepping immediately after generate works.
        """
        if self._state == SimState.READY:
            self._state = SimState.RUNNING
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

                # Compute content hash for payload
                hash_hex = self._compute_hash(payload.text)
                if hash_hex:
                    target.content_hash = hash_hex
                    self._topic_clusterer.update(target_id, hash_hex)

                # Run shield scan if target has AEGIS
                scan_result: dict[str, Any] = {}
                if target.has_aegis:
                    scan_result = self._run_shield_scan(target_id, payload.text)

                detected = scan_result.get("detected", False)

                # Record confusion matrix per technique
                for technique in TechniqueType:
                    present = technique in payload.techniques
                    # Shield blocks the entire message: if detected, all
                    # present techniques count as detected.
                    tech_detected = detected and present
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
                            # Mark newly infected agent as compromised
                            if hash_hex:
                                self._contagion_detector.mark_compromised(target_id, hash_hex)
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

                # Compute content hash for background payload
                bg_hash_hex = self._compute_hash(bg_payload.text)
                if bg_hash_hex:
                    agent.content_hash = bg_hash_hex
                    self._topic_clusterer.update(aid, bg_hash_hex)

                scan_result = {}
                if agent.has_aegis:
                    scan_result = self._run_shield_scan(aid, bg_payload.text)

                # Record confusion matrix (all techniques present=False)
                bg_detected = scan_result.get("detected", False)
                for technique in TechniqueType:
                    tick_confusion.record(
                        technique, present=False, detected=bg_detected
                    )
                    self._confusion.record(
                        technique, present=False, detected=bg_detected
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

        # Phase 4: Quarantine of infected agents (AEGIS only)
        # Quarantine is an AEGIS capability — agents without AEGIS have no
        # automated detection mechanism and stay infected until max_ticks.
        current_infected = [
            aid
            for aid, agent in self._agents.items()
            if agent.status == AgentStatus.INFECTED and agent.has_aegis
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

        # Compute cluster summary
        clusters = self._topic_clusterer.cluster()
        num_clusters = len(set(clusters.values())) if clusters else 0
        cluster_summary: dict[str, Any] = {"num_clusters": num_clusters}

        snapshot = TickSnapshot(
            tick=self._tick_count,
            counts=counts,
            r0=r0,
            confusion=tick_confusion,
            events=events,
            status_changes=status_changes,
            cluster_summary=cluster_summary,
        )
        self._snapshots.append(snapshot)

        # Terminal condition check
        num_infected = counts.get(AgentStatus.INFECTED.value, 0)
        if num_infected == 0 or self._tick_count >= self._config.max_ticks:
            self._state = SimState.COMPLETED

        snapshot.state = self._state.value
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
                "has_aegis": agent.has_aegis,
                "content_hash": agent.content_hash,
            }
            for agent in self._agents.values()
        ]

    def get_embedding_entries(self) -> list[dict[str, Any]]:
        """Return per-agent embedding entries with top-5 nearest neighbors."""
        agents_with_hashes = [
            (aid, agent)
            for aid, agent in self._agents.items()
            if agent.content_hash is not None
        ]
        if not agents_with_hashes:
            return []

        # Pre-compute int hashes for distance calculations
        hash_ints: dict[str, int] = {}
        for aid, agent in agents_with_hashes:
            hash_ints[aid] = hex_to_int(agent.content_hash)  # type: ignore[arg-type]

        # Get cluster assignments
        clusters = self._topic_clusterer.cluster()

        entries: list[dict[str, Any]] = []
        agent_list = list(hash_ints.keys())

        for aid in agent_list:
            agent = self._agents[aid]
            h = hash_ints[aid]

            # Compute distances to all other agents with hashes
            distances: list[tuple[str, int]] = []
            for other_id in agent_list:
                if other_id == aid:
                    continue
                d = hamming_distance(h, hash_ints[other_id])
                distances.append((other_id, d))

            # Sort by distance, take top 5
            distances.sort(key=lambda x: x[1])
            neighbors = [
                {
                    "agent_id": other_id,
                    "distance": dist,
                    "status": self._agents[other_id].status.value,
                    "hash": self._agents[other_id].content_hash[:12] + "..."
                    if self._agents[other_id].content_hash
                    else "",
                }
                for other_id, dist in distances[:5]
            ]

            # Contagion score
            contagion_score = self._contagion_detector.check(
                aid, agent.content_hash or ""
            )

            entries.append(
                {
                    "agent_id": aid,
                    "hash": agent.content_hash,
                    "status": agent.status.value,
                    "cluster_id": clusters.get(aid, -1),
                    "contagion_score": round(contagion_score, 4),
                    "neighbors": neighbors,
                }
            )

        return entries

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_hash(self, text: str) -> str | None:
        """Compute a 32-char hex content hash for *text*, or None if unavailable."""
        if not self._hash_available:
            return None
        try:
            profile = self._compute_profile_fn(text)
            hash_int = self._style_hasher.hash(profile)
            return f"{hash_int:032x}"
        except Exception:
            return None

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
        """Initialize a shared Scanner instance for AEGIS detection.

        Uses a single Scanner rather than per-agent Shield instances
        since the simulator only needs stateless pattern-matching scans.
        """
        if not self._config.modules.scanner:
            return
        try:
            from aegis.core.config import AegisConfig  # type: ignore[import-not-found]
            from aegis.scanner import Scanner  # type: ignore[import-not-found]
        except ImportError:
            return

        try:
            cfg = AegisConfig()
            st = self._config.modules.scanner_toggles
            cfg.scanner.pattern_matching = st.pattern_matching
            cfg.scanner.semantic_analysis = st.semantic_analysis
            cfg.scanner.sensitivity = self._config.modules.sensitivity
            cfg.scanner.confidence_threshold = self._config.modules.confidence_threshold
            self._scanner = Scanner(config=cfg)
        except Exception:
            pass

    def _run_shield_scan(self, agent_id: str, text: str) -> dict[str, Any]:
        """Run a Scanner scan for *agent_id*.  Returns empty dict on failure."""
        if self._scanner is None:
            return {}
        agent = self._agents.get(agent_id)
        if agent is None or not agent.has_aegis:
            return {}
        try:
            result = self._scanner.scan_input(text)
            return {
                "detected": result.is_threat,
                "threat_score": result.threat_score,
            }
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
