"""Core simulation engine for the AEGIS epidemic simulator.

Drives a tick-based epidemic simulation across a contact graph of AI agents,
optionally integrating AEGIS Shield modules for detection measurement.
"""

from __future__ import annotations

import random
from dataclasses import asdict
from typing import Any

import numpy as np

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
        self._seed_ids: set[str] = set()

        # Content hash integration — SemanticHasher (384-dim sentence
        # embeddings) for content fingerprinting and cluster analysis.
        self._topic_clusterer = TopicClusterer(threshold=46, min_samples=2)
        self._contagion_detector = ContagionDetector()
        self._next_stable_cluster_id: int = 0
        self._stable_clusters: dict[int, dict[str, Any]] = {}
        self._hash_available = False
        self._semantic_hasher: Any = None
        try:
            from aegis.behavior.content_hash import SemanticHasher

            self._semantic_hasher = SemanticHasher()
            # Eagerly verify that sentence-transformers is importable so we
            # don't silently produce empty hashes for the entire simulation.
            self._semantic_hasher._ensure_model()
            self._hash_available = True
        except ImportError as exc:
            import warnings

            warnings.warn(
                f"Embedding-based content hashing is unavailable: {exc}. "
                "Content hashes, topic velocity, and cluster analysis will "
                "be disabled for this simulation run.",
                stacklevel=2,
            )

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

        # 3c. Assign sentinel agents (highest-degree nodes preferred)
        if self._config.num_sentinels > 0:
            self._assign_sentinels()

        # 4. Seed initial infections
        num_seeds = max(1, int(self._config.num_agents * self._config.initial_infected_pct))
        seed_ids = self._select_seeds(num_seeds)
        self._seed_ids = set(seed_ids)
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
        self._scanner = None
        self._seed_ids.clear()
        self._topic_clusterer = TopicClusterer(threshold=46, min_samples=2)
        self._contagion_detector = ContagionDetector()
        self._next_stable_cluster_id = 0
        self._stable_clusters.clear()
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
        transmission_attempts: list[dict[str, Any]] = []
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
                    target.last_payload_text = payload.text
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
                            transmission_attempts.append(
                                {"source": aid, "target": target_id, "success": True}
                            )
                        else:
                            # Susceptibility roll failed
                            transmission_attempts.append(
                                {"source": aid, "target": target_id, "success": False, "blocked_by": "natural"}
                            )
                    elif not payload.is_benign and TechniqueType.WORM_PROPAGATION in payload.techniques:
                        # Worm payload was blocked by AEGIS detection
                        transmission_attempts.append(
                            {"source": aid, "target": target_id, "success": False, "blocked_by": "aegis"}
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
                    agent.last_payload_text = bg_payload.text
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

        # Phase 3b: Sentinel-driven recovery
        # Sentinel agents observe their neighbors. When an infected neighbor
        # is detected, the sentinel attempts dendritic processing (strip and
        # re-scan). Successful neutralization provokes direct recovery;
        # failed neutralization (re-scan gate drops content) escalates to
        # quarantine instead. This models the immunological role of dendritic
        # cells presenting processed antigens to provoke adaptive recovery.
        sentinel_ids = [
            aid
            for aid, agent in self._agents.items()
            if agent.is_sentinel and agent.status in (AgentStatus.CLEAN, AgentStatus.RECOVERED)
        ]
        for sentinel_id in sentinel_ids:
            neighbors = self._graph.get_neighbors(sentinel_id)
            for target_id in neighbors:
                target = self._agents[target_id]
                if target.status != AgentStatus.INFECTED:
                    continue

                # The sentinel observes the infected agent's last payload
                payload_text = target.last_payload_text or ""
                if not payload_text:
                    continue

                # Run scanner detection on the payload
                scan_result = self._run_shield_scan(sentinel_id, payload_text)
                if not scan_result.get("detected", False):
                    continue

                threat_score = scan_result.get("threat_score", 0.0)

                # Simulate dendritic processing with re-scan gate.
                # A successful re-scan (content passes) means the sentinel
                # can safely neutralize the injection → recovery.
                # A failed re-scan (content dropped) means residual danger
                # → quarantine instead.
                rescan_result = self._run_shield_scan(sentinel_id, payload_text)
                rescan_score = rescan_result.get("threat_score", 0.0)
                rescan_threshold = 0.5 * threat_score  # mirrors DEFAULT_RESCAN_RATIO

                # Probabilistic recovery (not guaranteed)
                if rescan_score < rescan_threshold and not rescan_result.get("detected", False):
                    # Re-scan gate passed: sentinel neutralized the payload
                    if self._rng.random() < self._config.sentinel_recovery_prob:
                        target.status = AgentStatus.RECOVERED
                        target.recovery_tick = self._tick_count
                        status_changes.append({
                            "agent_id": target_id,
                            "from": AgentStatus.INFECTED.value,
                            "to": AgentStatus.RECOVERED.value,
                            "tick": self._tick_count,
                            "sentinel": sentinel_id,
                            "mechanism": "dendritic_recovery",
                        })
                else:
                    # Re-scan gate tripped: escalate to quarantine
                    if self._rng.random() < self._config.sentinel_recovery_prob:
                        target.status = AgentStatus.QUARANTINED
                        target.quarantine_tick = self._tick_count
                        target.detected_status = AgentStatus.QUARANTINED
                        status_changes.append({
                            "agent_id": target_id,
                            "from": AgentStatus.INFECTED.value,
                            "to": AgentStatus.QUARANTINED.value,
                            "tick": self._tick_count,
                            "sentinel": sentinel_id,
                            "mechanism": "dendritic_quarantine",
                        })

        # Phase 4: Quarantine of infected agents (AEGIS only)
        # Quarantine is an AEGIS capability — agents without AEGIS have no
        # automated detection mechanism and stay infected until max_ticks.
        #
        # Detection probability scales with configured parameters:
        #   - sensitivity: higher → higher ceiling on detection probability
        #   - drift_threshold: lower → faster ramp (quicker MTTQ)
        sensitivity = self._config.modules.sensitivity
        drift_threshold = self._config.modules.drift_threshold
        # Ramp rate: inversely proportional to drift_threshold.
        # At default 2.5σ → 0.028/tick; at 3.0σ → 0.023/tick.
        ramp_rate = 0.07 / max(drift_threshold, 0.5)
        # Ceiling: sensitivity directly controls max detection probability.
        # Default sensitivity 0.5 → ceiling 0.5.
        detection_ceiling = max(0.05, min(0.95, sensitivity))
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
            detection_prob = min(detection_ceiling, ticks_infected * ramp_rate)
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

        # Reproduction metrics are derived from realized transmission events.
        seed_r = self._compute_seed_r()
        re = self._compute_running_re()

        # Compute cluster summary
        clusters = self._topic_clusterer.cluster()
        num_clusters = len(set(clusters.values())) if clusters else 0
        cluster_summary: dict[str, Any] = {"num_clusters": num_clusters}

        snapshot = TickSnapshot(
            tick=self._tick_count,
            counts=counts,
            seed_r=seed_r,
            re=re,
            confusion=tick_confusion,
            events=events,
            status_changes=status_changes,
            transmission_attempts=transmission_attempts,
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
                "is_sentinel": agent.is_sentinel,
                "content_hash": agent.content_hash,
            }
            for agent in self._agents.values()
        ]

    def get_embedding_entries(self) -> dict[str, Any]:
        """Return per-agent embedding entries with top-5 nearest neighbors
        and cluster centroid information."""
        agents_with_hashes = [
            (aid, agent)
            for aid, agent in self._agents.items()
            if agent.content_hash is not None
        ]
        if not agents_with_hashes:
            self._update_stable_clusters()
            return {"entries": [], "centroids": self._build_centroid_list()}

        # Update stable clusters and get agent -> stable_id mapping
        stable_map = self._update_stable_clusters()

        # Pre-compute int hashes for distance calculations
        hash_ints: dict[str, int] = {}
        for aid, agent in agents_with_hashes:
            hash_ints[aid] = hex_to_int(agent.content_hash)  # type: ignore[arg-type]

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
                    "cluster_id": stable_map.get(aid, -1),
                    "contagion_score": round(contagion_score, 4),
                    "neighbors": neighbors,
                }
            )

        return {
            "entries": entries,
            "centroids": self._build_centroid_list(),
        }

    def get_cluster_centroids(self) -> list[dict[str, Any]]:
        """Return representative centroid info for all known clusters.

        Clusters persist with stable auto-incrementing IDs even after
        their members change status or the cluster dissolves.
        """
        self._update_stable_clusters()
        return self._build_centroid_list()

    def _build_distance_matrix(
        self,
    ) -> tuple[list[str], list[int], "np.ndarray"] | None:
        """Build pairwise Hamming distance matrix for agents with hashes.

        Returns ``(ids, hash_ints, dist_matrix)`` or ``None`` when no
        agents have hashes.
        """
        agents_with_hashes = [
            (aid, agent)
            for aid, agent in self._agents.items()
            if agent.content_hash is not None
        ]
        if not agents_with_hashes:
            return None

        ids: list[str] = []
        hash_ints: list[int] = []
        for aid, agent in agents_with_hashes:
            ids.append(aid)
            hash_ints.append(hex_to_int(agent.content_hash))  # type: ignore[arg-type]

        n = len(ids)
        dist = np.zeros((n, n), dtype=np.float64)
        for i in range(n):
            for j in range(i + 1, n):
                d = hamming_distance(hash_ints[i], hash_ints[j])
                dist[i, j] = d
                dist[j, i] = d

        return ids, hash_ints, dist

    def get_scatter_data(self) -> list[dict[str, Any]]:
        """Project agent content hashes to 2D via classical MDS on pairwise
        Hamming distances.  Returns a list of point dicts suitable for a
        scatter chart."""
        result = self._build_distance_matrix()
        if result is None:
            return []

        ids, hash_ints, dist = result
        n = len(ids)
        stable_map = self._update_stable_clusters()

        # Classical MDS: double-center the squared distance matrix
        D2 = dist ** 2
        H = np.eye(n) - np.ones((n, n)) / n
        B = -0.5 * H @ D2 @ H

        eigvals, eigvecs = np.linalg.eigh(B)

        # Take the top 2 eigenvalues (they come sorted ascending from eigh)
        idx = np.argsort(eigvals)[::-1]
        coords = np.zeros((n, 2), dtype=np.float64)
        for dim in range(min(2, n)):
            lam = max(eigvals[idx[dim]], 0.0)
            coords[:, dim] = eigvecs[:, idx[dim]] * np.sqrt(lam)

        # Pre-compute centroid hashes for distance calculation
        centroid_hashes: dict[int, int] = {}
        for data in self._stable_clusters.values():
            if data["active"] and data["centroid_agent_id"]:
                cagent = self._agents.get(data["centroid_agent_id"])
                if cagent and cagent.content_hash:
                    centroid_hashes[data["cluster_id"]] = hex_to_int(
                        cagent.content_hash
                    )

        points: list[dict[str, Any]] = []
        for i, aid in enumerate(ids):
            agent = self._agents[aid]
            cluster_id = stable_map.get(aid, -1)
            is_centroid = False
            dist_from_centroid: int | None = None

            # Check if this agent is a centroid
            for data in self._stable_clusters.values():
                if data["centroid_agent_id"] == aid:
                    is_centroid = True
                    break

            # Compute distance from cluster centroid
            if cluster_id in centroid_hashes:
                dist_from_centroid = hamming_distance(
                    hash_ints[i], centroid_hashes[cluster_id]
                )

            points.append({
                "agent_id": aid,
                "x": float(coords[i, 0]),
                "y": float(coords[i, 1]),
                "status": agent.status.value,
                "cluster_id": cluster_id,
                "is_centroid": is_centroid,
                "distance_from_centroid": dist_from_centroid,
            })

        return points

    def _build_centroid_list(self) -> list[dict[str, Any]]:
        """Build the centroid response list from the stable cluster cache."""
        return [
            {
                "cluster_id": data["cluster_id"],
                "centroid_agent_id": data["centroid_agent_id"],
                "representative_text": data["representative_text"],
                "member_count": data["member_count"],
                "member_statuses": data["member_statuses"],
                "post_count": data.get("post_count", 0),
                "worm_count": data.get("worm_count", 0),
                "worm_entries": data.get("worm_entries", []),
                "active": data["active"],
                "formed_tick": data.get("formed_tick"),
                "dissolved_tick": data.get("dissolved_tick"),
            }
            for data in sorted(
                self._stable_clusters.values(),
                key=lambda d: d["cluster_id"],
            )
        ]

    def _update_stable_clusters(self) -> dict[str, int]:
        """Run raw clustering, match results to stable IDs, update cache.

        Returns ``{agent_id: stable_cluster_id}``.
        """
        raw_clusters = self._topic_clusterer.cluster()
        if not raw_clusters:
            for data in self._stable_clusters.values():
                if data["active"]:
                    data["active"] = False
                    data["dissolved_tick"] = self._tick_count
            return {}

        # Group agents by raw cluster ID
        raw_groups: dict[int, set[str]] = {}
        for aid, raw_cid in raw_clusters.items():
            raw_groups.setdefault(raw_cid, set()).add(aid)

        # Greedy matching: find best (highest Jaccard) pairing between
        # raw groups and existing stable clusters.
        candidates: list[tuple[float, int, int]] = []
        for raw_cid, raw_members in raw_groups.items():
            for stable_id, stable_data in self._stable_clusters.items():
                stable_members = stable_data["members"]
                intersection = len(raw_members & stable_members)
                union = len(raw_members | stable_members)
                jaccard = intersection / union if union > 0 else 0.0
                if jaccard > 0.3:
                    candidates.append((jaccard, raw_cid, stable_id))

        candidates.sort(key=lambda x: -x[0])

        matched_raw: set[int] = set()
        matched_stable: set[int] = set()
        raw_to_stable: dict[int, int] = {}

        for jaccard, raw_cid, stable_id in candidates:
            if raw_cid in matched_raw or stable_id in matched_stable:
                continue
            raw_to_stable[raw_cid] = stable_id
            matched_raw.add(raw_cid)
            matched_stable.add(stable_id)

        # Assign new stable IDs to unmatched raw groups
        for raw_cid in raw_groups:
            if raw_cid not in matched_raw:
                raw_to_stable[raw_cid] = self._next_stable_cluster_id
                self._next_stable_cluster_id += 1

        # Build agent -> stable cluster mapping
        agent_to_stable: dict[str, int] = {}
        for aid, raw_cid in raw_clusters.items():
            agent_to_stable[aid] = raw_to_stable[raw_cid]

        # Determine which stable clusters are still active this tick.
        # Any existing cluster not matched to a raw group dissolves.
        newly_dissolved = set(self._stable_clusters.keys()) - matched_stable
        for stable_id in newly_dissolved:
            data = self._stable_clusters[stable_id]
            if data["active"]:
                data["active"] = False
                data["dissolved_tick"] = self._tick_count

        # Update or create stable cluster entries
        for raw_cid, raw_members in raw_groups.items():
            stable_id = raw_to_stable[raw_cid]

            # Compute centroid (member closest to mean hash)
            member_hashes: list[tuple[str, int]] = []
            for aid in raw_members:
                agent = self._agents.get(aid)
                if agent and agent.content_hash:
                    member_hashes.append((aid, hex_to_int(agent.content_hash)))

            centroid_agent_id: str | None = None
            representative_text: str | None = None
            if member_hashes:
                num = len(member_hashes)
                mean_hash = 0
                for bit in range(128):
                    count = sum(1 for _, h in member_hashes if h & (1 << bit))
                    if count > num / 2:
                        mean_hash |= (1 << bit)

                best_aid = member_hashes[0][0]
                best_dist = hamming_distance(member_hashes[0][1], mean_hash)
                for aid, h in member_hashes[1:]:
                    d = hamming_distance(h, mean_hash)
                    if d < best_dist:
                        best_dist = d
                        best_aid = aid

                centroid_agent_id = best_aid
                centroid_agent = self._agents.get(best_aid)
                if centroid_agent and centroid_agent.last_payload_text:
                    representative_text = centroid_agent.last_payload_text

            # Collect known worm payloads from infected members
            worm_entries: list[dict[str, Any]] = []
            if member_hashes and centroid_agent_id:
                centroid_h = next(
                    h for a, h in member_hashes if a == centroid_agent_id
                )
                for aid_w in raw_members:
                    agent_w = self._agents.get(aid_w)
                    if (
                        agent_w
                        and agent_w.status
                        in (AgentStatus.INFECTED, AgentStatus.QUARANTINED)
                        and agent_w.last_payload_text
                        and aid_w != centroid_agent_id
                    ):
                        h_w = hex_to_int(agent_w.content_hash) if agent_w.content_hash else None
                        dist = hamming_distance(h_w, centroid_h) if h_w is not None else None
                        worm_entries.append({
                            "agent_id": aid_w,
                            "text": agent_w.last_payload_text,
                            "distance": dist,
                        })
                worm_entries.sort(key=lambda e: e["distance"] if e["distance"] is not None else 999)

            # Count current statuses and posts of cluster members
            status_counts: dict[str, int] = {}
            post_count = 0
            for aid in raw_members:
                agent = self._agents.get(aid)
                if agent:
                    s = agent.status.value
                    status_counts[s] = status_counts.get(s, 0) + 1
                    if agent.last_payload_text:
                        post_count += 1

            if stable_id in self._stable_clusters:
                entry = self._stable_clusters[stable_id]
                entry["members"] = raw_members
                entry["member_count"] = len(raw_members)
                entry["member_statuses"] = status_counts
                entry["post_count"] = post_count
                entry["worm_count"] = len(worm_entries)
                entry["worm_entries"] = worm_entries
                entry["active"] = True
                entry["dissolved_tick"] = None
                if centroid_agent_id:
                    entry["centroid_agent_id"] = centroid_agent_id
                if representative_text:
                    entry["representative_text"] = representative_text
            else:
                self._stable_clusters[stable_id] = {
                    "cluster_id": stable_id,
                    "members": raw_members,
                    "centroid_agent_id": centroid_agent_id,
                    "representative_text": representative_text,
                    "member_count": len(raw_members),
                    "member_statuses": status_counts,
                    "post_count": post_count,
                    "worm_count": len(worm_entries),
                    "worm_entries": worm_entries,
                    "active": True,
                    "formed_tick": self._tick_count,
                    "dissolved_tick": None,
                }

        return agent_to_stable

    def get_dendrogram_data(self) -> dict[str, Any]:
        """Compute hierarchical agglomerative clustering and return linkage
        data suitable for rendering a dendrogram on the client."""
        result = self._build_distance_matrix()
        if result is None:
            return {}

        ids, hash_ints, dist = result
        n = len(ids)
        if n < 2:
            return {}

        stable_map = self._update_stable_clusters()

        # Convert NxN to condensed form and compute linkage
        method = "average"
        try:
            from scipy.spatial.distance import squareform
            from scipy.cluster.hierarchy import linkage

            condensed = squareform(dist)
            Z = linkage(condensed, method="average")
        except ImportError:
            Z = self._single_linkage_fallback(dist)
            method = "single-fallback"

        leaves: list[dict[str, Any]] = []
        for i, aid in enumerate(ids):
            agent = self._agents[aid]
            is_worm = agent.status in (AgentStatus.INFECTED, AgentStatus.QUARANTINED)
            leaf: dict[str, Any] = {
                "agent_id": aid,
                "status": agent.status.value,
                "cluster_id": stable_map.get(aid, -1),
            }
            if is_worm and agent.last_payload_text:
                leaf["payload"] = agent.last_payload_text
            leaves.append(leaf)

        return {
            "labels": ids,
            "linkage": Z.tolist(),
            "leaves": leaves,
            "method": method,
        }

    @staticmethod
    def _single_linkage_fallback(dist: "np.ndarray") -> "np.ndarray":
        """Pure-numpy single-linkage producing a scipy-format linkage matrix.

        Uses dict-based distance tracking so we never need to resize numpy
        arrays during the merge loop.
        """
        n = dist.shape[0]
        # Track active cluster sizes
        sizes: dict[int, int] = {i: 1 for i in range(n)}
        # Pairwise distances keyed by (min_id, max_id)
        dists: dict[tuple[int, int], float] = {}
        for i in range(n):
            for j in range(i + 1, n):
                dists[(i, j)] = dist[i, j]

        Z = np.zeros((n - 1, 4), dtype=np.float64)
        next_id = n

        for step in range(n - 1):
            # Find the minimum distance pair
            min_key = min(dists, key=dists.__getitem__)
            min_dist = dists[min_key]
            a, b = min_key

            Z[step, 0] = a
            Z[step, 1] = b
            Z[step, 2] = min_dist
            Z[step, 3] = sizes[a] + sizes[b]

            # Collect all active cluster IDs except a and b
            active = set(sizes.keys()) - {a, b}

            # Compute distances from new cluster to every other active cluster
            new_dists: dict[tuple[int, int], float] = {}
            for c in active:
                key_ac = (min(a, c), max(a, c))
                key_bc = (min(b, c), max(b, c))
                d_ac = dists.get(key_ac, float("inf"))
                d_bc = dists.get(key_bc, float("inf"))
                d_new = min(d_ac, d_bc)  # single-linkage
                new_key = (min(next_id, c), max(next_id, c))
                new_dists[new_key] = d_new

            # Remove old entries involving a or b
            keys_to_remove = [
                k for k in dists if a in k or b in k
            ]
            for k in keys_to_remove:
                del dists[k]

            # Insert new cluster distances
            dists.update(new_dists)

            # Update sizes
            sizes[next_id] = sizes.pop(a) + sizes.pop(b)
            next_id += 1

        return Z

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_hash(self, text: str) -> str | None:
        """Compute a 32-char hex content hash for *text*, or None if unavailable."""
        if not self._hash_available:
            return None
        try:
            hash_int = self._semantic_hasher.hash(text)
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

    def _assign_sentinels(self) -> None:
        """Designate *num_sentinels* agents as sentinel nodes.

        Prefers high-degree (hub) nodes — sentinels placed at hubs can
        observe more neighbors, maximizing their recovery impact.
        Sentinel agents always have AEGIS enabled (they need the scanner).
        """
        assert self._graph is not None
        n = min(self._config.num_sentinels, len(self._agents))
        if n <= 0:
            return

        # Pick from highest-degree nodes
        hub_candidates = self._graph.get_hubs(top_n=n * 2)
        if len(hub_candidates) >= n:
            chosen = self._rng.sample(hub_candidates, n)
        else:
            remaining = [
                aid for aid in self._agents if aid not in hub_candidates
            ]
            extra = self._rng.sample(remaining, min(n - len(hub_candidates), len(remaining)))
            chosen = hub_candidates + extra

        for aid in chosen:
            self._agents[aid].is_sentinel = True
            self._agents[aid].has_aegis = True  # sentinels always have AEGIS

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

    def _compute_seed_r(self) -> float:
        """Return the realized mean offspring count for the initial seed cohort."""
        if not self._seed_ids:
            return 0.0

        seed_agents = [
            self._agents[aid]
            for aid in self._seed_ids
            if aid in self._agents
        ]
        if not seed_agents:
            return 0.0

        total_secondary = sum(agent.secondary_infections for agent in seed_agents)
        return total_secondary / len(seed_agents)

    def _compute_running_re(self) -> float:
        """Return the realized mean offspring count for agents with transmission exposure.

        Agents infected on the current tick have not yet had an opportunity to
        spread, so they are excluded until the next tick.
        """
        eligible_agents = [
            agent
            for agent in self._agents.values()
            if agent.infection_tick is not None and agent.infection_tick < self._tick_count
        ]
        if not eligible_agents:
            return 0.0

        total_secondary = sum(agent.secondary_infections for agent in eligible_agents)
        return total_secondary / len(eligible_agents)

