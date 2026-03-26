"""Cross-agent coordination detection inspired by Clio's aggregate pattern analysis.

Clio's core insight is that patterns invisible in individual conversations
become visible in aggregate.  This module applies the same principle to
multi-agent security: coordinated attacks that look like isolated anomalies
per-agent become detectable when comparing behavioral patterns across agents.

Three detection signals:
1. Synchronized drift: multiple agents drifting simultaneously
2. Content convergence: previously diverse agents converging on the same topic
3. Behavioral mimicry: unrelated agents developing similar fingerprints

No ML dependencies required — uses pure statistical analysis.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CoordinationAlert:
    """Alert for detected coordinated cross-agent activity."""

    alert_type: str  # "synchronized_drift", "content_convergence", "behavioral_mimicry"
    agent_ids: list[str]
    confidence: float  # 0.0–1.0
    description: str
    timestamp: float = field(default_factory=time.time)
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "alert_type": self.alert_type,
            "agent_ids": self.agent_ids,
            "confidence": round(self.confidence, 3),
            "description": self.description,
            "timestamp": self.timestamp,
            "details": self.details,
        }


@dataclass
class CoordinationConfig:
    """Configuration for coordination detection."""

    min_agents: int = 3  # minimum agents for a coordination signal
    drift_window_seconds: float = 300.0  # 5-minute window for synchronized drift
    drift_threshold: float = 0.5  # minimum drift score to count
    convergence_hamming_threshold: int = 16  # bits — hashes within this distance converge
    mimicry_similarity_threshold: float = 0.8  # fingerprint hash similarity threshold
    max_snapshots_per_agent: int = 50


@dataclass
class _AgentSnapshot:
    """Point-in-time behavioral snapshot from a heartbeat."""

    timestamp: float
    fingerprint_hash: str
    drift_score: float
    content_hash: str


class CoordinationDetector:
    """Detects coordinated behavioral patterns across multiple agents.

    Inspired by Clio's aggregate pattern detection: patterns invisible
    in individual agent analysis become visible when comparing across agents.
    """

    def __init__(self, config: CoordinationConfig | None = None) -> None:
        self._config = config or CoordinationConfig()
        self._snapshots: dict[str, deque[_AgentSnapshot]] = {}
        self._drift_events: deque[tuple[float, str, float]] = deque(maxlen=5000)
        self._alerts: deque[CoordinationAlert] = deque(maxlen=200)

    def record_heartbeat(
        self,
        agent_id: str,
        fingerprint_hash: str = "",
        drift_score: float = 0.0,
        content_hash: str = "",
    ) -> None:
        """Record a behavioral snapshot from an agent heartbeat."""
        now = time.time()
        snapshot = _AgentSnapshot(
            timestamp=now,
            fingerprint_hash=fingerprint_hash,
            drift_score=drift_score,
            content_hash=content_hash,
        )

        if agent_id not in self._snapshots:
            self._snapshots[agent_id] = deque(
                maxlen=self._config.max_snapshots_per_agent
            )
        self._snapshots[agent_id].append(snapshot)

        # Record drift event if above threshold
        if drift_score >= self._config.drift_threshold:
            self._drift_events.append((now, agent_id, drift_score))

    def detect_coordination(self) -> list[CoordinationAlert]:
        """Analyze cross-agent patterns for coordinated activity.

        Returns new alerts detected since last call.
        """
        alerts: list[CoordinationAlert] = []

        alerts.extend(self._detect_synchronized_drift())
        alerts.extend(self._detect_content_convergence())
        alerts.extend(self._detect_behavioral_mimicry())

        for alert in alerts:
            self._alerts.append(alert)
        return alerts

    def get_recent_alerts(self, max_age_seconds: float = 3600.0) -> list[dict]:
        """Return recent alerts as dicts for API consumption."""
        cutoff = time.time() - max_age_seconds
        return [
            a.to_dict() for a in self._alerts if a.timestamp >= cutoff
        ]

    # ------------------------------------------------------------------
    # Signal 1: Synchronized drift
    # ------------------------------------------------------------------

    def _detect_synchronized_drift(self) -> list[CoordinationAlert]:
        """Detect multiple agents drifting within the same time window.

        Clio parallel: coordinated abuse detection — multiple accounts
        exhibiting anomalous behavior simultaneously suggests orchestration.
        """
        now = time.time()
        window = self._config.drift_window_seconds
        cutoff = now - window
        min_agents = self._config.min_agents

        # Collect agents that drifted within the window
        recent: dict[str, float] = {}  # agent_id → max drift score
        for ts, agent_id, score in self._drift_events:
            if ts >= cutoff:
                if agent_id not in recent or score > recent[agent_id]:
                    recent[agent_id] = score

        if len(recent) < min_agents:
            return []

        agent_ids = sorted(recent.keys())
        mean_drift = sum(recent.values()) / len(recent)
        confidence = min(1.0, (len(recent) / min_agents) * 0.5 + mean_drift * 0.5)

        return [CoordinationAlert(
            alert_type="synchronized_drift",
            agent_ids=agent_ids,
            confidence=confidence,
            description=(
                f"{len(agent_ids)} agents showed behavioral drift within "
                f"{window:.0f}s window (mean drift: {mean_drift:.2f})"
            ),
            details={
                "agent_drift_scores": recent,
                "window_seconds": window,
            },
        )]

    # ------------------------------------------------------------------
    # Signal 2: Content convergence
    # ------------------------------------------------------------------

    def _detect_content_convergence(self) -> list[CoordinationAlert]:
        """Detect agents converging on the same content hash.

        Clio parallel: topic clustering revealing coordinated campaigns —
        multiple independent users suddenly producing the same kind of content.
        """
        min_agents = self._config.min_agents
        threshold = self._config.convergence_hamming_threshold

        # Get latest content hash per agent
        latest_hashes: dict[str, str] = {}
        for agent_id, snaps in self._snapshots.items():
            if snaps:
                h = snaps[-1].content_hash
                if h:
                    latest_hashes[agent_id] = h

        if len(latest_hashes) < min_agents:
            return []

        # Group agents by similar content hashes (union-find on Hamming distance)
        agents = list(latest_hashes.keys())
        groups: list[set[str]] = []

        for i, a1 in enumerate(agents):
            found = False
            for group in groups:
                # Check if a1 is close to any member of the group
                for member in group:
                    dist = _hamming_hex(latest_hashes[a1], latest_hashes[member])
                    if dist is not None and dist <= threshold:
                        group.add(a1)
                        found = True
                        break
                if found:
                    break
            if not found:
                groups.append({a1})

        alerts: list[CoordinationAlert] = []
        for group in groups:
            if len(group) >= min_agents:
                agent_list = sorted(group)
                confidence = min(1.0, len(group) / (min_agents * 2))
                alerts.append(CoordinationAlert(
                    alert_type="content_convergence",
                    agent_ids=agent_list,
                    confidence=confidence,
                    description=(
                        f"{len(group)} agents converged on similar content hashes "
                        f"(Hamming distance ≤ {threshold} bits)"
                    ),
                    details={
                        "content_hashes": {
                            a: latest_hashes[a] for a in agent_list
                        },
                    },
                ))

        return alerts

    # ------------------------------------------------------------------
    # Signal 3: Behavioral mimicry
    # ------------------------------------------------------------------

    def _detect_behavioral_mimicry(self) -> list[CoordinationAlert]:
        """Detect agents developing identical behavioral fingerprints.

        Clio parallel: usage pattern clustering — discovering that unrelated
        users are behaving identically suggests automation or coordination.
        """
        min_agents = self._config.min_agents

        # Get latest fingerprint hash per agent
        latest_fp: dict[str, str] = {}
        for agent_id, snaps in self._snapshots.items():
            if snaps:
                h = snaps[-1].fingerprint_hash
                if h:
                    latest_fp[agent_id] = h

        if len(latest_fp) < min_agents:
            return []

        # Group by identical fingerprint hashes
        fp_groups: dict[str, list[str]] = defaultdict(list)
        for agent_id, fp_hash in latest_fp.items():
            fp_groups[fp_hash].append(agent_id)

        alerts: list[CoordinationAlert] = []
        for fp_hash, agent_ids in fp_groups.items():
            if len(agent_ids) >= min_agents:
                confidence = min(1.0, len(agent_ids) / (min_agents * 2))
                alerts.append(CoordinationAlert(
                    alert_type="behavioral_mimicry",
                    agent_ids=sorted(agent_ids),
                    confidence=confidence,
                    description=(
                        f"{len(agent_ids)} agents share identical behavioral "
                        f"fingerprint ({fp_hash[:16]}...)"
                    ),
                    details={"fingerprint_hash": fp_hash},
                ))

        return alerts


def _hamming_hex(a: str, b: str) -> int | None:
    """Hamming distance between two hex-encoded hashes."""
    try:
        int_a = int(a, 16)
        int_b = int(b, 16)
        return bin(int_a ^ int_b).count("1")
    except (ValueError, TypeError):
        return None
