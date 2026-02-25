"""Contagion detection and topic clustering from LSH content hashes.

Uses DBSCAN with precomputed Hamming distance when scikit-learn is available
for density-based clustering that avoids transitive chaining.  Falls back to
union-find when sklearn is missing.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Shared utilities
# ------------------------------------------------------------------

def hamming_distance(a: int, b: int) -> int:
    """Return the Hamming distance (number of differing bits) between two ints."""
    return bin(a ^ b).count("1")


def hex_to_int(h: str) -> int:
    """Convert a hex string to an integer."""
    return int(h, 16)


# ------------------------------------------------------------------
# Union-Find (fallback when sklearn unavailable)
# ------------------------------------------------------------------

class _UnionFind:
    """Lightweight union-find (disjoint set) for clustering."""

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}
        self._rank: dict[str, int] = {}

    def find(self, x: str) -> str:
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]  # path compression
            x = self._parent[x]
        return x

    def union(self, x: str, y: str) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1


# ------------------------------------------------------------------
# Topic clusterer
# ------------------------------------------------------------------

_CLUSTER_PALETTE = [
    "#1abc9c", "#2ecc71", "#3498db", "#9b59b6",
    "#e74c3c", "#e67e22", "#f1c40f", "#1f77b4",
    "#ff7f0e", "#2ca02c", "#d62728", "#9467bd",
    "#8c564b", "#17becf", "#bcbd22", "#7f7f7f",
]


class TopicClusterer:
    """Clusters agents by content-hash similarity.

    Uses DBSCAN with a precomputed Hamming distance matrix when scikit-learn
    is installed.  DBSCAN avoids transitive chaining — agents only cluster if
    they share a dense neighbourhood, not merely because they're linked through
    a chain of pairwise-similar intermediaries.

    Falls back to union-find when sklearn is unavailable.

    Args:
        threshold: Maximum Hamming distance (out of 128 bits) for two hashes
            to be considered neighbours.  Default 16 (~87 % similarity).
        min_samples: DBSCAN ``min_samples`` — minimum neighbourhood density
            for a point to be a core point.  Default 1 (any neighbour pair
            forms a cluster).
    """

    def __init__(self, threshold: int = 16, min_samples: int = 1) -> None:
        self._threshold = threshold
        self._min_samples = min_samples
        self._hashes: dict[str, int] = {}  # agent_id -> latest hash int

    def update(self, agent_id: str, hash_hex: str) -> None:
        """Store the latest hash for an agent."""
        if not hash_hex:
            return
        self._hashes[agent_id] = hex_to_int(hash_hex)

    def cluster(self) -> dict[str, int]:
        """Return ``{agent_id: cluster_id}``.

        Tries DBSCAN first; falls back to union-find if sklearn is missing.
        """
        agents = list(self._hashes.keys())
        if not agents:
            return {}

        result = self._cluster_dbscan(agents)
        if result is not None:
            return result
        return self._cluster_union_find(agents)

    # -- DBSCAN backend (preferred) ------------------------------------------

    def _cluster_dbscan(self, agents: list[str]) -> dict[str, int] | None:
        """Cluster with DBSCAN on precomputed Hamming distance.  Returns None
        if sklearn is unavailable."""
        try:
            import numpy as np
            from sklearn.cluster import DBSCAN
        except ImportError:
            return None

        n = len(agents)
        # Build symmetric distance matrix
        dist = np.zeros((n, n), dtype=np.float64)
        for i in range(n):
            for j in range(i + 1, n):
                d = hamming_distance(self._hashes[agents[i]], self._hashes[agents[j]])
                dist[i, j] = d
                dist[j, i] = d

        db = DBSCAN(eps=self._threshold, min_samples=self._min_samples, metric="precomputed")
        labels = db.fit_predict(dist)

        # DBSCAN labels: -1 = noise.  Remap to non-negative sequential IDs,
        # assigning each noise point its own singleton cluster.
        label_map: dict[int, int] = {}
        next_id = 0
        result: dict[str, int] = {}
        for agent, label in zip(agents, labels):
            lab = int(label)
            if lab == -1:
                # Noise point → own cluster
                result[agent] = next_id
                next_id += 1
            else:
                if lab not in label_map:
                    label_map[lab] = next_id
                    next_id += 1
                result[agent] = label_map[lab]

        return result

    # -- Union-find fallback --------------------------------------------------

    def _cluster_union_find(self, agents: list[str]) -> dict[str, int]:
        """Cluster with union-find on Hamming distance (fallback)."""
        uf = _UnionFind()

        for i in range(len(agents)):
            uf.find(agents[i])  # ensure registered
            for j in range(i + 1, len(agents)):
                if hamming_distance(self._hashes[agents[i]], self._hashes[agents[j]]) <= self._threshold:
                    uf.union(agents[i], agents[j])

        root_to_id: dict[str, int] = {}
        result: dict[str, int] = {}
        for agent in agents:
            root = uf.find(agent)
            if root not in root_to_id:
                root_to_id[root] = len(root_to_id)
            result[agent] = root_to_id[root]

        return result

    def get_cluster_colors(self) -> dict[str, str]:
        """Return ``{agent_id: hex_color}`` based on cluster membership."""
        clusters = self.cluster()
        result: dict[str, str] = {}
        for agent_id, cluster_id in clusters.items():
            result[agent_id] = _CLUSTER_PALETTE[cluster_id % len(_CLUSTER_PALETTE)]
        return result


# ------------------------------------------------------------------
# Contagion detector
# ------------------------------------------------------------------

class ContagionDetector:
    """Detects contagion spread by comparing hashes against known-compromised agents.

    Combines two signals:

    1. **Hash proximity** — cosine-derived similarity between the agent's
       current content hash and the nearest known-compromised hash.
    2. **Topic velocity** — how abruptly the agent's topic changed.  A
       prompt injection snaps the topic instantly (high velocity), while
       organic dialogue drifts gradually (low velocity).

    The composite score amplifies proximity when velocity is high:
    ``composite = proximity * (1 + velocity_weight * velocity)``,
    clamped to [0, 1].
    """

    def __init__(
        self,
        alert_threshold: float = 0.85,
        velocity_weight: float = 0.5,
    ) -> None:
        self._alert_threshold = alert_threshold
        self._velocity_weight = velocity_weight
        self._compromised: dict[str, int] = {}  # agent_id -> hash int
        self._bits = 128

    def mark_compromised(self, agent_id: str, hash_hex: str) -> None:
        """Record the hash of a known-compromised agent."""
        if not hash_hex:
            return
        self._compromised[agent_id] = hex_to_int(hash_hex)

    def check(self, agent_id: str, hash_hex: str) -> float:
        """Return the similarity score to the nearest compromised hash.

        Score is ``1.0 - (hamming_distance / 128)``.  Returns 0.0 if there
        are no compromised hashes on file.
        """
        if not self._compromised or not hash_hex:
            return 0.0

        h = hex_to_int(hash_hex)
        min_dist = self._bits
        for comp_hash in self._compromised.values():
            d = hamming_distance(h, comp_hash)
            if d < min_dist:
                min_dist = d

        return 1.0 - (min_dist / self._bits)

    def check_with_velocity(
        self,
        agent_id: str,
        hash_hex: str,
        topic_velocity: float = 0.0,
    ) -> float:
        """Return a composite contagion score that factors in topic velocity.

        A high-velocity jump into a compromised-looking cluster is far more
        suspicious than gradually drifting near one.  The composite score
        amplifies hash proximity by the velocity:

            composite = proximity * (1 + velocity_weight * velocity)

        Clamped to [0.0, 1.0].

        Args:
            agent_id: The agent being checked.
            hash_hex: The agent's current content hash (32-char hex).
            topic_velocity: Rate of topic change in [0.0, 1.0].

        Returns:
            Composite contagion score in [0.0, 1.0].
        """
        proximity = self.check(agent_id, hash_hex)
        if proximity == 0.0:
            return 0.0
        composite = proximity * (1.0 + self._velocity_weight * topic_velocity)
        return min(composite, 1.0)
