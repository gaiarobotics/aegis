"""Contagion detection and topic clustering from LSH content hashes.

Uses DBSCAN with precomputed Hamming distance when scikit-learn is available
for density-based clustering that avoids transitive chaining.  Falls back to
union-find when sklearn is missing.
"""

from __future__ import annotations

import logging
from typing import Any

try:
    import numpy as np
except ImportError:  # pragma: no cover
    np = None  # type: ignore[assignment]

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

    def __init__(self, threshold: int = 16, min_samples: int = 3) -> None:
        self._threshold = threshold
        self._min_samples = min_samples
        self._hashes: dict[str, int] = {}  # agent_id -> latest hash int
        self._next_stable_cluster_id: int = 0
        self._stable_clusters: dict[int, dict] = {}
        self._update_counter: int = 0

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

    # -- Stable cluster tracking ------------------------------------------

    def update_stable_clusters(
        self, agent_statuses: dict[str, str],
    ) -> dict[str, int]:
        """Run raw clustering, match to stable IDs, compute centroids.

        Args:
            agent_statuses: ``{agent_id: status_string}`` where status is
                one of ``"active"``, ``"compromised"``, ``"quarantined"``.

        Returns:
            ``{agent_id: stable_cluster_id}``
        """
        raw_clusters = self.cluster()
        self._update_counter += 1

        if not raw_clusters:
            for data in self._stable_clusters.values():
                if data["active"]:
                    data["active"] = False
                    data["dissolved_at"] = self._update_counter
            return {}

        # Group agents by raw cluster ID
        raw_groups: dict[int, set[str]] = {}
        for aid, raw_cid in raw_clusters.items():
            raw_groups.setdefault(raw_cid, set()).add(aid)

        # Greedy Jaccard matching against existing stable clusters
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

        # New stable IDs for unmatched groups
        for raw_cid in raw_groups:
            if raw_cid not in matched_raw:
                raw_to_stable[raw_cid] = self._next_stable_cluster_id
                self._next_stable_cluster_id += 1

        # Agent -> stable cluster mapping
        agent_to_stable: dict[str, int] = {}
        for aid, raw_cid in raw_clusters.items():
            agent_to_stable[aid] = raw_to_stable[raw_cid]

        # Mark dissolved clusters
        newly_dissolved = set(self._stable_clusters.keys()) - matched_stable
        for stable_id in newly_dissolved:
            data = self._stable_clusters[stable_id]
            if data["active"]:
                data["active"] = False
                data["dissolved_at"] = self._update_counter

        # Update or create stable cluster entries
        for raw_cid, raw_members in raw_groups.items():
            stable_id = raw_to_stable[raw_cid]

            # Compute centroid (bit-wise majority vote -> closest agent)
            member_hashes: list[tuple[str, int]] = []
            for aid in raw_members:
                if aid in self._hashes:
                    member_hashes.append((aid, self._hashes[aid]))

            centroid_agent_id: str | None = None
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

            # Count statuses
            status_counts: dict[str, int] = {}
            compromised_count = 0
            for aid in raw_members:
                s = agent_statuses.get(aid, "active")
                status_counts[s] = status_counts.get(s, 0) + 1
                if s in ("compromised", "quarantined"):
                    compromised_count += 1

            if stable_id in self._stable_clusters:
                entry = self._stable_clusters[stable_id]
                entry["members"] = raw_members
                entry["member_count"] = len(raw_members)
                entry["member_statuses"] = status_counts
                entry["compromised_count"] = compromised_count
                entry["active"] = True
                entry["dissolved_at"] = None
                if centroid_agent_id:
                    entry["centroid_agent_id"] = centroid_agent_id
            else:
                self._stable_clusters[stable_id] = {
                    "cluster_id": stable_id,
                    "members": raw_members,
                    "centroid_agent_id": centroid_agent_id,
                    "member_count": len(raw_members),
                    "member_statuses": status_counts,
                    "compromised_count": compromised_count,
                    "active": True,
                    "formed_at": self._update_counter,
                    "dissolved_at": None,
                }

        return agent_to_stable

    def get_cluster_centroids(self) -> list[dict]:
        """Return sorted list of all clusters with centroid info."""
        return [
            {
                "cluster_id": data["cluster_id"],
                "centroid_agent_id": data.get("centroid_agent_id"),
                "member_count": data["member_count"],
                "member_statuses": data["member_statuses"],
                "compromised_count": data.get("compromised_count", 0),
                "active": data["active"],
                "formed_at": data.get("formed_at"),
                "dissolved_at": data.get("dissolved_at"),
            }
            for data in sorted(
                self._stable_clusters.values(),
                key=lambda d: d["cluster_id"],
            )
        ]

    def get_cluster_colors_stable(self) -> dict[str, str]:
        """Return ``{agent_id: hex_color}`` using stable cluster IDs."""
        result: dict[str, str] = {}
        for data in self._stable_clusters.values():
            if not data["active"]:
                continue
            color = _CLUSTER_PALETTE[data["cluster_id"] % len(_CLUSTER_PALETTE)]
            for aid in data["members"]:
                result[aid] = color
        return result

    # -- Distance matrix & dendrogram -------------------------------------

    def build_distance_matrix(
        self,
    ) -> tuple[list[str], list[int], Any] | None:
        """Build pairwise Hamming distance matrix.

        Returns ``(ids, hash_ints, dist_matrix)`` or ``None``.
        """
        if np is None or not self._hashes:
            return None

        ids = list(self._hashes.keys())
        hash_ints = [self._hashes[aid] for aid in ids]
        n = len(ids)
        if n < 2:
            return None

        dist = np.zeros((n, n), dtype=np.float64)
        for i in range(n):
            for j in range(i + 1, n):
                d = hamming_distance(hash_ints[i], hash_ints[j])
                dist[i, j] = d
                dist[j, i] = d

        return ids, hash_ints, dist

    def get_dendrogram_data(
        self,
        agent_statuses: dict[str, str],
        compromised_agents: set[str] | None = None,
    ) -> dict[str, Any]:
        """Compute hierarchical linkage data for dendrogram rendering.

        Args:
            agent_statuses: ``{agent_id: status}``
            compromised_agents: Set of compromised agent IDs.

        Returns:
            ``{labels, linkage, leaves, method}`` or empty dict.
        """
        result = self.build_distance_matrix()
        if result is None:
            return {}

        ids, hash_ints, dist = result
        n = len(ids)
        if n < 2:
            return {}

        compromised = compromised_agents or set()

        # Get stable cluster mapping
        # (use cached _stable_clusters to avoid re-clustering)
        stable_map: dict[str, int] = {}
        for data in self._stable_clusters.values():
            if data["active"]:
                for aid in data["members"]:
                    stable_map[aid] = data["cluster_id"]

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
            status = agent_statuses.get(aid, "active")
            leaf: dict[str, Any] = {
                "agent_id": aid,
                "status": status,
                "cluster_id": stable_map.get(aid, -1),
                "is_compromised": aid in compromised or status in ("compromised", "quarantined"),
            }
            leaves.append(leaf)

        return {
            "labels": ids,
            "linkage": Z.tolist(),
            "leaves": leaves,
            "method": method,
        }

    @staticmethod
    def _single_linkage_fallback(dist: Any) -> Any:
        """Pure-numpy single-linkage producing a scipy-format linkage matrix."""
        n = dist.shape[0]
        sizes: dict[int, int] = {i: 1 for i in range(n)}
        dists: dict[tuple[int, int], float] = {}
        for i in range(n):
            for j in range(i + 1, n):
                dists[(i, j)] = dist[i, j]

        Z = np.zeros((n - 1, 4), dtype=np.float64)
        next_id = n

        for step in range(n - 1):
            min_key = min(dists, key=dists.__getitem__)
            min_dist = dists[min_key]
            a, b = min_key

            Z[step, 0] = a
            Z[step, 1] = b
            Z[step, 2] = min_dist
            Z[step, 3] = sizes[a] + sizes[b]

            active = set(sizes.keys()) - {a, b}
            new_dists: dict[tuple[int, int], float] = {}
            for c in active:
                key_ac = (min(a, c), max(a, c))
                key_bc = (min(b, c), max(b, c))
                d_ac = dists.get(key_ac, float("inf"))
                d_bc = dists.get(key_bc, float("inf"))
                d_new = min(d_ac, d_bc)
                new_key = (min(next_id, c), max(next_id, c))
                new_dists[new_key] = d_new

            keys_to_remove = [k for k in dists if a in k or b in k]
            for k in keys_to_remove:
                del dists[k]

            dists.update(new_dists)
            sizes[next_id] = sizes.pop(a) + sizes.pop(b)
            next_id += 1

        return Z

    # -- Nearest neighbors -------------------------------------------------

    def get_nearest_neighbors(self, top_k: int = 5) -> dict[str, Any]:
        """Return per-agent nearest neighbors by Hamming distance.

        Returns ``{entries: [{agent_id, hash, neighbors: [{agent_id, distance, hash}]}]}``
        """
        agents = list(self._hashes.keys())
        if not agents:
            return {"entries": []}

        entries: list[dict[str, Any]] = []
        for aid in agents:
            h = self._hashes[aid]
            distances: list[tuple[str, int]] = []
            for other_id in agents:
                if other_id == aid:
                    continue
                d = hamming_distance(h, self._hashes[other_id])
                distances.append((other_id, d))

            distances.sort(key=lambda x: x[1])
            neighbors = [
                {
                    "agent_id": other_id,
                    "distance": dist,
                    "hash": f"{self._hashes[other_id]:032x}"[:12] + "...",
                }
                for other_id, dist in distances[:top_k]
            ]

            entries.append({
                "agent_id": aid,
                "hash": f"{h:032x}",
                "neighbors": neighbors,
            })

        return {"entries": entries}


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
