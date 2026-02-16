"""Semantic clustering of threat events using UMAP + HDBSCAN.

Operates on structured metadata (not raw content) to maintain privacy.
ML dependencies are optional — the module degrades gracefully if missing.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


class ThreatClusterer:
    """Clusters threat events by semantic similarity of their metadata."""

    def __init__(self) -> None:
        self._embedder = None
        self._event_ids: list[str] = []
        self._texts: list[str] = []
        self._embeddings: np.ndarray | None = None
        self._labels: np.ndarray | None = None

    def _ensure_embedder(self) -> bool:
        """Lazy-load the sentence transformer model."""
        if self._embedder is not None:
            return True
        try:
            from sentence_transformers import SentenceTransformer

            self._embedder = SentenceTransformer("all-MiniLM-L6-v2")
            return True
        except ImportError:
            logger.warning(
                "sentence-transformers not installed. "
                "Install aegis-monitor[ml] for clustering support."
            )
            return False

    def add_event(self, event_id: str, metadata_text: str) -> None:
        """Add a threat event for clustering.

        Args:
            event_id: Unique identifier for the event.
            metadata_text: Structured metadata string (NOT raw user content).
        """
        self._event_ids.append(event_id)
        self._texts.append(metadata_text)
        # Invalidate cached results
        self._labels = None

    def refit(self) -> bool:
        """Re-compute embeddings and cluster assignments.

        Returns True if clustering succeeded, False if dependencies are
        missing or insufficient data.
        """
        if len(self._texts) < 2:
            return False

        if not self._ensure_embedder():
            return False

        try:
            import hdbscan
            import umap
        except ImportError:
            logger.warning(
                "umap-learn or hdbscan not installed. "
                "Install aegis-monitor[ml] for clustering support."
            )
            return False

        try:
            self._embeddings = self._embedder.encode(
                self._texts, show_progress_bar=False
            )

            n_neighbors = min(15, len(self._texts) - 1)
            reducer = umap.UMAP(
                n_components=min(5, len(self._texts) - 1),
                n_neighbors=max(2, n_neighbors),
                random_state=42,
            )
            reduced = reducer.fit_transform(self._embeddings)

            clusterer = hdbscan.HDBSCAN(
                min_cluster_size=max(2, len(self._texts) // 10),
                min_samples=1,
            )
            self._labels = clusterer.fit_predict(reduced)
            return True
        except Exception:
            logger.debug("Clustering failed", exc_info=True)
            return False

    def get_clusters(self) -> dict[int, list[str]]:
        """Return cluster_id → list of event_ids mapping.

        Cluster -1 contains unclustered noise points.
        """
        if self._labels is None:
            return {}

        clusters: dict[int, list[str]] = {}
        for eid, label in zip(self._event_ids, self._labels):
            label_int = int(label)
            clusters.setdefault(label_int, []).append(eid)
        return clusters

    def get_cluster_info(self) -> list[dict[str, Any]]:
        """Return summary info per cluster for dashboard display."""
        clusters = self.get_clusters()
        info = []
        for cid, event_ids in sorted(clusters.items()):
            if cid == -1:
                label = "Unclustered"
            else:
                label = f"Strain {cid}"
            info.append({
                "cluster_id": cid,
                "label": label,
                "event_count": len(event_ids),
                "event_ids": event_ids,
            })
        return info

    @property
    def event_count(self) -> int:
        return len(self._event_ids)
