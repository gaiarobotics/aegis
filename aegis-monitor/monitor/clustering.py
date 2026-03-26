"""Semantic clustering of threat events using UMAP + HDBSCAN.

Operates on structured metadata (not raw content) to maintain privacy.
ML dependencies are optional — the module degrades gracefully if missing.

Clio-inspired enhancements:
- ThreatFacets: structured facet extraction for richer clustering input
- HierarchicalThreatClusterer: multi-level attack taxonomy (category → variant → strain)
- Cluster summarization: template-based, KeyBERT, or LLM-powered labeling
- Privacy thresholds: minimum events/agents before surfacing clusters
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Facet extraction (Clio technique #1)
# ---------------------------------------------------------------------------


@dataclass
class ThreatFacets:
    """Structured facets extracted from a threat event.

    Modeled after Clio's facet extraction: instead of passing raw metadata
    strings to the clusterer, we extract structured attributes that enable
    better clustering and hierarchical grouping.
    """

    attack_category: str = "unknown"
    target_layer: str = "unknown"  # input, output, memory, tool, identity
    evasion_techniques: list[str] = field(default_factory=list)
    severity: float = 0.0  # 0.0–1.0
    nk_verdict: str = "normal"  # normal, elevated, suspicious, hostile
    semantic_findings: list[str] = field(default_factory=list)
    agent_id: str = ""

    def to_clustering_text(self) -> str:
        """Produce rich text for embedding-based clustering."""
        parts = [
            f"attack:{self.attack_category}",
            f"layer:{self.target_layer}",
            f"severity:{self.severity:.1f}",
            f"verdict:{self.nk_verdict}",
        ]
        parts.extend(f"evasion:{t}" for t in self.evasion_techniques)
        parts.extend(f"finding:{f}" for f in self.semantic_findings)
        return " ".join(parts)


def extract_facets(data: dict[str, Any]) -> ThreatFacets:
    """Extract structured facets from a threat report payload.

    Maps scanner match categories, semantic findings, and NK verdicts
    into a ``ThreatFacets`` instance for clustering.

    Args:
        data: Raw threat report dict from ``/api/v1/reports/threat``.
    """
    # Determine attack category from scanner matches
    scanner_matches = data.get("scanner_matches", [])
    categories: list[str] = []
    evasion_techniques: list[str] = []
    for match in scanner_matches:
        cat = match.get("category", "") if isinstance(match, dict) else ""
        if cat:
            categories.append(cat)
        technique = match.get("evasion_technique", "") if isinstance(match, dict) else ""
        if technique:
            evasion_techniques.append(technique)

    # Infer attack category from the most common scanner category
    attack_category = "unknown"
    if categories:
        attack_category = Counter(categories).most_common(1)[0][0]
    elif data.get("threat_score", 0) > 0:
        # Fall back to NK verdict as a rough category
        verdict = data.get("nk_verdict", "")
        if verdict in ("hostile", "suspicious"):
            attack_category = "behavioral_anomaly"

    # Determine target layer from semantic findings
    semantic_findings = data.get("semantic_findings", [])
    if isinstance(semantic_findings, list):
        finding_names = [
            f.get("module", f) if isinstance(f, dict) else str(f)
            for f in semantic_findings
        ]
    else:
        finding_names = []

    target_layer = _infer_target_layer(finding_names, scanner_matches)

    # Detect evasion techniques from semantic findings
    evasion_map = {
        "unicode_attacks": "unicode",
        "encoding_attacks": "encoding",
        "boundary_violations": "boundary_spoofing",
        "conversation_injection": "turn_injection",
    }
    for finding in finding_names:
        if finding in evasion_map:
            evasion_techniques.append(evasion_map[finding])

    severity = min(1.0, max(0.0, float(data.get("threat_score", 0))))

    return ThreatFacets(
        attack_category=attack_category,
        target_layer=target_layer,
        evasion_techniques=list(set(evasion_techniques)),  # deduplicate
        severity=severity,
        nk_verdict=data.get("nk_verdict", "normal"),
        semantic_findings=finding_names,
        agent_id=data.get("agent_id", ""),
    )


def _infer_target_layer(
    finding_names: list[str], scanner_matches: list[Any]
) -> str:
    """Infer which layer an attack targets from findings and matches."""
    layer_signals: dict[str, int] = {}
    layer_map = {
        "boundary_violations": "input",
        "conversation_injection": "input",
        "privilege_escalation": "identity",
        "chain_propagation": "output",
        "unicode_attacks": "input",
        "encoding_attacks": "input",
    }
    for finding in finding_names:
        layer = layer_map.get(finding, "")
        if layer:
            layer_signals[layer] = layer_signals.get(layer, 0) + 1

    # Check scanner match categories for layer hints
    category_layer_map = {
        "memory_poisoning": "memory",
        "data_exfiltration": "output",
        "credential_extraction": "output",
        "prompt_injection": "input",
        "role_hijacking": "input",
        "instruction_override": "input",
        "chain_propagation": "output",
    }
    for match in scanner_matches:
        cat = match.get("category", "") if isinstance(match, dict) else ""
        layer = category_layer_map.get(cat, "")
        if layer:
            layer_signals[layer] = layer_signals.get(layer, 0) + 1

    if layer_signals:
        return max(layer_signals, key=layer_signals.get)  # type: ignore[arg-type]
    return "unknown"


# ---------------------------------------------------------------------------
# Cluster summarization (Clio technique #3)
# ---------------------------------------------------------------------------


def _severity_label(severity: float) -> str:
    """Convert severity float to human-readable label."""
    if severity >= 0.8:
        return "Critical"
    if severity >= 0.6:
        return "High"
    if severity >= 0.4:
        return "Medium"
    if severity >= 0.2:
        return "Low"
    return "Minimal"


def _most_common(items: list[str]) -> str:
    """Return the most common item, or 'unknown' if empty."""
    if not items:
        return "unknown"
    counter = Counter(items)
    return counter.most_common(1)[0][0]


class TemplateSummarizer:
    """Generates cluster labels from facet distributions (no ML required)."""

    def summarize(self, facets: list[ThreatFacets]) -> str:
        if not facets:
            return "Empty cluster"
        top_category = _most_common([f.attack_category for f in facets])
        all_evasions = [t for f in facets for t in f.evasion_techniques]
        top_evasion = _most_common(all_evasions) if all_evasions else ""
        top_layer = _most_common([f.target_layer for f in facets])
        mean_severity = sum(f.severity for f in facets) / len(facets)
        label = _severity_label(mean_severity)

        parts = [f"{label} {top_category}"]
        if top_layer != "unknown":
            parts.append(f"targeting {top_layer} layer")
        if top_evasion:
            parts.append(f"via {top_evasion}")
        return " ".join(parts)


class KeyBERTSummarizer:
    """Generates cluster labels using KeyBERT keyword extraction.

    Reuses the existing sentence-transformer model to avoid additional
    model loads.  Falls back to empty string if keybert is not installed.
    """

    def __init__(self, embedder: Any = None) -> None:
        self._kw_model: Any = None
        self._embedder = embedder
        self._available: bool | None = None

    def _ensure_model(self) -> bool:
        if self._available is False:
            return False
        if self._kw_model is not None:
            return True
        try:
            from keybert import KeyBERT

            self._kw_model = KeyBERT(model=self._embedder or "all-MiniLM-L6-v2")
            self._available = True
            return True
        except ImportError:
            logger.debug("keybert not installed — KeyBERT summarization unavailable")
            self._available = False
            return False

    def summarize(self, texts: list[str], top_n: int = 3) -> str:
        """Extract top-N keyphrases from combined cluster texts."""
        if not texts or not self._ensure_model():
            return ""
        combined = " ".join(texts)
        try:
            keywords = self._kw_model.extract_keywords(
                combined,
                keyphrase_ngram_range=(1, 3),
                use_mmr=True,
                diversity=0.5,
                top_n=top_n,
            )
            return " | ".join(kw for kw, _score in keywords)
        except Exception:
            logger.debug("KeyBERT extraction failed", exc_info=True)
            return ""


class LLMSummarizer:
    """Generates cluster labels using a local LLM endpoint.

    Supports Ollama and vLLM-compatible endpoints.
    """

    def __init__(self, endpoint: str = "", model: str = "") -> None:
        self._endpoint = endpoint
        self._model = model

    def summarize(self, facets: list[ThreatFacets]) -> str:
        """Generate a natural language summary via LLM."""
        if not self._endpoint or not facets:
            return ""
        try:
            import urllib.request
            import json as _json

            categories = Counter(f.attack_category for f in facets)
            techniques = Counter(t for f in facets for t in f.evasion_techniques)
            layers = Counter(f.target_layer for f in facets)

            prompt = (
                f"Summarize this cluster of {len(facets)} security threat events in "
                f"one concise phrase (under 15 words). "
                f"Attack categories: {dict(categories)}. "
                f"Evasion techniques: {dict(techniques)}. "
                f"Target layers: {dict(layers)}. "
                f"Do not include any specific agent IDs, content, or PII."
            )

            payload = _json.dumps({
                "model": self._model,
                "prompt": prompt,
                "stream": False,
            }).encode()

            req = urllib.request.Request(
                self._endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = _json.loads(resp.read())
            return result.get("response", result.get("text", ""))[:200].strip()
        except Exception:
            logger.debug("LLM summarization failed", exc_info=True)
            return ""


class ClusterSummarizer:
    """Unified summarizer that falls back gracefully: LLM → KeyBERT → template."""

    def __init__(
        self,
        strategy: str = "template",
        embedder: Any = None,
        llm_endpoint: str = "",
        llm_model: str = "",
    ) -> None:
        self._strategy = strategy
        self._template = TemplateSummarizer()
        self._keybert = KeyBERTSummarizer(embedder=embedder)
        self._llm = LLMSummarizer(endpoint=llm_endpoint, model=llm_model)

    def summarize(self, facets: list[ThreatFacets], texts: list[str] | None = None) -> str:
        """Generate a cluster label using the configured strategy with fallback."""
        if self._strategy == "llm":
            result = self._llm.summarize(facets)
            if result:
                return result
            # Fall through to keybert

        if self._strategy in ("llm", "keybert"):
            result = self._keybert.summarize(texts or [f.to_clustering_text() for f in facets])
            if result:
                return result
            # Fall through to template

        return self._template.summarize(facets)


# ---------------------------------------------------------------------------
# Privacy thresholds (Clio technique #6)
# ---------------------------------------------------------------------------


@dataclass
class PrivacyThresholds:
    """Minimum thresholds before surfacing cluster details.

    Inspired by Clio's statistical thresholds that require minimum unique
    users/conversations before exposing a topic cluster.
    """

    min_events_per_cluster: int = 3
    min_agents_per_cluster: int = 2
    redact_agent_ids_below: int = 5


def _apply_privacy_filter(
    cluster_info: list[dict[str, Any]],
    facets_by_event: dict[str, ThreatFacets],
    thresholds: PrivacyThresholds,
) -> list[dict[str, Any]]:
    """Filter and redact cluster info based on privacy thresholds."""
    filtered = []
    other_events: list[str] = []

    for cluster in cluster_info:
        cid = cluster["cluster_id"]
        event_ids = cluster["event_ids"]

        # Noise cluster always passes
        if cid == -1:
            filtered.append(cluster)
            continue

        # Check event count threshold
        if len(event_ids) < thresholds.min_events_per_cluster:
            other_events.extend(event_ids)
            continue

        # Check unique agent count threshold
        unique_agents = set()
        for eid in event_ids:
            f = facets_by_event.get(eid)
            if f:
                unique_agents.add(f.agent_id)
        if len(unique_agents) < thresholds.min_agents_per_cluster:
            other_events.extend(event_ids)
            continue

        # Redact event IDs if cluster is small
        entry = dict(cluster)
        if len(event_ids) < thresholds.redact_agent_ids_below:
            entry["event_ids"] = [f"redacted-{i}" for i in range(len(event_ids))]
        filtered.append(entry)

    # Roll filtered-out events into "Other" bucket
    if other_events:
        filtered.append({
            "cluster_id": -2,
            "label": "Other (below privacy threshold)",
            "event_count": len(other_events),
            "event_ids": [],  # never expose individual IDs
        })

    return filtered


# ---------------------------------------------------------------------------
# Original flat clusterer (preserved for backward compatibility)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Hierarchical clusterer (Clio technique #2)
# ---------------------------------------------------------------------------


class HierarchicalThreatClusterer:
    """Multi-level threat clustering inspired by Clio's hierarchical topic trees.

    Level 0: Deterministic grouping by attack_category facet (no ML needed)
    Level 1: HDBSCAN sub-clustering within each category (technique variants)

    Falls back to flat clustering when facets are unavailable.
    """

    def __init__(
        self,
        summarizer: ClusterSummarizer | None = None,
        privacy: PrivacyThresholds | None = None,
    ) -> None:
        self._facets: dict[str, ThreatFacets] = {}  # event_id → facets
        self._sub_clusterers: dict[str, ThreatClusterer] = {}  # category → clusterer
        self._flat_clusterer = ThreatClusterer()  # fallback
        self._summarizer = summarizer or ClusterSummarizer()
        self._privacy = privacy or PrivacyThresholds()

    def add_event(
        self,
        event_id: str,
        facets: ThreatFacets | None = None,
        metadata_text: str = "",
    ) -> None:
        """Add a threat event for hierarchical clustering.

        If *facets* are provided, the event is grouped by attack category
        for hierarchical clustering.  Otherwise, it falls through to the
        flat clusterer using *metadata_text*.
        """
        if facets is not None:
            self._facets[event_id] = facets
            category = facets.attack_category
            if category not in self._sub_clusterers:
                self._sub_clusterers[category] = ThreatClusterer()
            self._sub_clusterers[category].add_event(
                event_id, facets.to_clustering_text()
            )
        # Always feed flat clusterer for backward-compatible cluster_info
        text = facets.to_clustering_text() if facets else metadata_text
        self._flat_clusterer.add_event(event_id, text)

    def refit(self) -> bool:
        """Re-cluster all sub-clusterers and the flat fallback."""
        any_success = False
        for clusterer in self._sub_clusterers.values():
            if clusterer.refit():
                any_success = True
        if self._flat_clusterer.refit():
            any_success = True
        return any_success

    def get_hierarchy(self) -> list[dict[str, Any]]:
        """Return hierarchical cluster structure.

        Returns a list of category nodes, each containing variant sub-clusters::

            [
                {
                    "category": "prompt_injection",
                    "event_count": 42,
                    "severity_mean": 0.78,
                    "label": "High prompt injection targeting input layer",
                    "variants": [
                        {"variant_id": 0, "label": "...", "event_count": 20, "event_ids": [...]},
                        ...
                    ]
                },
                ...
            ]
        """
        hierarchy: list[dict[str, Any]] = []

        for category, clusterer in sorted(self._sub_clusterers.items()):
            # Collect all events in this category
            cat_event_ids = [
                eid for eid, f in self._facets.items()
                if f.attack_category == category
            ]
            cat_facets = [self._facets[eid] for eid in cat_event_ids]

            if not cat_facets:
                continue

            mean_severity = sum(f.severity for f in cat_facets) / len(cat_facets)

            # Get sub-clusters (variants) from HDBSCAN
            sub_clusters = clusterer.get_clusters()
            variants: list[dict[str, Any]] = []
            for vid, event_ids in sorted(sub_clusters.items()):
                if vid == -1:
                    variant_label = "Unclustered"
                else:
                    variant_facets = [
                        self._facets[eid] for eid in event_ids
                        if eid in self._facets
                    ]
                    variant_label = self._summarizer.summarize(variant_facets)

                variants.append({
                    "variant_id": vid,
                    "label": variant_label,
                    "event_count": len(event_ids),
                    "event_ids": event_ids,
                })

            # If no sub-clustering happened, create a single variant
            if not variants:
                variants.append({
                    "variant_id": 0,
                    "label": self._summarizer.summarize(cat_facets),
                    "event_count": len(cat_event_ids),
                    "event_ids": cat_event_ids,
                })

            category_label = self._summarizer.summarize(cat_facets)

            hierarchy.append({
                "category": category,
                "event_count": len(cat_event_ids),
                "severity_mean": round(mean_severity, 2),
                "label": category_label,
                "variants": variants,
            })

        # Sort by event count descending
        hierarchy.sort(key=lambda h: h["event_count"], reverse=True)
        return hierarchy

    def get_cluster_info(self) -> list[dict[str, Any]]:
        """Return flat cluster info (backward-compatible).

        Uses the flat clusterer output but enriches labels with the
        summarizer and applies privacy thresholds.
        """
        raw_info = self._flat_clusterer.get_cluster_info()

        # Enrich labels via summarizer
        flat_clusters = self._flat_clusterer.get_clusters()
        for entry in raw_info:
            cid = entry["cluster_id"]
            if cid == -1:
                continue
            event_ids = flat_clusters.get(cid, [])
            cluster_facets = [
                self._facets[eid] for eid in event_ids if eid in self._facets
            ]
            if cluster_facets:
                entry["label"] = self._summarizer.summarize(cluster_facets)

        # Apply privacy thresholds
        return _apply_privacy_filter(raw_info, self._facets, self._privacy)

    @property
    def event_count(self) -> int:
        return self._flat_clusterer.event_count

    @property
    def facets(self) -> dict[str, ThreatFacets]:
        return self._facets
