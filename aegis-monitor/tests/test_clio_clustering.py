"""Tests for Clio-inspired clustering enhancements.

Tests cover: facet extraction, hierarchical clustering, template summarization,
KeyBERT summarization (skipped if not installed), privacy thresholds.
"""

import pytest

from monitor.clustering import (
    ClusterSummarizer,
    HierarchicalThreatClusterer,
    KeyBERTSummarizer,
    PrivacyThresholds,
    TemplateSummarizer,
    ThreatFacets,
    _apply_privacy_filter,
    _severity_label,
    extract_facets,
)


# ---------------------------------------------------------------------------
# ThreatFacets
# ---------------------------------------------------------------------------

class TestThreatFacets:
    def test_defaults(self):
        f = ThreatFacets()
        assert f.attack_category == "unknown"
        assert f.severity == 0.0
        assert f.evasion_techniques == []

    def test_to_clustering_text(self):
        f = ThreatFacets(
            attack_category="prompt_injection",
            target_layer="input",
            evasion_techniques=["base64", "unicode"],
            severity=0.8,
            nk_verdict="hostile",
            semantic_findings=["boundary_violations"],
        )
        text = f.to_clustering_text()
        assert "attack:prompt_injection" in text
        assert "layer:input" in text
        assert "severity:0.8" in text
        assert "verdict:hostile" in text
        assert "evasion:base64" in text
        assert "evasion:unicode" in text
        assert "finding:boundary_violations" in text


# ---------------------------------------------------------------------------
# Facet extraction
# ---------------------------------------------------------------------------

class TestExtractFacets:
    def test_basic_extraction(self):
        data = {
            "threat_score": 0.85,
            "nk_verdict": "hostile",
            "agent_id": "agent-001",
            "scanner_matches": [
                {"category": "prompt_injection", "evasion_technique": "base64"},
                {"category": "prompt_injection"},
            ],
            "semantic_findings": ["boundary_violations", "unicode_attacks"],
        }
        facets = extract_facets(data)
        assert facets.attack_category == "prompt_injection"
        assert facets.severity == 0.85
        assert facets.nk_verdict == "hostile"
        assert facets.agent_id == "agent-001"
        assert "base64" in facets.evasion_techniques
        assert "unicode" in facets.evasion_techniques
        assert "boundary_violations" in facets.semantic_findings
        assert facets.target_layer == "input"

    def test_empty_data(self):
        facets = extract_facets({})
        assert facets.attack_category == "unknown"
        assert facets.severity == 0.0
        assert facets.nk_verdict == "normal"

    def test_behavioral_anomaly_fallback(self):
        data = {"threat_score": 0.6, "nk_verdict": "suspicious"}
        facets = extract_facets(data)
        assert facets.attack_category == "behavioral_anomaly"

    def test_target_layer_memory(self):
        data = {
            "scanner_matches": [{"category": "memory_poisoning"}],
        }
        facets = extract_facets(data)
        assert facets.target_layer == "memory"

    def test_severity_clamped(self):
        data = {"threat_score": 2.5}
        facets = extract_facets(data)
        assert facets.severity == 1.0

        data2 = {"threat_score": -0.5}
        facets2 = extract_facets(data2)
        assert facets2.severity == 0.0


# ---------------------------------------------------------------------------
# Summarization
# ---------------------------------------------------------------------------

class TestTemplateSummarizer:
    def test_empty(self):
        s = TemplateSummarizer()
        assert s.summarize([]) == "Empty cluster"

    def test_basic_summary(self):
        s = TemplateSummarizer()
        facets = [
            ThreatFacets(
                attack_category="prompt_injection",
                target_layer="input",
                evasion_techniques=["base64"],
                severity=0.9,
            ),
            ThreatFacets(
                attack_category="prompt_injection",
                target_layer="input",
                evasion_techniques=["base64"],
                severity=0.7,
            ),
        ]
        label = s.summarize(facets)
        assert "prompt_injection" in label
        assert "input" in label
        assert "base64" in label

    def test_severity_labels(self):
        assert _severity_label(0.9) == "Critical"
        assert _severity_label(0.7) == "High"
        assert _severity_label(0.5) == "Medium"
        assert _severity_label(0.3) == "Low"
        assert _severity_label(0.1) == "Minimal"


class TestKeyBERTSummarizer:
    def test_unavailable_returns_empty(self):
        s = KeyBERTSummarizer()
        # If keybert is not installed, should return empty string
        try:
            import keybert
            pytest.skip("keybert is installed")
        except ImportError:
            pass
        result = s.summarize(["test text"])
        assert result == ""

    def test_empty_input(self):
        s = KeyBERTSummarizer()
        assert s.summarize([]) == ""


class TestClusterSummarizer:
    def test_template_fallback(self):
        s = ClusterSummarizer(strategy="template")
        facets = [
            ThreatFacets(attack_category="role_hijacking", severity=0.6),
        ]
        label = s.summarize(facets)
        assert "role_hijacking" in label

    def test_keybert_falls_back_to_template(self):
        """When keybert is not installed, falls back to template."""
        s = ClusterSummarizer(strategy="keybert")
        facets = [
            ThreatFacets(attack_category="data_exfiltration", severity=0.8),
        ]
        label = s.summarize(facets)
        assert "data_exfiltration" in label

    def test_llm_falls_back_to_template(self):
        """When no LLM endpoint, falls back through to template."""
        s = ClusterSummarizer(strategy="llm")
        facets = [
            ThreatFacets(attack_category="evasion", severity=0.4),
        ]
        label = s.summarize(facets)
        assert "evasion" in label


# ---------------------------------------------------------------------------
# Privacy thresholds
# ---------------------------------------------------------------------------

class TestPrivacyThresholds:
    def test_filters_small_clusters(self):
        thresholds = PrivacyThresholds(
            min_events_per_cluster=3,
            min_agents_per_cluster=1,
        )
        clusters = [
            {"cluster_id": 0, "label": "Strain 0", "event_count": 2, "event_ids": ["e1", "e2"]},
            {"cluster_id": 1, "label": "Strain 1", "event_count": 5, "event_ids": ["e3", "e4", "e5", "e6", "e7"]},
            {"cluster_id": -1, "label": "Unclustered", "event_count": 1, "event_ids": ["e8"]},
        ]
        facets = {
            "e1": ThreatFacets(agent_id="a1"),
            "e2": ThreatFacets(agent_id="a2"),
            "e3": ThreatFacets(agent_id="a1"),
            "e4": ThreatFacets(agent_id="a2"),
            "e5": ThreatFacets(agent_id="a3"),
            "e6": ThreatFacets(agent_id="a1"),
            "e7": ThreatFacets(agent_id="a2"),
        }
        filtered = _apply_privacy_filter(clusters, facets, thresholds)
        # Cluster 0 should be rolled into "Other" (only 2 events < 3)
        # Cluster 1 should remain
        # Cluster -1 (noise) always passes
        ids = [c["cluster_id"] for c in filtered]
        assert -1 in ids  # noise passes
        assert 1 in ids  # large enough
        assert 0 not in ids  # too small
        assert -2 in ids  # "Other" bucket

    def test_agent_count_threshold(self):
        thresholds = PrivacyThresholds(
            min_events_per_cluster=1,
            min_agents_per_cluster=2,
        )
        clusters = [
            {"cluster_id": 0, "label": "X", "event_count": 5,
             "event_ids": ["e1", "e2", "e3", "e4", "e5"]},
        ]
        # All from same agent
        facets = {f"e{i}": ThreatFacets(agent_id="a1") for i in range(1, 6)}
        filtered = _apply_privacy_filter(clusters, facets, thresholds)
        ids = [c["cluster_id"] for c in filtered]
        assert 0 not in ids
        assert -2 in ids

    def test_redaction(self):
        thresholds = PrivacyThresholds(
            min_events_per_cluster=1,
            min_agents_per_cluster=1,
            redact_agent_ids_below=10,
        )
        clusters = [
            {"cluster_id": 0, "label": "X", "event_count": 3,
             "event_ids": ["e1", "e2", "e3"]},
        ]
        facets = {
            "e1": ThreatFacets(agent_id="a1"),
            "e2": ThreatFacets(agent_id="a2"),
            "e3": ThreatFacets(agent_id="a3"),
        }
        filtered = _apply_privacy_filter(clusters, facets, thresholds)
        cluster_0 = [c for c in filtered if c["cluster_id"] == 0][0]
        assert all(eid.startswith("redacted-") for eid in cluster_0["event_ids"])


# ---------------------------------------------------------------------------
# Hierarchical clusterer
# ---------------------------------------------------------------------------

class TestHierarchicalThreatClusterer:
    def test_add_events(self):
        h = HierarchicalThreatClusterer()
        f1 = ThreatFacets(attack_category="prompt_injection", severity=0.9)
        f2 = ThreatFacets(attack_category="data_exfiltration", severity=0.7)
        h.add_event("e1", facets=f1)
        h.add_event("e2", facets=f2)
        assert h.event_count == 2

    def test_hierarchy_structure(self):
        h = HierarchicalThreatClusterer()
        for i in range(5):
            f = ThreatFacets(attack_category="prompt_injection", severity=0.8)
            h.add_event(f"pi-{i}", facets=f)
        for i in range(3):
            f = ThreatFacets(attack_category="data_exfiltration", severity=0.5)
            h.add_event(f"de-{i}", facets=f)

        hierarchy = h.get_hierarchy()
        assert len(hierarchy) == 2
        # Sorted by event_count descending
        assert hierarchy[0]["category"] == "prompt_injection"
        assert hierarchy[0]["event_count"] == 5
        assert hierarchy[1]["category"] == "data_exfiltration"
        assert hierarchy[1]["event_count"] == 3
        # Each should have at least one variant
        assert len(hierarchy[0]["variants"]) >= 1

    def test_cluster_info_backward_compat(self):
        h = HierarchicalThreatClusterer(
            privacy=PrivacyThresholds(min_events_per_cluster=1, min_agents_per_cluster=1),
        )
        f = ThreatFacets(attack_category="test", severity=0.5, agent_id="a1")
        h.add_event("e1", facets=f)
        info = h.get_cluster_info()
        assert isinstance(info, list)

    def test_fallback_without_facets(self):
        h = HierarchicalThreatClusterer()
        h.add_event("e1", metadata_text="score:0.5 nk:elevated")
        assert h.event_count == 1
