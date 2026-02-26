"""Tests for monitor.contagion — topic clustering and contagion detection."""

from __future__ import annotations

from unittest import mock

import pytest

from monitor.contagion import (
    ContagionDetector,
    TopicClusterer,
    hamming_distance,
    hex_to_int,
)


# ------------------------------------------------------------------
# Utility
# ------------------------------------------------------------------

class TestHammingDistance:
    def test_identical(self):
        assert hamming_distance(0, 0) == 0
        assert hamming_distance(0xFF, 0xFF) == 0

    def test_all_different_8bit(self):
        assert hamming_distance(0x00, 0xFF) == 8

    def test_single_bit(self):
        assert hamming_distance(0b0000, 0b0001) == 1
        assert hamming_distance(0b1000, 0b0000) == 1

    def test_mixed(self):
        assert hamming_distance(0b1010, 0b0101) == 4


class TestHexToInt:
    def test_basic(self):
        assert hex_to_int("ff") == 255
        assert hex_to_int("00000000000000000000000000000000") == 0
        assert hex_to_int("00000000000000000000000000000001") == 1


# ------------------------------------------------------------------
# TopicClusterer — core behaviour (works with either backend)
# ------------------------------------------------------------------

class TestTopicClusterer:
    def test_identical_hashes_same_cluster(self):
        """Agents with identical hashes are in the same cluster."""
        tc = TopicClusterer(threshold=16)
        h = "a" * 32  # all-a hex
        tc.update("agent-1", h)
        tc.update("agent-2", h)
        tc.update("agent-3", h)

        clusters = tc.cluster()
        assert clusters["agent-1"] == clusters["agent-2"]
        assert clusters["agent-2"] == clusters["agent-3"]

    def test_very_different_hashes_different_clusters(self):
        """Agents with very different hashes are in different clusters."""
        tc = TopicClusterer(threshold=16)
        tc.update("agent-1", "0" * 32)
        tc.update("agent-2", "f" * 32)

        clusters = tc.cluster()
        assert clusters["agent-1"] != clusters["agent-2"]

    def test_close_hashes_same_cluster(self):
        """Agents with similar hashes (within threshold) cluster together."""
        tc = TopicClusterer(threshold=16)
        # Only a few bits differ between these
        tc.update("agent-1", "00000000000000000000000000000000")
        tc.update("agent-2", "00000000000000000000000000000001")  # 4 bits diff

        clusters = tc.cluster()
        assert clusters["agent-1"] == clusters["agent-2"]

    def test_cluster_colors(self):
        """get_cluster_colors returns hex color strings."""
        tc = TopicClusterer(threshold=16)
        tc.update("agent-1", "a" * 32)
        tc.update("agent-2", "a" * 32)

        colors = tc.get_cluster_colors()
        assert "agent-1" in colors
        assert "agent-2" in colors
        assert colors["agent-1"].startswith("#")
        assert colors["agent-1"] == colors["agent-2"]

    def test_empty_clusterer(self):
        """Empty clusterer returns empty dict."""
        tc = TopicClusterer()
        assert tc.cluster() == {}
        assert tc.get_cluster_colors() == {}

    def test_empty_hash_ignored(self):
        """Empty hash string is ignored."""
        tc = TopicClusterer()
        tc.update("agent-1", "")
        assert tc.cluster() == {}

    def test_single_agent(self):
        """Single agent gets its own cluster."""
        tc = TopicClusterer()
        tc.update("agent-1", "a" * 32)
        clusters = tc.cluster()
        assert "agent-1" in clusters


# ------------------------------------------------------------------
# TopicClusterer — DBSCAN-specific (anti-chaining)
# ------------------------------------------------------------------

class TestTopicClustererDBSCAN:
    """Tests that exercise the DBSCAN backend specifically.

    These are skipped when sklearn is not installed.
    """

    @pytest.fixture(autouse=True)
    def _require_sklearn(self):
        try:
            import sklearn  # noqa: F401
        except ImportError:
            pytest.skip("scikit-learn not installed")

    def test_dbscan_no_transitive_chaining(self):
        """DBSCAN should not chain A→B→C when A and C are far apart.

        Construct three agents where A↔B and B↔C are within threshold,
        but A↔C is far beyond threshold.  With union-find, all three
        would cluster.  With DBSCAN (min_samples=2) B is a core point,
        but A and C should NOT be in the same cluster if they're too far
        from each other (the cluster should still form around the core
        point B, but only if there is genuine density).
        """
        # With min_samples=2, a core point needs at least 2 neighbours
        # within eps.  If B is close to both A and C, B has 2 neighbours
        # so it's a core point, and both A and C are reachable from B.
        # DBSCAN *will* put all three together in that case — that's
        # correct density-based behaviour.
        #
        # The real anti-chaining benefit shows when the chain is longer
        # and intermediaries lack sufficient density.
        #
        # Test: A-B close, C-D close, B-C close but NO other cross-links.
        # With min_samples=2: B needs 2 neighbours within eps to be core.
        # B has A and C → core.  C has B and D → core.
        # So DBSCAN forms {A,B,C,D} — same as union-find for 4-chains.
        #
        # Better test: raise min_samples to 3 so intermediaries with only
        # 2 neighbours are NOT core.  Then A(1 nbr) - B(2 nbrs) can't
        # form a dense cluster.
        tc = TopicClusterer(threshold=16, min_samples=3)

        # A is close to B (distance ~8 bits)
        tc.update("A", "00000000000000000000000000000000")
        tc.update("B", "00000000000000000000000000000f0f")  # ~8 bits from A
        # C is close to B but far from A
        tc.update("C", "00000000000000000000000000ffff0f")  # close to B, far from A

        clusters = tc.cluster()
        # With min_samples=3, none of these have 3 neighbours within eps,
        # so all are noise → each gets its own cluster.
        assert clusters["A"] != clusters["C"], (
            "A and C should not chain through B when min_samples=3"
        )

    def test_dbscan_dense_cluster_forms(self):
        """A genuinely dense group clusters together under DBSCAN."""
        tc = TopicClusterer(threshold=16, min_samples=2)

        # Three agents all pairwise close — dense cluster
        tc.update("A", "00000000000000000000000000000000")
        tc.update("B", "00000000000000000000000000000001")
        tc.update("C", "00000000000000000000000000000003")

        # One distant agent
        tc.update("Z", "ffffffffffffffffffffffffffffffff")

        clusters = tc.cluster()
        assert clusters["A"] == clusters["B"] == clusters["C"]
        assert clusters["Z"] != clusters["A"]

    def test_dbscan_is_used_when_available(self):
        """Verify DBSCAN path is taken (not union-find) when sklearn exists."""
        tc = TopicClusterer(threshold=16)
        tc.update("A", "a" * 32)
        tc.update("B", "a" * 32)

        with mock.patch.object(tc, "_cluster_union_find", wraps=tc._cluster_union_find) as uf_spy:
            tc.cluster()
            uf_spy.assert_not_called()


# ------------------------------------------------------------------
# TopicClusterer — union-find fallback
# ------------------------------------------------------------------

class TestTopicClustererFallback:
    def test_union_find_used_when_sklearn_missing(self):
        """Union-find fallback is used when sklearn is unavailable."""
        tc = TopicClusterer(threshold=16)
        tc.update("A", "a" * 32)
        tc.update("B", "a" * 32)

        with mock.patch.object(tc, "_cluster_dbscan", return_value=None) as db_spy:
            clusters = tc.cluster()
            db_spy.assert_called_once()
            # Should still produce correct results via fallback
            assert clusters["A"] == clusters["B"]

    def test_union_find_chains(self):
        """Union-find DOES chain — this documents the known limitation."""
        tc = TopicClusterer(threshold=16)

        # Force union-find path
        with mock.patch.object(tc, "_cluster_dbscan", return_value=None):
            # A close to B, B close to C, A far from C
            tc.update("A", "00000000000000000000000000000000")
            tc.update("B", "00000000000000000000000000000f0f")
            tc.update("C", "00000000000000000000000000ffff0f")

            clusters = tc.cluster()
            # Union-find will chain A→B→C into one cluster
            # (this is the limitation that DBSCAN avoids with min_samples>2)
            assert clusters["A"] == clusters["B"]
            assert clusters["B"] == clusters["C"]


# ------------------------------------------------------------------
# ContagionDetector
# ------------------------------------------------------------------

class TestContagionDetector:
    def test_no_compromised_returns_zero(self):
        """No compromised hashes → score 0.0."""
        cd = ContagionDetector()
        assert cd.check("agent-1", "a" * 32) == 0.0

    def test_matching_compromised_hash_triggers_alert(self):
        """Identical hash to compromised agent → score 1.0."""
        cd = ContagionDetector(alert_threshold=0.85)
        h = "abcdef01" * 4  # 32-char hex
        cd.mark_compromised("bad-agent", h)

        score = cd.check("agent-1", h)
        assert score == 1.0
        assert score >= cd._alert_threshold

    def test_distant_hash_no_alert(self):
        """Very different hash → low score, no alert."""
        cd = ContagionDetector(alert_threshold=0.85)
        cd.mark_compromised("bad-agent", "0" * 32)

        score = cd.check("agent-1", "f" * 32)
        # 128 bits differ → similarity = 1 - 128/128 = 0.0
        assert score == 0.0
        assert score < cd._alert_threshold

    def test_similar_hash_high_score(self):
        """Slightly different hash → high similarity score."""
        cd = ContagionDetector(alert_threshold=0.85)
        cd.mark_compromised("bad-agent", "00000000000000000000000000000000")

        # 1 hex digit different: '1' = 0001 → 1 bit difference
        score = cd.check("agent-1", "00000000000000000000000000000001")
        h_dist = hamming_distance(
            hex_to_int("00000000000000000000000000000000"),
            hex_to_int("00000000000000000000000000000001"),
        )
        expected = 1.0 - (h_dist / 128)
        assert score == pytest.approx(expected)
        assert score >= cd._alert_threshold

    def test_empty_hash_returns_zero(self):
        """Empty hash string returns 0.0."""
        cd = ContagionDetector()
        cd.mark_compromised("bad-agent", "a" * 32)
        assert cd.check("agent-1", "") == 0.0

    def test_empty_compromised_hash_ignored(self):
        """Empty hash for mark_compromised is ignored."""
        cd = ContagionDetector()
        cd.mark_compromised("bad-agent", "")
        assert cd.check("agent-1", "a" * 32) == 0.0


# ------------------------------------------------------------------
# ContagionDetector — velocity-aware scoring
# ------------------------------------------------------------------

class TestContagionDetectorVelocity:
    def test_velocity_amplifies_proximity(self):
        """High velocity amplifies the proximity score."""
        cd = ContagionDetector(alert_threshold=0.85, velocity_weight=0.5)
        cd.mark_compromised("bad-agent", "00000000000000000000000000000000")

        # Hash that's somewhat close — proximity alone might be below threshold
        # Pick a hash with ~20 bits different → proximity = 1 - 20/128 ≈ 0.844
        test_hash = "00000000000000000000000000f0f0f0"
        h_dist = hamming_distance(hex_to_int("0" * 32), hex_to_int(test_hash))

        score_no_vel = cd.check_with_velocity("agent-1", test_hash, topic_velocity=0.0)
        score_hi_vel = cd.check_with_velocity("agent-1", test_hash, topic_velocity=1.0)

        # Without velocity, composite equals raw proximity
        assert score_no_vel == pytest.approx(cd.check("agent-1", test_hash))
        # With velocity, composite should be higher
        assert score_hi_vel > score_no_vel, (
            f"High velocity should amplify: no_vel={score_no_vel}, hi_vel={score_hi_vel}"
        )

    def test_velocity_zero_equals_raw_proximity(self):
        """Zero velocity produces the same score as check()."""
        cd = ContagionDetector(velocity_weight=0.5)
        cd.mark_compromised("bad-agent", "a" * 32)

        raw = cd.check("agent-1", "a" * 32)
        composite = cd.check_with_velocity("agent-1", "a" * 32, topic_velocity=0.0)
        assert composite == pytest.approx(raw)

    def test_velocity_clamped_to_one(self):
        """Composite score never exceeds 1.0."""
        cd = ContagionDetector(velocity_weight=0.5)
        cd.mark_compromised("bad-agent", "a" * 32)

        # Identical hash → proximity = 1.0, high velocity
        score = cd.check_with_velocity("agent-1", "a" * 32, topic_velocity=1.0)
        assert score <= 1.0

    def test_velocity_no_compromised_still_zero(self):
        """No compromised hashes → score 0.0 regardless of velocity."""
        cd = ContagionDetector(velocity_weight=0.5)
        score = cd.check_with_velocity("agent-1", "a" * 32, topic_velocity=1.0)
        assert score == 0.0

    def test_velocity_pushes_borderline_over_threshold(self):
        """A borderline proximity score crosses the threshold with high velocity."""
        cd = ContagionDetector(alert_threshold=0.85, velocity_weight=0.5)
        cd.mark_compromised("bad-agent", "00000000000000000000000000000000")

        # Find a hash that gives proximity just below threshold
        # 20 bits different → proximity = 1 - 20/128 = 0.84375 (just below 0.85)
        # We need exactly 20 bits set. 0xfffff = 20 bits.
        test_hash = f"{'0' * 27}fffff"  # 20 bits differ
        proximity = cd.check("agent-1", test_hash)

        # Without velocity: below threshold
        score_no_vel = cd.check_with_velocity("agent-1", test_hash, topic_velocity=0.0)
        assert score_no_vel < cd._alert_threshold, (
            f"Proximity alone ({score_no_vel}) should be below threshold"
        )

        # With high velocity: pushed above threshold
        score_hi_vel = cd.check_with_velocity("agent-1", test_hash, topic_velocity=1.0)
        assert score_hi_vel >= cd._alert_threshold, (
            f"Velocity-boosted score ({score_hi_vel}) should cross threshold"
        )


# ------------------------------------------------------------------
# Integration: contagion alert creates quarantine rule
# ------------------------------------------------------------------

class TestContagionAlertCreatesQuarantineRule:
    """Integration test: heartbeat with compromised hash auto-quarantines."""

    @pytest.fixture
    def client(self, tmp_path):
        import os
        from fastapi.testclient import TestClient
        from monitor.app import app

        db_path = str(tmp_path / "test.db")
        os.environ["MONITOR_DATABASE_PATH"] = db_path
        os.environ.pop("MONITOR_API_KEYS", None)

        with TestClient(app) as c:
            app.state.config.api_keys = []
            yield c, app

        os.environ.pop("MONITOR_DATABASE_PATH", None)

    def test_contagion_alert_creates_quarantine_rule(self, client):
        """A heartbeat triggering a contagion alert should auto-quarantine the agent."""
        c, app = client

        # First, mark an agent as compromised so its hash is flagged
        compromised_hash = "abcdef01" * 4  # 32-char hex
        contagion_detector = app.state.contagion_detector
        contagion_detector.mark_compromised("bad-agent", compromised_hash)

        # Send heartbeat from a different agent with the SAME hash
        # This should trigger a contagion alert and auto-quarantine
        resp = c.post("/api/v1/heartbeat", json={
            "agent_id": "victim-agent",
            "operator_id": "op-1",
            "trust_tier": 2,
            "trust_score": 50.0,
            "content_hash": compromised_hash,
            "topic_velocity": 0.0,
            "edges": [],
        })
        assert resp.status_code == 200

        # Verify quarantine was created
        db = app.state.db
        quarantined, reason, scope, severity = db.check_quarantine(
            "victim-agent", "op-1",
        )
        assert quarantined is True
        assert "Contagion alert" in reason
        assert severity == "high"

        # Verify agent is marked quarantined in DB
        agent = db.get_agent("victim-agent")
        assert agent is not None
        assert agent.is_quarantined is True
