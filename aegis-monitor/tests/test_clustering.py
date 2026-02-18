"""Tests for threat clustering.

ML-dependent tests are skipped if sentence-transformers is not installed.
"""

import pytest

from monitor.clustering import ThreatClusterer


class TestThreatClusterer:
    def test_empty(self):
        c = ThreatClusterer()
        assert c.event_count == 0
        assert c.get_clusters() == {}
        assert c.get_cluster_info() == []

    def test_add_events(self):
        c = ThreatClusterer()
        c.add_event("e1", "score:0.9 matches:3 nk:hostile")
        c.add_event("e2", "score:0.5 matches:1 nk:elevated")
        assert c.event_count == 2

    def test_refit_insufficient_data(self):
        c = ThreatClusterer()
        c.add_event("e1", "test")
        assert c.refit() is False  # need at least 2

    def test_refit_without_ml(self):
        """refit() should return False if ML deps are missing."""
        c = ThreatClusterer()
        c.add_event("e1", "test data one")
        c.add_event("e2", "test data two")

        try:
            import sentence_transformers
            # ML is available, skip this test
            pytest.skip("sentence-transformers is installed")
        except ImportError:
            pass

        result = c.refit()
        assert result is False

    def test_cluster_info_format(self):
        """cluster_info returns correct structure even when empty."""
        c = ThreatClusterer()
        info = c.get_cluster_info()
        assert isinstance(info, list)
