"""Tests for the contact graph topology generator."""

from __future__ import annotations

import pytest

from monitor.simulator.models import TopologyConfig
from monitor.simulator.topology import ContactGraph


# ---------------------------------------------------------------------------
# TestContactGraphCreation
# ---------------------------------------------------------------------------


class TestContactGraphCreation:
    """Verify ContactGraph creation with different topology types."""

    def test_random_topology(self):
        cfg = TopologyConfig(type="random", mean_degree=4)
        graph = ContactGraph.generate(50, cfg, seed=42)
        assert graph.num_agents == 50
        # Every agent should have a get_neighbors result (even if empty list)
        neighbors = graph.get_neighbors("agent-0")
        assert isinstance(neighbors, list)

    def test_scale_free_topology(self):
        cfg = TopologyConfig(type="scale_free", m=3)
        graph = ContactGraph.generate(100, cfg, seed=42)
        assert graph.num_agents == 100
        # Scale-free networks have hubs: max degree should exceed min degree
        degrees = [len(graph.get_neighbors(aid)) for aid in graph.all_agent_ids()]
        assert max(degrees) > min(degrees)

    def test_small_world_topology(self):
        cfg = TopologyConfig(type="small_world", mean_degree=6, rewire_probability=0.1)
        graph = ContactGraph.generate(50, cfg, seed=42)
        assert graph.num_agents == 50

    def test_community_topology(self):
        cfg = TopologyConfig(
            type="community",
            num_communities=3,
            intra_probability=0.3,
            inter_probability=0.01,
        )
        graph = ContactGraph.generate(60, cfg, seed=42)
        assert graph.num_agents == 60


# ---------------------------------------------------------------------------
# TestContactGraphQueries
# ---------------------------------------------------------------------------


class TestContactGraphQueries:
    """Verify query methods on a ContactGraph."""

    @pytest.fixture()
    def scale_free_graph(self) -> ContactGraph:
        cfg = TopologyConfig(type="scale_free", m=3)
        return ContactGraph.generate(50, cfg, seed=42)

    def test_get_neighbors(self, scale_free_graph: ContactGraph):
        neighbors = scale_free_graph.get_neighbors("agent-0")
        assert isinstance(neighbors, list)

    def test_get_hubs(self, scale_free_graph: ContactGraph):
        hubs = scale_free_graph.get_hubs(top_n=5)
        assert len(hubs) == 5
        # Hubs should be sorted by degree descending
        degrees = [len(scale_free_graph.get_neighbors(h)) for h in hubs]
        assert degrees == sorted(degrees, reverse=True)

    def test_get_periphery(self, scale_free_graph: ContactGraph):
        periphery = scale_free_graph.get_periphery(top_n=5)
        assert len(periphery) == 5
        # Periphery should be sorted by degree ascending
        degrees = [len(scale_free_graph.get_neighbors(p)) for p in periphery]
        assert degrees == sorted(degrees)

    def test_get_community_members(self):
        cfg = TopologyConfig(
            type="community",
            num_communities=3,
            intra_probability=0.3,
            inter_probability=0.01,
        )
        graph = ContactGraph.generate(30, cfg, seed=42)
        for i in range(3):
            members = graph.get_community_members(i)
            assert len(members) == 10

    def test_all_agent_ids(self, scale_free_graph: ContactGraph):
        ids = scale_free_graph.all_agent_ids()
        assert len(ids) == 50
        assert "agent-0" in ids

    def test_to_serializable(self, scale_free_graph: ContactGraph):
        data = scale_free_graph.to_serializable()
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) == 50


# ---------------------------------------------------------------------------
# TestReproducibility
# ---------------------------------------------------------------------------


class TestReproducibility:
    """Verify deterministic graph generation with seeds."""

    def test_same_seed_same_graph(self):
        cfg = TopologyConfig(type="scale_free", m=3)
        g1 = ContactGraph.generate(50, cfg, seed=123)
        g2 = ContactGraph.generate(50, cfg, seed=123)
        # Same seed should produce identical neighbor lists for all agents
        for aid in g1.all_agent_ids():
            assert sorted(g1.get_neighbors(aid)) == sorted(g2.get_neighbors(aid))
