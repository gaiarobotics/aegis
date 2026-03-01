"""Contact graph topology generator for the AEGIS epidemic simulator."""

from __future__ import annotations

import networkx as nx

from monitor.simulator.models import TopologyConfig


class ContactGraph:
    """Agent contact graph built from configurable network topologies.

    The graph determines which agents can interact during the simulation,
    directly influencing infection spread dynamics.
    """

    def __init__(
        self,
        graph: nx.Graph,
        communities: dict[int, list[str]] | None = None,
    ) -> None:
        self._graph = graph
        self._communities = communities

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def generate(
        cls,
        num_agents: int,
        config: TopologyConfig,
        seed: int | None = None,
    ) -> ContactGraph:
        """Build a ContactGraph using the topology type specified in *config*."""
        builders = {
            "random": cls._build_random,
            "scale_free": cls._build_scale_free,
            "small_world": cls._build_small_world,
            "community": cls._build_community,
        }
        builder = builders.get(config.type)
        if builder is None:
            raise ValueError(f"Unknown topology type: {config.type!r}")
        return builder(num_agents, config, seed)

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    @classmethod
    def _build_random(cls, n: int, cfg: TopologyConfig, seed: int | None) -> ContactGraph:
        """Erdos-Renyi random graph.  p = mean_degree / (n - 1)."""
        p = cfg.mean_degree / (n - 1) if n > 1 else 0
        g = nx.erdos_renyi_graph(n, p, seed=seed)
        g = _relabel(g, n)
        return cls(g)

    @classmethod
    def _build_small_world(cls, n: int, cfg: TopologyConfig, seed: int | None) -> ContactGraph:
        """Watts-Strogatz small-world graph.  k = mean_degree (must be even)."""
        k = cfg.mean_degree
        # Watts-Strogatz requires k to be even
        if k % 2 != 0:
            k += 1
        g = nx.watts_strogatz_graph(n, k, cfg.rewire_probability, seed=seed)
        g = _relabel(g, n)
        return cls(g)

    @classmethod
    def _build_scale_free(cls, n: int, cfg: TopologyConfig, seed: int | None) -> ContactGraph:
        """Barabasi-Albert scale-free graph.  m = cfg.m."""
        g = nx.barabasi_albert_graph(n, cfg.m, seed=seed)
        g = _relabel(g, n)
        return cls(g)

    @classmethod
    def _build_community(cls, n: int, cfg: TopologyConfig, seed: int | None) -> ContactGraph:
        """Stochastic Block Model with *num_communities* equal-sized groups."""
        k = cfg.num_communities
        base_size = n // k
        remainder = n % k
        sizes = [base_size + (1 if i < remainder else 0) for i in range(k)]

        # Build probability matrix: intra on diagonal, inter elsewhere
        p_matrix = [
            [
                cfg.intra_probability if i == j else cfg.inter_probability
                for j in range(k)
            ]
            for i in range(k)
        ]

        g = nx.stochastic_block_model(sizes, p_matrix, seed=seed)
        g = _relabel(g, n)

        # Record community membership using agent-id labels
        communities: dict[int, list[str]] = {}
        offset = 0
        for idx, size in enumerate(sizes):
            communities[idx] = [f"agent-{i}" for i in range(offset, offset + size)]
            offset += size

        return cls(g, communities=communities)

    # ------------------------------------------------------------------
    # Properties / queries
    # ------------------------------------------------------------------

    @property
    def num_agents(self) -> int:
        """Return the number of agents (nodes) in the graph."""
        return self._graph.number_of_nodes()

    def all_agent_ids(self) -> list[str]:
        """Return a list of all agent IDs."""
        return list(self._graph.nodes)

    def get_neighbors(self, agent_id: str) -> list[str]:
        """Return the neighbors of *agent_id*."""
        return list(self._graph.neighbors(agent_id))

    def get_hubs(self, top_n: int = 10) -> list[str]:
        """Return the *top_n* agents with highest degree, sorted descending."""
        degree_pairs = sorted(
            self._graph.degree,
            key=lambda pair: pair[1],
            reverse=True,
        )
        return [node for node, _deg in degree_pairs[:top_n]]

    def get_periphery(self, top_n: int = 10) -> list[str]:
        """Return the *top_n* agents with lowest degree, sorted ascending."""
        degree_pairs = sorted(
            self._graph.degree,
            key=lambda pair: pair[1],
        )
        return [node for node, _deg in degree_pairs[:top_n]]

    def get_community_members(self, community_idx: int) -> list[str]:
        """Return the agent IDs belonging to community *community_idx*."""
        if self._communities is None:
            return []
        return self._communities.get(community_idx, [])

    def to_serializable(self) -> dict:
        """Serialize the graph to a plain dict with *nodes* and *edges* keys.

        Each node entry contains ``id`` and ``degree``.
        Each edge entry contains ``source`` and ``target``.
        """
        nodes = [
            {"id": node, "degree": deg}
            for node, deg in self._graph.degree
        ]
        edges = [
            {"source": u, "target": v}
            for u, v in self._graph.edges
        ]
        return {"nodes": nodes, "edges": edges}


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _relabel(g: nx.Graph, n: int) -> nx.Graph:
    """Relabel integer node IDs to ``agent-{i}`` strings."""
    mapping = {i: f"agent-{i}" for i in range(n)}
    return nx.relabel_nodes(g, mapping)
