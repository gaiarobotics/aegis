"""Agent graph management using NetworkX."""

from __future__ import annotations

import time
from typing import Any

import networkx as nx

from monitor.models import AgentEdge, AgentNode


def _trust_color(
    tier: int,
    is_compromised: bool,
    is_quarantined: bool,
    is_killswitched: bool = False,
) -> str:
    """Map trust state to a node color."""
    if is_killswitched:
        return "#e67e22"  # orange — distinct from quarantined (red)
    if is_compromised or is_quarantined:
        return "#e74c3c"  # red
    if tier >= 2:
        return "#2ecc71"  # green
    if tier == 1:
        return "#f1c40f"  # yellow
    return "#95a5a6"  # gray


class AgentGraph:
    """Wraps a ``nx.DiGraph`` to manage the live agent network state."""

    def __init__(self) -> None:
        self._g = nx.DiGraph()

    @property
    def graph(self) -> nx.DiGraph:
        return self._g

    def update_from_heartbeat(
        self,
        agent_id: str,
        operator_id: str = "",
        trust_tier: int = 0,
        trust_score: float = 0.0,
        is_quarantined: bool = False,
        is_killswitched: bool | None = None,
        edges: list[dict[str, Any]] | None = None,
    ) -> None:
        """Add or update a node and its edges from a heartbeat."""
        existing = self._g.nodes.get(agent_id, {})
        ks = is_killswitched if is_killswitched is not None else existing.get("is_killswitched", False)
        self._g.add_node(
            agent_id,
            operator_id=operator_id,
            trust_tier=trust_tier,
            trust_score=trust_score,
            is_compromised=existing.get("is_compromised", False),
            is_quarantined=is_quarantined,
            is_killswitched=ks,
            last_heartbeat=time.time(),
        )
        for edge in edges or []:
            target = edge.get("target_agent_id", "")
            if not target:
                continue
            # Ensure target node exists
            if target not in self._g:
                self._g.add_node(target, trust_tier=0, trust_score=0.0,
                                 is_compromised=False, is_quarantined=False,
                                 is_killswitched=False,
                                 operator_id="", last_heartbeat=0)
            self._g.add_edge(
                agent_id,
                target,
                direction=edge.get("direction", "outbound"),
                last_seen=edge.get("last_seen", time.time()),
                message_count=edge.get("message_count", 0),
            )

    def mark_compromised(self, agent_id: str) -> None:
        """Flag an agent as compromised in the graph."""
        if agent_id in self._g:
            self._g.nodes[agent_id]["is_compromised"] = True
            self._g.nodes[agent_id]["trust_tier"] = 0
            self._g.nodes[agent_id]["trust_score"] = 0.0
        else:
            self._g.add_node(
                agent_id,
                trust_tier=0,
                trust_score=0.0,
                is_compromised=True,
                is_quarantined=False,
                is_killswitched=False,
                operator_id="",
                last_heartbeat=0,
            )

    def mark_killswitched(self, agent_id: str, killswitched: bool = True) -> None:
        """Set the killswitched flag on an agent in the graph."""
        if agent_id in self._g:
            self._g.nodes[agent_id]["is_killswitched"] = killswitched
        elif killswitched:
            self._g.add_node(
                agent_id,
                trust_tier=0,
                trust_score=0.0,
                is_compromised=False,
                is_quarantined=False,
                is_killswitched=True,
                operator_id="",
                last_heartbeat=0,
            )

    def get_graph_state(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the full graph."""
        nodes = []
        for nid, data in self._g.nodes(data=True):
            tier = data.get("trust_tier", 0)
            compromised = data.get("is_compromised", False)
            quarantined = data.get("is_quarantined", False)
            killswitched = data.get("is_killswitched", False)
            nodes.append({
                "id": nid,
                "operator_id": data.get("operator_id", ""),
                "trust_tier": tier,
                "trust_score": data.get("trust_score", 0.0),
                "is_compromised": compromised,
                "is_quarantined": quarantined,
                "is_killswitched": killswitched,
                "color": _trust_color(tier, compromised, quarantined, killswitched),
                "last_heartbeat": data.get("last_heartbeat", 0),
            })

        edges = []
        for src, tgt, data in self._g.edges(data=True):
            edges.append({
                "source": src,
                "target": tgt,
                "direction": data.get("direction", "outbound"),
                "last_seen": data.get("last_seen", 0),
                "message_count": data.get("message_count", 0),
                "weight": max(1, data.get("message_count", 0)),
            })

        return {"nodes": nodes, "edges": edges}

    def get_at_risk_agents(self, agent_id: str, hops: int = 2) -> list[str]:
        """Return agent IDs within ``hops`` of a compromised agent."""
        if agent_id not in self._g:
            return []
        # Use undirected view for neighbor traversal
        undirected = self._g.to_undirected()
        at_risk: set[str] = set()
        current_layer = {agent_id}
        for _ in range(hops):
            next_layer: set[str] = set()
            for node in current_layer:
                for neighbor in undirected.neighbors(node):
                    if neighbor != agent_id and neighbor not in at_risk:
                        next_layer.add(neighbor)
            at_risk.update(next_layer)
            current_layer = next_layer
        return sorted(at_risk)

    def to_agent_nodes(self) -> list[AgentNode]:
        """Convert graph nodes to ``AgentNode`` list."""
        result = []
        for nid, data in self._g.nodes(data=True):
            result.append(AgentNode(
                agent_id=nid,
                operator_id=data.get("operator_id", ""),
                trust_tier=data.get("trust_tier", 0),
                trust_score=data.get("trust_score", 0.0),
                is_compromised=data.get("is_compromised", False),
                is_quarantined=data.get("is_quarantined", False),
                is_killswitched=data.get("is_killswitched", False),
                last_heartbeat=data.get("last_heartbeat", 0),
            ))
        return result

    def to_agent_edges(self) -> list[AgentEdge]:
        """Convert graph edges to ``AgentEdge`` list."""
        result = []
        for src, tgt, data in self._g.edges(data=True):
            result.append(AgentEdge(
                source_agent_id=src,
                target_agent_id=tgt,
                direction=data.get("direction", "outbound"),
                last_seen=data.get("last_seen", 0),
                message_count=data.get("message_count", 0),
            ))
        return result
