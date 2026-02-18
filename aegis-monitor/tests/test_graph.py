"""Tests for the agent graph module."""

from monitor.graph import AgentGraph


class TestAgentGraph:
    def test_empty_graph(self):
        g = AgentGraph()
        state = g.get_graph_state()
        assert state["nodes"] == []
        assert state["edges"] == []

    def test_add_node_via_heartbeat(self):
        g = AgentGraph()
        g.update_from_heartbeat("a1", operator_id="op1", trust_tier=2, trust_score=55.0)
        state = g.get_graph_state()
        assert len(state["nodes"]) == 1
        assert state["nodes"][0]["id"] == "a1"
        assert state["nodes"][0]["trust_tier"] == 2
        assert state["nodes"][0]["color"] == "#2ecc71"  # green

    def test_add_edges(self):
        g = AgentGraph()
        g.update_from_heartbeat(
            "a1",
            edges=[
                {"target_agent_id": "a2", "direction": "outbound",
                 "last_seen": 1.0, "message_count": 5},
            ],
        )
        state = g.get_graph_state()
        assert len(state["nodes"]) == 2  # a1 + a2 auto-created
        assert len(state["edges"]) == 1
        assert state["edges"][0]["source"] == "a1"
        assert state["edges"][0]["target"] == "a2"
        assert state["edges"][0]["weight"] == 5

    def test_mark_compromised(self):
        g = AgentGraph()
        g.update_from_heartbeat("a1", trust_tier=2, trust_score=55.0)
        g.mark_compromised("a1")
        state = g.get_graph_state()
        assert state["nodes"][0]["is_compromised"] is True
        assert state["nodes"][0]["color"] == "#e74c3c"  # red

    def test_mark_compromised_unknown_agent(self):
        g = AgentGraph()
        g.mark_compromised("unknown")
        state = g.get_graph_state()
        assert len(state["nodes"]) == 1
        assert state["nodes"][0]["is_compromised"] is True

    def test_at_risk_agents(self):
        g = AgentGraph()
        g.update_from_heartbeat("a1", edges=[
            {"target_agent_id": "a2", "direction": "outbound"},
        ])
        g.update_from_heartbeat("a2", edges=[
            {"target_agent_id": "a3", "direction": "outbound"},
        ])
        g.update_from_heartbeat("a3", edges=[
            {"target_agent_id": "a4", "direction": "outbound"},
        ])

        at_risk = g.get_at_risk_agents("a1", hops=2)
        assert "a2" in at_risk
        assert "a3" in at_risk
        assert "a4" not in at_risk  # 3 hops away

    def test_at_risk_unknown_agent(self):
        g = AgentGraph()
        assert g.get_at_risk_agents("nonexistent") == []

    def test_node_colors(self):
        g = AgentGraph()
        g.update_from_heartbeat("t0", trust_tier=0)
        g.update_from_heartbeat("t1", trust_tier=1)
        g.update_from_heartbeat("t2", trust_tier=2)
        g.update_from_heartbeat("t3", trust_tier=3)

        state = g.get_graph_state()
        by_id = {n["id"]: n for n in state["nodes"]}
        assert by_id["t0"]["color"] == "#95a5a6"  # gray
        assert by_id["t1"]["color"] == "#f1c40f"  # yellow
        assert by_id["t2"]["color"] == "#2ecc71"  # green
        assert by_id["t3"]["color"] == "#2ecc71"  # green

    def test_to_agent_nodes_and_edges(self):
        g = AgentGraph()
        g.update_from_heartbeat("a1", edges=[
            {"target_agent_id": "a2", "message_count": 3},
        ])
        nodes = g.to_agent_nodes()
        edges = g.to_agent_edges()
        assert len(nodes) == 2
        assert len(edges) == 1
        assert edges[0].message_count == 3
