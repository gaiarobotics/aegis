"""Data models for the AEGIS monitor service."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentNode:
    """Represents an agent in the graph."""

    agent_id: str
    operator_id: str = ""
    trust_tier: int = 0
    trust_score: float = 0.0
    is_compromised: bool = False
    is_quarantined: bool = False
    last_heartbeat: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentEdge:
    """Represents a communication edge between agents."""

    source_agent_id: str = ""
    target_agent_id: str = ""
    direction: str = "outbound"
    last_seen: float = field(default_factory=time.time)
    message_count: int = 0


@dataclass
class StoredEvent:
    """A persisted coordination event."""

    event_id: str = ""
    event_type: str = ""
    agent_id: str = ""
    operator_id: str = ""
    timestamp: float = field(default_factory=time.time)
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class CompromiseRecord:
    """A persisted compromise report."""

    record_id: str = ""
    reporter_agent_id: str = ""
    compromised_agent_id: str = ""
    source: str = ""
    nk_score: float = 0.0
    nk_verdict: str = ""
    recommended_action: str = "quarantine"
    timestamp: float = field(default_factory=time.time)


@dataclass
class KillswitchRule:
    """A killswitch rule that can block agents by scope."""

    rule_id: str = ""
    scope: str = "agent"      # "swarm", "operator", "agent"
    target: str = ""           # agent_id or operator_id (ignored for swarm)
    blocked: bool = True
    reason: str = ""
    created_at: float = field(default_factory=time.time)
    created_by: str = ""
