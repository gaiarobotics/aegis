"""Behavior tracking and fingerprinting for agent activity."""

from __future__ import annotations

import hashlib
import json
import math
from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BehaviorEvent:
    """A single behavioral event from an agent."""

    agent_id: str
    timestamp: float
    event_type: str
    output_length: int
    tool_used: str | None
    content_type: str  # "text", "code", "url", "structured"
    target: str | None


@dataclass
class BehaviorFingerprint:
    """Statistical fingerprint of an agent's recent behavior."""

    dimensions: dict[str, dict[str, Any]]
    fingerprint_hash: str
    event_count: int


class BehaviorTracker:
    """Tracks per-agent behavioral events in a rolling window and computes fingerprints."""

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self._window_size: int = config.get("window_size", 100)
        self._events: dict[str, deque[BehaviorEvent]] = {}

    def record_event(self, event: BehaviorEvent) -> None:
        """Add an event to the per-agent rolling window."""
        agent_id = event.agent_id
        if agent_id not in self._events:
            self._events[agent_id] = deque(maxlen=self._window_size)
        self._events[agent_id].append(event)

    def get_fingerprint(self, agent_id: str) -> BehaviorFingerprint:
        """Compute the current behavioral fingerprint for an agent."""
        events = list(self._events.get(agent_id, []))
        event_count = len(events)

        dimensions: dict[str, dict[str, Any]] = {}

        # output_length: mean and std
        if event_count > 0:
            lengths = [e.output_length for e in events]
            mean_len = sum(lengths) / len(lengths)
            variance = sum((x - mean_len) ** 2 for x in lengths) / len(lengths)
            std_len = math.sqrt(variance)
            dimensions["output_length"] = {"mean": mean_len, "std": std_len}
        else:
            dimensions["output_length"] = {"mean": 0.0, "std": 0.0}

        # message_frequency: mean and std of inter-event time gaps
        if event_count > 1:
            sorted_events = sorted(events, key=lambda e: e.timestamp)
            gaps = [
                sorted_events[i + 1].timestamp - sorted_events[i].timestamp
                for i in range(len(sorted_events) - 1)
            ]
            mean_gap = sum(gaps) / len(gaps)
            variance_gap = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
            std_gap = math.sqrt(variance_gap)
            dimensions["message_frequency"] = {"mean": mean_gap, "std": std_gap}
        else:
            dimensions["message_frequency"] = {"mean": 0.0, "std": 0.0}

        # tool_distribution: fraction of events using each tool
        tool_counts: dict[str, int] = {}
        for e in events:
            if e.tool_used is not None:
                tool_counts[e.tool_used] = tool_counts.get(e.tool_used, 0) + 1
        total_tool_events = sum(tool_counts.values())
        if total_tool_events > 0:
            dimensions["tool_distribution"] = {
                tool: count / total_tool_events for tool, count in tool_counts.items()
            }
        else:
            dimensions["tool_distribution"] = {}

        # content_ratios: fraction of events per content_type
        content_counts: dict[str, int] = {}
        for e in events:
            content_counts[e.content_type] = content_counts.get(e.content_type, 0) + 1
        if event_count > 0:
            dimensions["content_ratios"] = {
                ct: count / event_count for ct, count in content_counts.items()
            }
        else:
            dimensions["content_ratios"] = {}

        # unique_targets: count of distinct non-None targets
        targets = {e.target for e in events if e.target is not None}
        dimensions["unique_targets"] = {"count": len(targets)}

        # Compute fingerprint hash from dimensions
        hash_input = json.dumps(dimensions, sort_keys=True, default=str)
        fingerprint_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

        return BehaviorFingerprint(
            dimensions=dimensions,
            fingerprint_hash=fingerprint_hash,
            event_count=event_count,
        )
