"""Epidemiological analysis of compromise propagation.

Estimates R0 (basic reproduction number) for prompt injection attacks
spreading through an agent network.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from monitor.models import CompromiseRecord


class R0Estimator:
    """Estimates R0 and traces propagation chains from compromise records."""

    def __init__(self) -> None:
        self._records: list[CompromiseRecord] = []

    def add_record(self, record: CompromiseRecord) -> None:
        """Add a compromise record for analysis."""
        self._records.append(record)

    def load_records(self, records: list[CompromiseRecord]) -> None:
        """Replace the internal record set."""
        self._records = list(records)

    def estimate_r0(self, window_hours: int = 24) -> float:
        """Estimate R0 over the given time window.

        R0 = average number of secondary infections caused by each
        primary infection within the window.

        Returns 0.0 if there are no compromises in the window.
        """
        cutoff = time.time() - window_hours * 3600
        window_records = [r for r in self._records if r.timestamp >= cutoff]
        if not window_records:
            return 0.0

        # Build the infection chain: reporter → compromised
        # A "primary" is any agent that reported a compromise.
        # A "secondary" is the compromised agent in the report.
        secondaries_per_primary: dict[str, set[str]] = defaultdict(set)

        for rec in window_records:
            primary = rec.reporter_agent_id
            secondary = rec.compromised_agent_id
            if primary and secondary and primary != secondary:
                secondaries_per_primary[primary].add(secondary)

        if not secondaries_per_primary:
            return 0.0

        total_secondaries = sum(len(s) for s in secondaries_per_primary.values())
        return total_secondaries / len(secondaries_per_primary)

    def get_propagation_chains(self) -> list[list[str]]:
        """Trace compromise cascades as ordered chains.

        Each chain is a list of agent IDs in infection order.
        """
        # Sort by timestamp
        sorted_records = sorted(self._records, key=lambda r: r.timestamp)

        # Build adjacency: compromised agent → reporter
        infected_by: dict[str, str] = {}
        for rec in sorted_records:
            if rec.compromised_agent_id and rec.reporter_agent_id:
                if rec.compromised_agent_id not in infected_by:
                    infected_by[rec.compromised_agent_id] = rec.reporter_agent_id

        # Find chain roots (reporters not themselves reported as compromised before)
        all_compromised = set(infected_by.keys())
        roots = set()
        for compromised, reporter in infected_by.items():
            if reporter not in all_compromised:
                roots.add(reporter)

        if not roots:
            # All agents are part of cycles or there's a single chain
            roots = {sorted_records[0].reporter_agent_id} if sorted_records else set()

        # Build forward adjacency
        children: dict[str, list[str]] = defaultdict(list)
        for compromised, reporter in infected_by.items():
            children[reporter].append(compromised)

        chains: list[list[str]] = []
        for root in sorted(roots):
            self._trace_chain(root, children, [], chains)

        return chains

    def _trace_chain(
        self,
        node: str,
        children: dict[str, list[str]],
        current: list[str],
        result: list[list[str]],
    ) -> None:
        current = [*current, node]
        kids = children.get(node, [])
        if not kids:
            result.append(current)
        else:
            for child in sorted(kids):
                self._trace_chain(child, children, current, result)

    def get_r0_trend(
        self, window_hours: int = 24, buckets: int = 12
    ) -> list[dict[str, Any]]:
        """Return R0 estimates over time buckets for trend visualization.

        Returns a list of ``{"timestamp": float, "r0": float}`` entries.
        """
        now = time.time()
        bucket_size = (window_hours * 3600) / buckets
        trend = []

        for i in range(buckets):
            bucket_end = now - i * bucket_size
            bucket_start = bucket_end - bucket_size

            bucket_records = [
                r for r in self._records
                if bucket_start <= r.timestamp < bucket_end
            ]

            secondaries: dict[str, set[str]] = defaultdict(set)
            for rec in bucket_records:
                if rec.reporter_agent_id and rec.compromised_agent_id:
                    if rec.reporter_agent_id != rec.compromised_agent_id:
                        secondaries[rec.reporter_agent_id].add(rec.compromised_agent_id)

            if secondaries:
                r0 = sum(len(s) for s in secondaries.values()) / len(secondaries)
            else:
                r0 = 0.0

            trend.append({"timestamp": bucket_start, "r0": r0})

        trend.reverse()
        return trend
