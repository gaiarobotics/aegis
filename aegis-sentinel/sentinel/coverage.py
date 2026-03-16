"""Coverage manager — controls what the sentinel observes on Moltbook."""

from __future__ import annotations

from typing import Any

from sentinel.config import CoverageMode, SentinelConfig


class CoverageManager:
    """Manages the set of submolts and agents the sentinel monitors."""

    def __init__(self, config: SentinelConfig) -> None:
        self._config = config
        self._subscribed_submolts: set[str] = set()
        self._followed_agents: set[str] = set()

        if config.coverage_mode == CoverageMode.WATCHLIST:
            for entry in config.watchlist:
                if entry.startswith("submolt:"):
                    self._subscribed_submolts.add(entry)
                else:
                    self._followed_agents.add(entry)

    @property
    def mode(self) -> CoverageMode:
        return self._config.coverage_mode

    @property
    def subscribed_submolts(self) -> set[str]:
        return set(self._subscribed_submolts)

    @property
    def followed_agents(self) -> set[str]:
        return set(self._followed_agents)

    def add_submolt(self, submolt_id: str) -> None:
        self._subscribed_submolts.add(submolt_id)

    def add_agent(self, agent_id: str) -> None:
        self._followed_agents.add(agent_id)

    def discover_from_posts(self, posts: list[dict[str, Any]]) -> None:
        if self._config.coverage_mode != CoverageMode.BROAD:
            return
        for post in posts:
            submolt = post.get("submolt")
            if submolt:
                self._subscribed_submolts.add(submolt)
            author = post.get("author")
            if author:
                self._followed_agents.add(author)

    def get_targets(self) -> dict[str, set[str]]:
        return {
            "submolts": set(self._subscribed_submolts),
            "agents": set(self._followed_agents),
        }
