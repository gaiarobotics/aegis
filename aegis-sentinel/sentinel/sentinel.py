"""Sentinel — main orchestrator for the passive Moltbook compromise detector."""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Any

from aegis.broker.actions import ActionRequest
from aegis.shield import Shield

from sentinel.config import SentinelConfig
from sentinel.coverage import CoverageManager
from sentinel.observer import ObservationResult, Observer
from sentinel.reporter import SentinelReporter

logger = logging.getLogger(__name__)

_PROFILE_DIR = Path(__file__).resolve().parent.parent / "profiles"


class Sentinel:
    """Passive Moltbook sentinel agent.

    Bootstraps an AEGIS Shield with the sentinel profile (zero-write broker),
    subscribes to submolts, likes posts for visibility, and scans all content
    for compromise indicators.
    """

    declared_capabilities: tuple[str, ...] = ("like", "subscribe", "read")

    def __init__(self, config: SentinelConfig) -> None:
        self._config = config

        profile_path = str(_PROFILE_DIR / "sentinel.yaml")
        self._shield = Shield(
            policy=config.profile_path or profile_path,
            modules=["scanner", "broker", "identity", "behavior", "recovery"],
            mode="enforce",
        )

        monitoring_client = getattr(self._shield, "_monitoring_client", None)
        self._reporter = SentinelReporter(monitoring_client=monitoring_client)
        self._observer = Observer(shield=self._shield, reporter=self._reporter)
        self._coverage = CoverageManager(config)

    def process_posts(self, posts: list[dict[str, Any]]) -> list[ObservationResult]:
        """Scan a batch of posts and return observation results."""
        results = []
        for post in posts:
            result = self._observer.observe_post(post)
            results.append(result)
        self._coverage.discover_from_posts(posts)
        return results

    def attempt_write_action(self, action_type: str, target: str) -> Any:
        """Attempt a write action through the broker (expected to be denied)."""
        action = ActionRequest(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            source_provenance="trusted.system",
            action_type=action_type,
            read_write="write",
            target=target,
            args={},
            risk_hints={},
        )
        return self._shield.evaluate_action(action)
