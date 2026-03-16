"""Observer — ingests Moltbook content and scans for compromise indicators."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ObservationResult:
    """Result of observing a single post."""

    post_id: str
    agent_id: str
    is_threat: bool
    threat_score: float
    details: dict[str, Any] = field(default_factory=dict)


class Observer:
    """Scans Moltbook posts through the AEGIS Shield and reports threats."""

    def __init__(self, shield: Any, reporter: Any) -> None:
        self._shield = shield
        self._reporter = reporter
        self._agent_observation_counts: dict[str, int] = defaultdict(int)

    def observe_post(self, post: dict[str, Any]) -> ObservationResult:
        """Scan a single post and report if malicious.

        If scanning raises an exception (malformed content, scanner crash),
        the error is logged and a safe non-threat result is returned so that
        a single poisoned post cannot take down the sentinel.
        """
        post_id = post.get("id", "")
        author = post.get("author", "")
        content = post.get("content", "")

        self._agent_observation_counts[author] += 1

        try:
            scan_result = self._shield.scan_input(
                text=content,
                source_agent_id=author,
            )
        except Exception:
            logger.warning(
                "scan_input failed for post %s from %s", post_id, author,
                exc_info=True,
            )
            return ObservationResult(
                post_id=post_id,
                agent_id=author,
                is_threat=False,
                threat_score=0.0,
            )

        result = ObservationResult(
            post_id=post_id,
            agent_id=author,
            is_threat=scan_result.is_threat,
            threat_score=scan_result.threat_score,
            details=scan_result.details,
        )

        if scan_result.is_threat:
            content_hash = scan_result.details.get("content_hash_hex", "")

            self._reporter.report_compromised_agent(
                compromised_agent_id=author,
                nk_score=scan_result.threat_score,
                nk_verdict=(
                    "hostile" if scan_result.threat_score >= 0.7 else "suspicious"
                ),
                content_hash_hex=content_hash,
            )
            self._reporter.report_threat_event(
                threat_score=scan_result.threat_score,
                is_threat=True,
                scanner_match_count=len(scan_result.details),
            )

        return result

    def get_agent_observation_count(self, agent_id: str) -> int:
        return self._agent_observation_counts.get(agent_id, 0)
