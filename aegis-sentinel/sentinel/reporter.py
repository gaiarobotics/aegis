"""Sentinel reporter — wraps monitoring client with sentinel-specific tagging."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class SentinelReporter:
    """Sends sentinel-tagged reports to the AEGIS monitor.

    All reports carry ``source="sentinel"`` so the monitor can distinguish
    sentinel detections from inline AEGIS detections.  If the monitoring
    client is ``None`` (monitoring not configured), all methods are no-ops.
    """

    SOURCE_TAG = "sentinel"

    def __init__(self, monitoring_client: Any) -> None:
        self._client = monitoring_client

    def report_compromised_agent(
        self,
        compromised_agent_id: str,
        nk_score: float = 0.0,
        nk_verdict: str = "",
        recommended_action: str = "quarantine",
        content_hash_hex: str = "",
    ) -> None:
        """Report a compromised agent to the monitor."""
        if self._client is None:
            return
        try:
            self._client.send_compromise_report(
                compromised_agent_id=compromised_agent_id,
                source=self.SOURCE_TAG,
                nk_score=nk_score,
                nk_verdict=nk_verdict,
                recommended_action=recommended_action,
                content_hash_hex=content_hash_hex,
            )
        except Exception:
            logger.debug("Failed to send compromise report", exc_info=True)

    def report_threat_event(
        self,
        threat_score: float = 0.0,
        is_threat: bool = False,
        scanner_match_count: int = 0,
        nk_score: float = 0.0,
        nk_verdict: str = "",
    ) -> None:
        """Report a threat event to the monitor."""
        if self._client is None:
            return
        try:
            self._client.send_threat_event(
                threat_score=threat_score,
                is_threat=is_threat,
                scanner_match_count=scanner_match_count,
                nk_score=nk_score,
                nk_verdict=nk_verdict,
            )
        except Exception:
            logger.debug("Failed to send threat event", exc_info=True)

    def send_heartbeat(self, **kwargs: Any) -> None:
        """Forward a heartbeat to the monitor."""
        if self._client is None:
            return
        try:
            self._client.send_heartbeat(**kwargs)
        except Exception:
            logger.debug("Failed to send heartbeat", exc_info=True)
