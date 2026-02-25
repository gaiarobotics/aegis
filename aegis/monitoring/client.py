"""Monitoring client — opt-in reporting to a central AEGIS service.

All methods are no-ops when ``enabled=False``.  All exceptions are caught
silently so that monitoring never disrupts the agent's primary work.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from typing import Any
from urllib.parse import urlparse

from aegis.core.config import MonitoringConfig
from aegis.monitoring.reports import (
    AgentHeartbeat,
    CompromiseReport,
    ReportBase,
    ThreatEventReport,
    TrustReport,
)

logger = logging.getLogger(__name__)


class MonitoringClient:
    """Non-blocking client that reports signed events to a monitoring service.

    Args:
        config: Monitoring configuration (from ``AegisConfig.monitoring``).
        agent_id: This agent's identifier.
        operator_id: The operator deploying this agent.
        keypair: Optional ``KeyPair`` for signing reports.
    """

    def __init__(
        self,
        config: MonitoringConfig,
        agent_id: str = "",
        operator_id: str = "",
        keypair: Any = None,
        content_hash_provider: Any = None,
    ) -> None:
        self._config = config
        self._enabled = config.enabled
        service_url = config.service_url.rstrip("/")
        parsed = urlparse(service_url)
        if parsed.scheme not in ("http", "https", ""):
            raise ValueError(f"Invalid service URL scheme: {parsed.scheme}")
        if service_url and not parsed.hostname:
            raise ValueError("Service URL must have a valid hostname")
        self._service_url = service_url
        self._api_key = config.api_key
        self._heartbeat_interval = config.heartbeat_interval_seconds
        self._retry_max = config.retry_max_attempts
        self._retry_backoff = config.retry_backoff_seconds
        self._timeout = config.timeout_seconds
        self._queue_max = config.queue_max_size

        self._agent_id = agent_id
        self._operator_id = operator_id
        self._keypair = keypair
        self._content_hash_provider = content_hash_provider

        self._queue: deque[dict[str, Any]] = deque(maxlen=self._queue_max)
        self._queue_lock = threading.Lock()
        self._heartbeat_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    @property
    def enabled(self) -> bool:
        return self._enabled

    # ------------------------------------------------------------------
    # Public report methods
    # ------------------------------------------------------------------

    def send_compromise_report(
        self,
        compromised_agent_id: str,
        source: str = "",
        nk_score: float = 0.0,
        nk_verdict: str = "",
        recommended_action: str = "quarantine",
    ) -> None:
        """Send a compromise report. No-op if disabled."""
        if not self._enabled:
            return
        try:
            report = CompromiseReport(
                agent_id=self._agent_id,
                operator_id=self._operator_id,
                compromised_agent_id=compromised_agent_id,
                source=source,
                nk_score=nk_score,
                nk_verdict=nk_verdict,
                recommended_action=recommended_action,
            )
            self._sign_and_send(report, "/reports/compromise")
        except Exception:
            logger.debug("Failed to send compromise report", exc_info=True)

    def send_trust_report(
        self,
        target_agent_id: str,
        trust_score: float = 0.0,
        trust_tier: int = 0,
        clean_interactions: int = 0,
        total_interactions: int = 0,
        anomaly_count: int = 0,
        voucher_count: int = 0,
    ) -> None:
        """Send a trust state report. No-op if disabled."""
        if not self._enabled:
            return
        try:
            report = TrustReport(
                agent_id=self._agent_id,
                operator_id=self._operator_id,
                target_agent_id=target_agent_id,
                trust_score=trust_score,
                trust_tier=trust_tier,
                clean_interactions=clean_interactions,
                total_interactions=total_interactions,
                anomaly_count=anomaly_count,
                voucher_count=voucher_count,
            )
            self._sign_and_send(report, "/reports/trust")
        except Exception:
            logger.debug("Failed to send trust report", exc_info=True)

    def send_threat_event(
        self,
        threat_score: float = 0.0,
        is_threat: bool = False,
        scanner_match_count: int = 0,
        nk_score: float = 0.0,
        nk_verdict: str = "",
    ) -> None:
        """Send a threat event report (metadata only). No-op if disabled."""
        if not self._enabled:
            return
        try:
            report = ThreatEventReport(
                agent_id=self._agent_id,
                operator_id=self._operator_id,
                threat_score=threat_score,
                is_threat=is_threat,
                scanner_match_count=scanner_match_count,
                nk_score=nk_score,
                nk_verdict=nk_verdict,
            )
            self._sign_and_send(report, "/reports/threat")
        except Exception:
            logger.debug("Failed to send threat event", exc_info=True)

    def send_heartbeat(
        self,
        trust_tier: int = 0,
        trust_score: float = 0.0,
        is_quarantined: bool = False,
        edges: list[dict[str, Any]] | None = None,
        style_hash: str = "",
        content_hash: str = "",
    ) -> None:
        """Send a heartbeat. No-op if disabled."""
        if not self._enabled:
            return
        try:
            report = AgentHeartbeat(
                agent_id=self._agent_id,
                operator_id=self._operator_id,
                trust_tier=trust_tier,
                trust_score=trust_score,
                is_quarantined=is_quarantined,
                edges=edges or [],
                style_hash=style_hash,
                content_hash=content_hash,
            )
            self._sign_and_send(report, "/heartbeat")
        except Exception:
            logger.debug("Failed to send heartbeat", exc_info=True)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start background heartbeat thread."""
        if not self._enabled:
            return
        self._stop_event.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name="aegis-heartbeat"
        )
        self._heartbeat_thread.start()

    def stop(self) -> None:
        """Stop background heartbeat thread."""
        self._stop_event.set()
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join(timeout=5)
            self._heartbeat_thread = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _heartbeat_loop(self) -> None:
        """Periodically send heartbeats and flush the offline queue."""
        while not self._stop_event.is_set():
            try:
                hashes: dict[str, str] = {}
                if self._content_hash_provider is not None:
                    try:
                        hashes = self._content_hash_provider()
                    except Exception:
                        logger.debug("Content hash provider failed", exc_info=True)
                self.send_heartbeat(
                    style_hash=hashes.get("style_hash", ""),
                    content_hash=hashes.get("content_hash", ""),
                )
                self._flush_queue()
            except Exception:
                logger.debug("Heartbeat loop error", exc_info=True)
            self._stop_event.wait(timeout=self._heartbeat_interval)

    def _sign_and_send(self, report: ReportBase, endpoint: str) -> None:
        """Sign a report and POST it to the service."""
        if self._keypair is not None:
            report.sign(self._keypair)
        payload = report.to_dict()
        success = self._post(endpoint, payload)
        if not success:
            # Queue for retry
            with self._queue_lock:
                self._queue.append({"endpoint": endpoint, "payload": payload})

    def _flush_queue(self) -> None:
        """Attempt to send queued reports."""
        with self._queue_lock:
            retries = len(self._queue)
        for _ in range(retries):
            with self._queue_lock:
                if not self._queue:
                    break
                item = self._queue.popleft()
            if not self._post(item["endpoint"], item["payload"]):
                with self._queue_lock:
                    self._queue.append(item)
                break  # stop on first failure

    def _post(self, endpoint: str, payload: dict) -> bool:
        """POST JSON to the monitoring service. Returns True on success."""
        url = f"{self._service_url}{endpoint}"
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        body = json.dumps(payload).encode("utf-8")

        # Try httpx first (optional), fall back to stdlib urllib
        for attempt in range(self._retry_max):
            try:
                if self._try_httpx(url, body, headers):
                    return True
                if self._try_urllib(url, body, headers):
                    return True
            except Exception:
                logger.debug(
                    "POST attempt %d/%d failed for %s",
                    attempt + 1,
                    self._retry_max,
                    endpoint,
                )
            if attempt < self._retry_max - 1:
                time.sleep(self._retry_backoff)
        return False

    @staticmethod
    def _try_httpx(url: str, body: bytes, headers: dict) -> bool:
        """Attempt to POST using httpx. Returns True on 2xx."""
        try:
            import httpx  # noqa: F811

            resp = httpx.post(url, content=body, headers=headers, timeout=10)
            return 200 <= resp.status_code < 300
        except ImportError:
            return False
        except Exception:
            return False

    @staticmethod
    def _try_urllib(url: str, body: bytes, headers: dict) -> bool:
        """Attempt to POST using urllib.request. Returns True on 2xx."""
        try:
            import urllib.request

            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False
