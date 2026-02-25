"""Remote quarantine — polls the monitoring service for quarantine status.

Mirrors the RemoteKillswitch pattern: daemon thread, fail-last,
thread-safe is_quarantined() property.  When the monitor quarantines an
agent (e.g. due to a contagion alert), the agent discovers this via
polling and blocks inference.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

_POLL_TIMEOUT = 5  # seconds


class RemoteQuarantine:
    """Polls the monitoring service for quarantine status.

    Mirrors the RemoteKillswitch pattern: daemon thread, fail-last,
    thread-safe ``is_quarantined()`` property.
    """

    def __init__(
        self,
        service_url: str,
        api_key: str,
        agent_id: str,
        operator_id: str,
        poll_interval: float = 30,
    ) -> None:
        self._url = f"{service_url.rstrip('/')}/quarantine/status"
        self._api_key = api_key
        self._agent_id = agent_id
        self._operator_id = operator_id
        self._poll_interval = poll_interval

        self._quarantined = False
        self._reason = ""
        self._severity = ""
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_quarantined(self) -> bool:
        """Thread-safe.  Returns ``True`` if the agent is quarantined."""
        with self._lock:
            return self._quarantined

    @property
    def reason(self) -> str:
        """Human-readable reason for the quarantine, or ``""``."""
        with self._lock:
            return self._reason

    @property
    def severity(self) -> str:
        """Severity level of the quarantine rule, or ``""``."""
        with self._lock:
            return self._severity

    def start(self) -> None:
        """Start background polling thread (daemon)."""
        if self._thread is not None:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop background polling."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._poll_interval + _POLL_TIMEOUT + 1)
            self._thread = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        """Poll every ``poll_interval`` seconds."""
        self._poll()
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self._poll_interval)
            if self._stop_event.is_set():
                break
            self._poll()

    def _poll(self) -> None:
        """GET /quarantine/status?agent_id=...&operator_id=..."""
        try:
            sep = "&" if "?" in self._url else "?"
            full_url = (
                f"{self._url}{sep}"
                f"agent_id={urllib.request.quote(self._agent_id)}"
                f"&operator_id={urllib.request.quote(self._operator_id)}"
            )
            req = urllib.request.Request(full_url, method="GET")
            req.add_header("Accept", "application/json")
            if self._api_key:
                req.add_header("Authorization", f"Bearer {self._api_key}")
            with urllib.request.urlopen(req, timeout=_POLL_TIMEOUT) as resp:
                data: dict[str, Any] = json.loads(resp.read())

            quarantined = bool(data.get("quarantined", False))
            reason = str(data.get("reason", ""))
            severity = str(data.get("severity", ""))

            with self._lock:
                self._quarantined = quarantined
                self._reason = reason
                self._severity = severity
        except Exception:
            # Network failure — keep previous state (fail-last).
            # If monitor said "quarantined" and network drops, the agent
            # stays quarantined — the safe direction.
            logger.debug("Quarantine poll failed for %s", self._url, exc_info=True)
