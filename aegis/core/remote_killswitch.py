"""Remote killswitch — polls external monitors to determine if inference should halt.

The control plane lives outside the agent's runtime, so a compromised agent
cannot disable it.  When ``monitors`` is empty the killswitch is inert (no
threads, no polling, no overhead).
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from aegis.core.config import KillswitchConfig

logger = logging.getLogger(__name__)

_AEGIS_CENTRAL_URL = "https://aegis.gaiarobotics.com/api/v1/killswitch/status"
_POLL_TIMEOUT = 5  # seconds


@dataclass
class MonitorState:
    """Per-URL cached state from a monitor endpoint."""

    blocked: bool = False
    reason: str = ""
    last_checked: float = 0.0
    last_response: float = 0.0


class RemoteKillswitch:
    """Polls remote monitors to determine if this agent should halt inference.

    Any single monitor returning ``blocked=True`` is sufficient to block the
    agent.  On network failure the last-known status is preserved (not
    fail-open, not fail-closed per-monitor).
    """

    def __init__(
        self,
        config: KillswitchConfig,
        agent_id: str = "",
        operator_id: str = "",
    ) -> None:
        self._ttl = config.ttl_seconds
        self._agent_id = agent_id
        self._operator_id = operator_id

        # Expand aliases and build per-URL state
        self._monitor_states: dict[str, MonitorState] = {}
        for url in config.monitors:
            resolved = _AEGIS_CENTRAL_URL if url == "aegis-central" else url
            self._monitor_states[resolved] = MonitorState()

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_blocked(self) -> bool:
        """Thread-safe.  Returns ``True`` if ANY monitor's last-known status is 'block'."""
        with self._lock:
            return any(s.blocked for s in self._monitor_states.values())

    @property
    def block_reason(self) -> str:
        """Human-readable reason from the first blocking monitor, or ``""``."""
        with self._lock:
            for s in self._monitor_states.values():
                if s.blocked:
                    return s.reason
        return ""

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
            self._thread.join(timeout=self._ttl + _POLL_TIMEOUT + 1)
            self._thread = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        """Poll all monitors sequentially every ``ttl_seconds``."""
        # Do an initial poll immediately
        self._poll_all()
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self._ttl)
            if self._stop_event.is_set():
                break
            self._poll_all()

    def _poll_all(self) -> None:
        for url in list(self._monitor_states.keys()):
            self._poll_one(url)

    def _poll_one(self, url: str) -> None:
        now = time.time()
        try:
            sep = "&" if "?" in url else "?"
            full_url = (
                f"{url}{sep}agent_id={urllib.request.quote(self._agent_id)}"
                f"&operator_id={urllib.request.quote(self._operator_id)}"
            )
            req = urllib.request.Request(full_url, method="GET")
            req.add_header("Accept", "application/json")
            with urllib.request.urlopen(req, timeout=_POLL_TIMEOUT) as resp:
                data: dict[str, Any] = json.loads(resp.read())

            blocked = bool(data.get("blocked", False))
            reason = str(data.get("reason", ""))

            with self._lock:
                state = self._monitor_states[url]
                state.blocked = blocked
                state.reason = reason
                state.last_checked = now
                state.last_response = now
        except Exception:
            # Network failure — keep previous blocked value (last-known)
            with self._lock:
                state = self._monitor_states[url]
                state.last_checked = now
            logger.debug("Killswitch poll failed for %s", url, exc_info=True)
