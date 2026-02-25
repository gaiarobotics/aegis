"""Remote threat intelligence — polls the monitor for compromised agents and hashes.

Enables pre-emptive contagion avoidance: agents check incoming content
against known-bad signatures before the LLM processes it.  Mirrors the
RemoteKillswitch/RemoteQuarantine pattern: daemon thread, fail-last,
thread-safe reads.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

_POLL_TIMEOUT = 5  # seconds
_BITS = 128  # LSH hash width


def _hex_to_int(h: str) -> int:
    """Convert a hex string to an integer."""
    return int(h, 16)


def _hamming_distance(a: int, b: int) -> int:
    """Count differing bits between two integers."""
    return bin(a ^ b).count("1")


class RemoteThreatIntel:
    """Polls the monitoring service for threat intelligence.

    Caches compromised agent IDs, quarantined agent IDs, and
    compromised content hashes.  The Shield queries this cache
    during ``scan_input()`` to reject suspicious content before
    the LLM sees it.
    """

    def __init__(
        self,
        service_url: str,
        api_key: str,
        poll_interval: float = 30,
    ) -> None:
        self._url = f"{service_url.rstrip('/')}/threat-intel"
        self._api_key = api_key
        self._poll_interval = poll_interval

        self._compromised_agents: set[str] = set()
        self._quarantined_agents: set[str] = set()
        self._compromised_hashes: set[int] = set()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_agent_compromised(self, agent_id: str) -> bool:
        """Thread-safe check if an agent is known-compromised."""
        with self._lock:
            return agent_id in self._compromised_agents

    def is_agent_quarantined(self, agent_id: str) -> bool:
        """Thread-safe check if an agent is quarantined."""
        with self._lock:
            return agent_id in self._quarantined_agents

    def check_hash(
        self, hash_hex: str, threshold: float = 0.85,
    ) -> tuple[bool, float]:
        """Check a content hash against known-compromised hashes.

        Returns ``(is_suspicious, max_similarity)`` where similarity
        is ``1.0 - hamming_distance / 128``.
        """
        if not hash_hex:
            return False, 0.0

        with self._lock:
            if not self._compromised_hashes:
                return False, 0.0
            hashes = list(self._compromised_hashes)

        h = _hex_to_int(hash_hex)
        max_sim = 0.0
        for comp_hash in hashes:
            dist = _hamming_distance(h, comp_hash)
            sim = 1.0 - (dist / _BITS)
            if sim > max_sim:
                max_sim = sim

        return max_sim >= threshold, max_sim

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
        self._poll()
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self._poll_interval)
            if self._stop_event.is_set():
                break
            self._poll()

    def _poll(self) -> None:
        try:
            req = urllib.request.Request(self._url, method="GET")
            req.add_header("Accept", "application/json")
            if self._api_key:
                req.add_header("Authorization", f"Bearer {self._api_key}")
            with urllib.request.urlopen(req, timeout=_POLL_TIMEOUT) as resp:
                data: dict[str, Any] = json.loads(resp.read())

            compromised_agents = set(data.get("compromised_agents", []))
            quarantined_agents = set(data.get("quarantined_agents", []))
            compromised_hashes: set[int] = set()
            for h in data.get("compromised_hashes", []):
                try:
                    compromised_hashes.add(_hex_to_int(h))
                except (ValueError, TypeError):
                    pass

            with self._lock:
                self._compromised_agents = compromised_agents
                self._quarantined_agents = quarantined_agents
                self._compromised_hashes = compromised_hashes
        except Exception:
            # Fail-last: preserve cached data on network error
            logger.debug("Threat intel poll failed for %s", self._url, exc_info=True)
