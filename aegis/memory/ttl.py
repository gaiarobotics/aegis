"""TTL management and diff-anomaly detection for agent memory."""
from __future__ import annotations

import time
from typing import Sequence

from aegis.memory.guard import MemoryEntry

# Default TTL: 7 days in hours.
DEFAULT_TTL_HOURS: int = 168

# Keywords that signal blocked-category content (potential injection).
_BLOCKED_KEYWORDS = frozenset({
    "instruction", "policy", "directive", "tool_config",
    "override", "ignore", "execute", "shell", "sudo",
})


class TTLManager:
    """Checks memory entries for expiry and detects diff anomalies."""

    def check_expired(
        self,
        entries: Sequence[MemoryEntry],
        now: float | None = None,
    ) -> tuple[list[MemoryEntry], list[MemoryEntry]]:
        """Partition *entries* into (valid, expired).

        An entry is expired when ``now >= entry.timestamp + ttl_hours * 3600``.
        If the entry has no explicit TTL, the default (168 h / 7 days) is used.
        """
        if now is None:
            now = time.time()

        valid: list[MemoryEntry] = []
        expired: list[MemoryEntry] = []

        for entry in entries:
            ttl_hours = entry.ttl if entry.ttl is not None else DEFAULT_TTL_HOURS
            expiry = entry.timestamp + ttl_hours * 3600
            if now >= expiry:
                expired.append(entry)
            else:
                valid.append(entry)

        return valid, expired

    def check_diff_anomaly(
        self,
        old_state: Sequence[MemoryEntry],
        new_state: Sequence[MemoryEntry],
    ) -> list[dict]:
        """Detect additions that look like global overrides or tool directives.

        Compares *new_state* against *old_state* and flags any new entries whose
        value contains blocked-category keywords.
        """
        old_keys = {e.key for e in old_state}
        additions = [e for e in new_state if e.key not in old_keys]

        anomalies: list[dict] = []
        for entry in additions:
            value_lower = entry.value.lower()
            matched = [kw for kw in _BLOCKED_KEYWORDS if kw in value_lower]
            if matched:
                anomalies.append({
                    "key": entry.key,
                    "value": entry.value,
                    "matched_keywords": matched,
                    "reason": f"Suspicious addition: value contains blocked keywords {matched}",
                })

        return anomalies
