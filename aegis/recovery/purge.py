"""Recovery purge module for AEGIS."""

import time
from dataclasses import dataclass, field


@dataclass
class PurgeResult:
    """Result of a purge operation."""

    purged_count: int
    purged_keys: list[str] = field(default_factory=list)


class MemoryPurge:
    """Manages memory purging for the AEGIS recovery system."""

    def purge_tainted(
        self,
        entries: dict,
        window_hours: float = 24,
    ) -> PurgeResult:
        """Remove entries that are tainted and within the time window.

        Args:
            entries: A mutable dict of entries. Each entry value should be a
                dict with at least 'tainted' (bool) and 'timestamp' (float) keys.
            window_hours: Only purge entries whose timestamp is within this
                many hours from now.

        Returns:
            A PurgeResult with the count and keys of purged entries.
        """
        now = time.time()
        window_seconds = window_hours * 3600
        cutoff = now - window_seconds

        keys_to_purge = [
            key
            for key, entry in entries.items()
            if entry.get("tainted", False) and entry.get("timestamp", 0) >= cutoff
        ]

        for key in keys_to_purge:
            del entries[key]

        return PurgeResult(purged_count=len(keys_to_purge), purged_keys=keys_to_purge)

    def purge_by_provenance(
        self,
        entries: dict,
        provenance: str,
    ) -> PurgeResult:
        """Remove entries matching a given provenance.

        Args:
            entries: A mutable dict of entries. Each entry value should be a
                dict with at least a 'provenance' key.
            provenance: The provenance value to match for purging.

        Returns:
            A PurgeResult with the count and keys of purged entries.
        """
        keys_to_purge = [
            key
            for key, entry in entries.items()
            if entry.get("provenance") == provenance
        ]

        for key in keys_to_purge:
            del entries[key]

        return PurgeResult(purged_count=len(keys_to_purge), purged_keys=keys_to_purge)
