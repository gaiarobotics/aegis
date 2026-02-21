"""Taint tracking — marks memory entries with provenance and taint status."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from aegis.memory.guard import MemoryEntry

# Provenances considered "trusted" (not tainted).
_TRUSTED_PROVENANCES = frozenset({"user", "system", "internal"})


@dataclass
class TaintedEntry:
    """A memory entry annotated with provenance and taint flag."""

    entry: MemoryEntry
    provenance: str
    tainted: bool


class TaintTracker:
    """Tracks provenance and taint status for memory entries."""

    def __init__(self) -> None:
        self._registry: dict[str, TaintedEntry] = {}

    def tag(self, entry: MemoryEntry, provenance: str) -> TaintedEntry:
        """Mark *entry* with the given *provenance* and compute taint status."""
        tainted = provenance not in _TRUSTED_PROVENANCES
        te = TaintedEntry(entry=entry, provenance=provenance, tainted=tainted)
        self._registry[entry.entry_id] = te
        return te

    def is_tainted(self, entry: MemoryEntry) -> bool:
        """Return whether *entry* has been tagged as tainted."""
        te = self._registry.get(entry.entry_id)
        if te is None:
            return False
        return te.tainted

    def get_provenance(self, entry: MemoryEntry) -> str:
        """Return the provenance string for a previously-tagged entry."""
        te = self._registry.get(entry.entry_id)
        if te is None:
            return "unknown"
        return te.provenance

    def filter_for_channel(
        self, entries: Sequence[MemoryEntry], channel: str
    ) -> list[MemoryEntry]:
        """Filter entries based on *channel*.

        * ``"trusted"`` — remove tainted entries.
        * ``"data"`` — return all entries.
        """
        if channel == "trusted":
            return [e for e in entries if not self.is_tainted(e)]
        # "data" or any other channel → return all
        return list(entries)
