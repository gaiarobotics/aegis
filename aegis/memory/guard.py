"""Memory Guard — validates writes to agent memory stores."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from aegis.core.config import MemoryConfig


@dataclass
class MemoryEntry:
    """A single entry to be written to agent memory."""

    key: str
    value: str
    category: str
    provenance: str
    ttl: int | None  # hours
    timestamp: float
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class WriteResult:
    """Result of a write-validation check."""

    allowed: bool
    reason: str
    sanitized_value: str | None


class MemoryGuard:
    """Validates memory writes against category allowlists and an optional scanner."""

    def __init__(self, config: MemoryConfig | None = None, scanner: Any = None) -> None:
        self._config = config or MemoryConfig()
        self._scanner = scanner

    def validate_write(self, entry: MemoryEntry) -> WriteResult:
        """Validate whether *entry* may be persisted.

        Returns a :class:`WriteResult` indicating whether the write is allowed.
        """
        from aegis.core.killswitch import is_active as _killswitch_active

        # Killswitch active → passthrough (allow everything)
        if _killswitch_active():
            return WriteResult(allowed=True, reason="killswitch active – passthrough", sanitized_value=entry.value)

        # Category checks
        if entry.category in self._config.blocked_categories:
            return WriteResult(
                allowed=False,
                reason=f"Category '{entry.category}' is blocked",
                sanitized_value=None,
            )

        if entry.category not in self._config.allowed_categories:
            return WriteResult(
                allowed=False,
                reason=f"Category '{entry.category}' is unknown and not allowed",
                sanitized_value=None,
            )

        # Optional scanner check
        if self._scanner is not None:
            threats = self._scanner.scan(entry.value)
            if threats:
                return WriteResult(
                    allowed=False,
                    reason=f"Scanner detected threats: {threats}",
                    sanitized_value=None,
                )

        return WriteResult(allowed=True, reason="OK", sanitized_value=entry.value)
