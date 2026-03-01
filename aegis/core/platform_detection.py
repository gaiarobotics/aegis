"""AEGIS platform auto-detection — identifies deployment platforms at runtime."""

from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Agent ID prefixes that indicate a known platform
_PLATFORM_PREFIXES = {"moltbook", "openclaw", "slack", "discord"}

# Tool call patterns that indicate Moltbook/OpenClaw usage
_MOLTBOOK_TOOL_PATTERNS = (
    "heartbeat.md",
    "moltbook",
    ".openclaw",
    ".moltbot",
    ".clawdbot",
)


class PlatformDetector:
    """Detects deployment platforms from agent IDs and tool call patterns.

    Once a platform is detected, it stays active for the session (one-way latch).
    Fires an optional callback on first activation.

    Args:
        on_activate: Callback invoked with platform name on first detection.
        explicit_profiles: Set of profile names already explicitly activated.
            Auto-detection is suppressed for these platforms.
    """

    def __init__(
        self,
        on_activate: Optional[Callable[[str], None]] = None,
        explicit_profiles: Optional[set[str]] = None,
    ) -> None:
        self._active: set[str] = set()
        self._on_activate = on_activate
        self._explicit = explicit_profiles or set()
        self._lock = threading.Lock()

    @property
    def active_platforms(self) -> set[str]:
        """Currently detected platforms."""
        with self._lock:
            return set(self._active)

    def is_active(self, platform: str) -> bool:
        """Check if a platform has been detected."""
        with self._lock:
            return platform in self._active or platform in self._explicit

    def check_agent_id(self, canonical_id: str) -> None:
        """Check a canonical agent ID for platform prefix."""
        for prefix in _PLATFORM_PREFIXES:
            if canonical_id.startswith(f"{prefix}:"):
                self._activate(prefix)
                return

    def check_tool_call(
        self,
        tool_name: str,
        target: str = "",
    ) -> None:
        """Check a tool call for platform-indicative patterns."""
        combined = f"{tool_name} {target}".lower()
        for pattern in _MOLTBOOK_TOOL_PATTERNS:
            if pattern in combined:
                self._activate("moltbook")
                return

    def _activate(self, platform: str) -> None:
        """Activate a platform (one-way latch, thread-safe)."""
        with self._lock:
            if platform in self._active or platform in self._explicit:
                return
            self._active.add(platform)
            callback = self._on_activate

        # Fire callback outside lock to prevent deadlocks
        if callback is not None:
            try:
                callback(platform)
            except Exception:
                logger.debug("Platform activation callback failed", exc_info=True)
