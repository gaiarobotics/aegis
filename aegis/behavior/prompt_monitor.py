"""System prompt and core file integrity monitoring.

Tracks the SHA-256 hash of the system prompt across LLM calls and
optionally monitors configured files (e.g. SOUL.md) for modifications.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from pathlib import Path
from typing import Any

from aegis.core.config import PromptMonitorConfig

logger = logging.getLogger(__name__)


class PromptMonitor:
    """Monitors system prompt integrity and watched file changes.

    On the first call to :meth:`check`, the system prompt hash is recorded
    as the baseline.  Subsequent calls return ``True`` if the hash has
    changed.  Optionally watches a list of file paths for modifications.

    Args:
        config: Optional dict with ``watch_files`` (list of paths).
    """

    def __init__(self, config: PromptMonitorConfig | None = None) -> None:
        config = config or PromptMonitorConfig()
        self._watch_files: list[str] = list(config.watch_files)
        self._prompt_hash: str | None = None
        self._file_hashes: dict[str, str] = {}
        self._lock = threading.Lock()
        self._init_file_hashes()

    def _init_file_hashes(self) -> None:
        """Hash each watched file that exists on disk."""
        for path_str in self._watch_files:
            try:
                p = Path(path_str)
                if p.is_file():
                    self._file_hashes[path_str] = hashlib.sha256(
                        p.read_bytes()
                    ).hexdigest()
            except Exception:
                logger.debug("Failed to hash watched file %s", path_str, exc_info=True)

    @staticmethod
    def _extract_system_prompt(kwargs: dict[str, Any]) -> str | None:
        """Extract the system prompt from provider-specific kwargs.

        Handles:
        - Anthropic: ``kwargs["system"]``
        - OpenAI / Generic: first message with ``role == "system"``
        """
        # Anthropic passes system prompt as top-level kwarg
        system = kwargs.get("system")
        if isinstance(system, str) and system:
            return system

        # OpenAI / Generic embed it in the messages array
        messages = kwargs.get("messages")
        if isinstance(messages, list):
            for msg in messages:
                if isinstance(msg, dict) and msg.get("role") == "system":
                    content = msg.get("content", "")
                    if isinstance(content, str) and content:
                        return content
        return None

    def check(self, kwargs: dict[str, Any]) -> bool:
        """Check for system prompt or watched file changes.

        Returns ``True`` if the system prompt hash differs from baseline
        or any watched file has been modified.  The first call establishes
        the baseline and always returns ``False``.
        """
        changed = False

        prompt_text = self._extract_system_prompt(kwargs)

        with self._lock:
            if prompt_text is not None:
                current_hash = hashlib.sha256(
                    prompt_text.encode("utf-8")
                ).hexdigest()
                if self._prompt_hash is None:
                    # First call — establish baseline
                    self._prompt_hash = current_hash
                elif current_hash != self._prompt_hash:
                    changed = True

        # Check watched files (outside lock — file I/O may be slow)
        if not changed:
            changed = self._check_watched_files()

        return changed

    def _check_watched_files(self) -> bool:
        """Return True if any watched file has changed since init."""
        for path_str in self._watch_files:
            try:
                p = Path(path_str)
                if not p.is_file():
                    continue
                current_hash = hashlib.sha256(p.read_bytes()).hexdigest()
                baseline = self._file_hashes.get(path_str)
                if baseline is not None and current_hash != baseline:
                    return True
            except Exception:
                logger.debug(
                    "Failed to check watched file %s", path_str, exc_info=True
                )
        return False

    def reset(self) -> None:
        """Clear stored hashes so the next call re-establishes baselines."""
        with self._lock:
            self._prompt_hash = None
        self._file_hashes.clear()
        self._init_file_hashes()
