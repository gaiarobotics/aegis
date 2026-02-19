"""YARA signature engine — optional high-performance multi-pattern matching.

Compiles AEGIS threat signatures into YARA rules for O(1) multi-pattern
scanning. Falls back to existing regex iteration when yara-python is
not installed.

Requires: pip install aegis-shield[yara]
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, field
from typing import Any

from aegis.scanner.signatures import Signature

logger = logging.getLogger(__name__)

_YARA_AVAILABLE: bool | None = None


def is_yara_available() -> bool:
    """Check whether the yara-python package is importable."""
    global _YARA_AVAILABLE
    if _YARA_AVAILABLE is None:
        try:
            import yara  # noqa: F401

            _YARA_AVAILABLE = True
        except ImportError:
            _YARA_AVAILABLE = False
    return _YARA_AVAILABLE


@dataclass(frozen=True)
class YaraMatch:
    """A single YARA match result."""

    signature_id: str
    category: str
    matched_text: str
    severity: float
    confidence: float


class YaraEngine:
    """Compiles AEGIS signatures into YARA rules for fast scanning.

    Lazily compiles rules on first scan. Thread-safe.

    Args:
        signatures: List of Signature objects to compile into YARA rules.
    """

    def __init__(self, signatures: list[Signature]) -> None:
        self._signatures = signatures
        self._rules = None
        self._sig_map: dict[str, Signature] = {}
        self._init_lock = threading.Lock()
        self._compiled = False
        self._skipped: list[str] = []

    def _compile_rules(self) -> None:
        """Convert Signature list to YARA rules and compile."""
        with self._init_lock:
            if self._compiled:
                return
            self._compiled = True

            if not is_yara_available():
                return

            import yara

            rule_parts: list[str] = []
            for sig in self._signatures:
                # Sanitize signature ID for YARA rule name
                safe_id = re.sub(r"[^a-zA-Z0-9_]", "_", sig.id)
                if safe_id[0].isdigit():
                    safe_id = "s_" + safe_id

                # Store mapping for result conversion
                self._sig_map[safe_id] = sig

                # Convert regex pattern to YARA string
                # Use the pattern source string
                pattern_str = sig.pattern.pattern

                rule = (
                    f"rule {safe_id} {{\n"
                    f"  meta:\n"
                    f'    category = "{sig.category}"\n'
                    f'    severity = "{sig.severity}"\n'
                    f"  strings:\n"
                    f"    $pattern = /{pattern_str}/ nocase\n"
                    f"  condition:\n"
                    f"    $pattern\n"
                    f"}}\n"
                )
                rule_parts.append(rule)

            if not rule_parts:
                return

            # Try to compile all rules; if any fail, compile individually
            combined = "\n".join(rule_parts)
            try:
                self._rules = yara.compile(source=combined)
            except Exception:
                logger.debug("Bulk YARA compilation failed, trying individual rules")
                self._compile_individual(rule_parts)

    def _compile_individual(self, rule_parts: list[str]) -> None:
        """Compile rules one by one, skipping any that fail."""
        import yara

        valid_rules: list[str] = []
        for rule_src in rule_parts:
            try:
                yara.compile(source=rule_src)
                valid_rules.append(rule_src)
            except Exception:
                # Extract rule name for logging
                name = rule_src.split("{")[0].replace("rule ", "").strip()
                self._skipped.append(name)
                logger.debug("Skipping YARA rule %s (compilation failed)", name)

        if valid_rules:
            try:
                self._rules = yara.compile(source="\n".join(valid_rules))
            except Exception:
                logger.warning("YARA compilation failed entirely", exc_info=True)
                self._rules = None

    def scan(self, text: str) -> list[YaraMatch]:
        """Scan text using compiled YARA rules.

        Returns:
            List of YaraMatch objects. Returns empty list if YARA is
            not available or compilation failed.
        """
        if not self._compiled:
            self._compile_rules()

        if self._rules is None:
            return []

        try:
            matches = self._rules.match(data=text.encode("utf-8"))
        except Exception:
            logger.debug("YARA scan failed", exc_info=True)
            return []

        results: list[YaraMatch] = []
        for match in matches:
            sig = self._sig_map.get(match.rule)
            if sig is None:
                continue

            # Get matched text from YARA strings
            matched_text = ""
            if match.strings:
                # YARA string matches: list of (offset, identifier, data)
                first = match.strings[0]
                if hasattr(first, "instances") and first.instances:
                    matched_text = first.instances[0].matched_data.decode(
                        "utf-8", errors="replace"
                    )[:200]
                elif isinstance(first, tuple) and len(first) >= 3:
                    matched_text = first[2].decode("utf-8", errors="replace")[:200]

            results.append(
                YaraMatch(
                    signature_id=sig.id,
                    category=sig.category,
                    matched_text=matched_text,
                    severity=sig.severity,
                    confidence=sig.severity,
                )
            )

        return results

    @property
    def skipped_rules(self) -> list[str]:
        """Rules that failed YARA compilation (handled by regex fallback)."""
        return list(self._skipped)
