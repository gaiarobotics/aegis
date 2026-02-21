"""AEGIS pattern-based threat matching engine."""

from __future__ import annotations

import logging
import re as _re
import unicodedata
from dataclasses import dataclass

from aegis.scanner.signatures import Signature

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ThreatMatch:
    """A single threat match result."""

    signature_id: str
    category: str
    matched_text: str
    severity: float
    confidence: float


class PatternMatcher:
    """Scans text against precompiled threat signatures.

    Uses YARA engine for fast multi-pattern matching when available,
    with regex fallback for signatures that fail YARA compilation
    or when yara-python is not installed.

    Args:
        signatures: List of compiled Signature objects to match against.
        sensitivity: Threshold (0.0-1.0) for filtering matches by confidence.
    """

    def __init__(self, signatures: list[Signature], sensitivity: float = 0.5) -> None:
        self._signatures = signatures
        self._sensitivity = max(0.0, min(1.0, sensitivity))

        # Try to init YARA engine
        self._yara_engine = None
        try:
            from aegis.scanner.yara_engine import YaraEngine, is_yara_available

            if is_yara_available():
                self._yara_engine = YaraEngine(signatures)
        except Exception:
            logger.debug("YARA engine init failed, using regex fallback")

    @property
    def sensitivity(self) -> float:
        """Current sensitivity threshold."""
        return self._sensitivity

    def scan(self, text: str) -> list[ThreatMatch]:
        """Run all signatures against the input text.

        Prefers YARA engine when available. Falls back to regex
        iteration on failure or when YARA is not installed.
        """
        # Unicode normalization to prevent evasion
        text = unicodedata.normalize("NFC", text)
        text = text.replace("\u00a0", " ")  # NBSP -> space
        text = text.replace("\u00ad", "")  # soft hyphen -> removed
        text = _re.sub(r"[\uFE00-\uFE0F]", "", text)  # variation selectors

        # Try YARA fast path
        if self._yara_engine is not None:
            try:
                yara_matches = self._yara_engine.scan(text)
                if yara_matches:
                    matches = [
                        ThreatMatch(
                            signature_id=m.signature_id,
                            category=m.category,
                            matched_text=m.matched_text,
                            severity=m.severity,
                            confidence=round(m.confidence, 4),
                        )
                        for m in yara_matches
                        if m.confidence >= self._sensitivity
                    ]
                    return matches
            except Exception:
                logger.debug("YARA scan failed, falling back to regex")

        # Regex fallback (original logic)
        return self._regex_scan(text)

    def _regex_scan(self, text: str) -> list[ThreatMatch]:
        """Original regex-based scanning."""
        matches: list[ThreatMatch] = []

        for sig in self._signatures:
            match = sig.pattern.search(text)
            if match is None:
                continue

            matched_text = match.group(0)[:200]

            # Confidence equals severity -- a match is a match regardless of
            # surrounding text length (prevents dilution via padding attacks).
            confidence = sig.severity

            # Filter by sensitivity threshold
            if confidence < self._sensitivity:
                continue

            matches.append(
                ThreatMatch(
                    signature_id=sig.id,
                    category=sig.category,
                    matched_text=matched_text,
                    severity=sig.severity,
                    confidence=round(confidence, 4),
                )
            )

        return matches
