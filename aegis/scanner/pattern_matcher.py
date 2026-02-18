"""AEGIS pattern-based threat matching engine."""

from __future__ import annotations

import re as _re
import unicodedata
from dataclasses import dataclass

from aegis.scanner.signatures import Signature


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

    Args:
        signatures: List of compiled Signature objects to match against.
        sensitivity: Threshold (0.0-1.0) for filtering matches by confidence.
            Lower values return more matches; higher values are stricter.
    """

    def __init__(self, signatures: list[Signature], sensitivity: float = 0.5) -> None:
        self._signatures = signatures
        self._sensitivity = max(0.0, min(1.0, sensitivity))

    @property
    def sensitivity(self) -> float:
        """Current sensitivity threshold."""
        return self._sensitivity

    def scan(self, text: str) -> list[ThreatMatch]:
        """Run all signatures against the input text.

        Args:
            text: The text to scan for threats.

        Returns:
            List of ThreatMatch objects for patterns that matched
            and passed the sensitivity threshold.
        """
        # Unicode normalization to prevent evasion via confusable characters
        text = unicodedata.normalize("NFC", text)
        text = text.replace("\u00a0", " ")       # NBSP → space
        text = text.replace("\u00ad", "")         # soft hyphen → removed
        text = _re.sub(r"[\uFE00-\uFE0F]", "", text)  # variation selectors

        matches: list[ThreatMatch] = []

        for sig in self._signatures:
            match = sig.pattern.search(text)
            if match is None:
                continue

            matched_text = match.group(0)[:200]

            # Confidence equals severity — a match is a match regardless of
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
