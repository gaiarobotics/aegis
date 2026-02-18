"""AEGIS pattern-based threat matching engine."""

from __future__ import annotations

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
        matches: list[ThreatMatch] = []

        for sig in self._signatures:
            match = sig.pattern.search(text)
            if match is None:
                continue

            matched_text = match.group(0)

            # Confidence is based on severity and match quality
            # Longer matches relative to text length boost confidence slightly
            match_ratio = min(len(matched_text) / max(len(text), 1), 1.0)
            confidence = sig.severity * (0.7 + 0.3 * match_ratio)
            confidence = min(confidence, 1.0)

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
