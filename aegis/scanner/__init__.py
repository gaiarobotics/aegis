"""AEGIS Scanner module — unified threat detection and mitigation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from aegis.core import killswitch
from aegis.core.config import AegisConfig
from aegis.scanner.envelope import PromptEnvelope
from aegis.scanner.pattern_matcher import PatternMatcher, ThreatMatch
from aegis.scanner.sanitizer import OutboundSanitizer, SanitizeResult
from aegis.scanner.semantic import SemanticAnalyzer, SemanticResult
from aegis.scanner.signatures import Signature, load_signatures


@dataclass
class ScanResult:
    """Result of a combined input scan."""

    matches: list[ThreatMatch] = field(default_factory=list)
    semantic_result: Optional[SemanticResult] = None
    threat_score: float = 0.0
    is_threat: bool = False


class Scanner:
    """Unified AEGIS scanner combining pattern matching, semantic analysis,
    prompt envelope, and outbound sanitization.

    Args:
        config: Optional AegisConfig. If not provided, defaults are used.
    """

    def __init__(self, config: Optional[AegisConfig] = None) -> None:
        if config is None:
            config = AegisConfig()

        self._config = config
        scanner_cfg = config.scanner

        # Load signatures and init pattern matcher
        sig_cfg = scanner_cfg.get("signatures", {})
        signatures = load_signatures(
            use_bundled=sig_cfg.get("use_bundled", True),
            additional_files=sig_cfg.get("additional_files", []) or None,
        )
        self._pattern_matcher: Optional[PatternMatcher] = None
        if scanner_cfg.get("pattern_matching", True):
            self._pattern_matcher = PatternMatcher(
                signatures=signatures,
                sensitivity=scanner_cfg.get("sensitivity", 0.5),
            )

        # Init semantic analyzer
        self._semantic_analyzer: Optional[SemanticAnalyzer] = None
        if scanner_cfg.get("semantic_analysis", True):
            self._semantic_analyzer = SemanticAnalyzer()

        # Init prompt envelope
        self._envelope = PromptEnvelope(config=scanner_cfg)

        # Init outbound sanitizer
        self._sanitizer = OutboundSanitizer(config=scanner_cfg)

        # Threat threshold from config
        self._confidence_threshold = scanner_cfg.get("confidence_threshold", 0.7)

    def scan_input(self, text: str) -> ScanResult:
        """Scan input text for threats using pattern matching and semantic analysis.

        Args:
            text: The input text to scan.

        Returns:
            ScanResult with combined findings. Returns clean/empty result
            when killswitch is active.
        """
        if killswitch.is_active():
            return ScanResult()

        matches: list[ThreatMatch] = []
        semantic_result: Optional[SemanticResult] = None

        # Pattern matching
        if self._pattern_matcher is not None:
            matches = self._pattern_matcher.scan(text)

        # Semantic analysis
        if self._semantic_analyzer is not None:
            semantic_result = self._semantic_analyzer.analyze(text)

        # Compute combined threat score
        threat_score = self._compute_threat_score(matches, semantic_result)
        is_threat = threat_score >= self._confidence_threshold

        return ScanResult(
            matches=matches,
            semantic_result=semantic_result,
            threat_score=round(threat_score, 4),
            is_threat=is_threat,
        )

    def wrap_messages(
        self,
        messages: list[dict[str, Any]],
        provenance_map: Optional[dict[int | str, str]] = None,
    ) -> list[dict[str, Any]]:
        """Wrap messages with provenance tags.

        Delegates to PromptEnvelope. Returns messages unchanged when
        killswitch is active.
        """
        if killswitch.is_active():
            return messages

        return self._envelope.wrap_messages(messages, provenance_map=provenance_map)

    def sanitize_output(self, text: str) -> SanitizeResult:
        """Sanitize model output text.

        Delegates to OutboundSanitizer. Returns clean result when
        killswitch is active.
        """
        if killswitch.is_active():
            return SanitizeResult(cleaned_text=text, modifications=[])

        return self._sanitizer.sanitize(text)

    def _compute_threat_score(
        self,
        matches: list[ThreatMatch],
        semantic_result: Optional[SemanticResult],
    ) -> float:
        """Compute a combined threat score from pattern matches and semantic analysis."""
        scores: list[float] = []

        if matches:
            max_match_confidence = max(m.confidence for m in matches)
            scores.append(max_match_confidence)

        if semantic_result and semantic_result.aggregate_score > 0:
            scores.append(semantic_result.aggregate_score)

        if not scores:
            return 0.0

        # Combined: take the max and boost slightly if both sources agree
        max_score = max(scores)
        if len(scores) > 1:
            avg_score = sum(scores) / len(scores)
            combined = max_score * 0.7 + avg_score * 0.3
            return min(combined, 1.0)

        return max_score
