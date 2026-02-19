"""AEGIS Scanner module — unified threat detection and mitigation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from aegis.core import killswitch
from aegis.core.config import AegisConfig
from aegis.scanner.envelope import PromptEnvelope
from aegis.scanner.llm_guard import LLMGuardAdapter, LLMGuardResult
from aegis.scanner.pattern_matcher import PatternMatcher, ThreatMatch
from aegis.scanner.pii import PiiDetector, PiiResult
from aegis.scanner.sanitizer import OutboundSanitizer, SanitizeResult
from aegis.scanner.semantic import SemanticAnalyzer, SemanticResult
from aegis.scanner.signatures import Signature, load_signatures


@dataclass
class ScanResult:
    """Result of a combined input scan."""

    matches: list[ThreatMatch] = field(default_factory=list)
    semantic_result: Optional[SemanticResult] = None
    llm_guard_result: Optional[LLMGuardResult] = None
    pii_result: Optional[PiiResult] = None
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
        signatures = load_signatures(
            use_bundled=scanner_cfg.signatures.use_bundled,
            additional_files=scanner_cfg.signatures.additional_files or None,
        )
        self._pattern_matcher: Optional[PatternMatcher] = None
        if scanner_cfg.pattern_matching:
            self._pattern_matcher = PatternMatcher(
                signatures=signatures,
                sensitivity=scanner_cfg.sensitivity,
            )

        # Init semantic analyzer
        self._semantic_analyzer: Optional[SemanticAnalyzer] = None
        if scanner_cfg.semantic_analysis:
            self._semantic_analyzer = SemanticAnalyzer()

        # Init prompt envelope
        self._envelope = PromptEnvelope(config=scanner_cfg)

        # Init outbound sanitizer
        self._sanitizer = OutboundSanitizer(config=scanner_cfg)

        # Init LLM Guard adapter (optional ML-based scanning)
        self._llm_guard: Optional[LLMGuardAdapter] = None
        if scanner_cfg.llm_guard.enabled:
            self._llm_guard = LLMGuardAdapter(config=scanner_cfg.llm_guard)

        # Init PII detector (optional Presidio-based)
        self._pii_detector: Optional[PiiDetector] = None
        if scanner_cfg.pii.enabled:
            self._pii_detector = PiiDetector(config=scanner_cfg.pii)

        # Threat threshold from config
        self._confidence_threshold = scanner_cfg.confidence_threshold

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
        llm_guard_result: Optional[LLMGuardResult] = None

        # Pattern matching
        if self._pattern_matcher is not None:
            matches = self._pattern_matcher.scan(text)

        # Semantic analysis
        if self._semantic_analyzer is not None:
            semantic_result = self._semantic_analyzer.analyze(text)

        # LLM Guard ML-based scanning
        if self._llm_guard is not None:
            llm_guard_result = self._llm_guard.scan(text)

        # PII detection (input awareness)
        pii_result: Optional[PiiResult] = None
        if self._pii_detector is not None:
            pii_result = self._pii_detector.detect(text)

        # Compute combined threat score
        threat_score = self._compute_threat_score(matches, semantic_result, llm_guard_result)
        is_threat = threat_score >= self._confidence_threshold

        return ScanResult(
            matches=matches,
            semantic_result=semantic_result,
            llm_guard_result=llm_guard_result,
            pii_result=pii_result,
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

        result = self._sanitizer.sanitize(text)

        # PII redaction on output
        if self._pii_detector is not None:
            pii_result = self._pii_detector.redact(result.cleaned_text)
            if pii_result.had_pii:
                result = SanitizeResult(
                    cleaned_text=pii_result.redacted_text,
                    modifications=result.modifications + [
                        {
                            "type": "pii_redaction",
                            "description": f"Redacted {len(pii_result.entities)} PII entities",
                            "entity_types": list({e.entity_type for e in pii_result.entities}),
                        }
                    ],
                )

        return result

    def _compute_threat_score(
        self,
        matches: list[ThreatMatch],
        semantic_result: Optional[SemanticResult],
        llm_guard_result: Optional[LLMGuardResult] = None,
    ) -> float:
        """Compute a combined threat score from all detection tiers.

        Tiers:
            1. Pattern matching (regex signatures)
            2. Semantic analysis (heuristics)
            3. LLM Guard (ML classifiers, optional)

        ML scores are weighted higher when present because transformer-based
        classifiers are more accurate than pattern/heuristic approaches.
        """
        heuristic_scores: list[float] = []
        ml_score: float | None = None

        if matches:
            max_match_confidence = max(m.confidence for m in matches)
            heuristic_scores.append(max_match_confidence)

        if semantic_result and semantic_result.aggregate_score > 0:
            heuristic_scores.append(semantic_result.aggregate_score)

        if llm_guard_result and llm_guard_result.aggregate_score > 0:
            ml_score = llm_guard_result.aggregate_score

        # No signals at all
        if not heuristic_scores and ml_score is None:
            return 0.0

        # ML-only
        if not heuristic_scores and ml_score is not None:
            return ml_score

        # Heuristic-only (original logic)
        heuristic_max = max(heuristic_scores) if heuristic_scores else 0.0
        if ml_score is None:
            if len(heuristic_scores) > 1:
                avg = sum(heuristic_scores) / len(heuristic_scores)
                combined = min(heuristic_max * 0.7 + avg * 0.3, 1.0)
                # Boost when multiple heuristic detectors agree
                if all(s > 0.5 for s in heuristic_scores):
                    combined = min(combined + 0.05, 1.0)
                return combined
            return heuristic_max

        # Both ML and heuristic — ML gets higher weight
        combined = ml_score * 0.6 + heuristic_max * 0.4
        # Boost when both tiers agree the input is threatening
        if ml_score > 0.5 and heuristic_max > 0.5:
            combined = min(combined + 0.1, 1.0)
        return min(combined, 1.0)
