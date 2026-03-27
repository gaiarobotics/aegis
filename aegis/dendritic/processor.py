"""Dendritic processor — chains content gate filtering, sanitizer stripping, and MHC tagging.

Analogous to dendritic cell antigen processing:
1. Capture (scanner detection)
2. Proteolysis (content gate sentence filtering + sanitizer stripping)
3. MHC-II loading (provenance tagging with danger signal)
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any

from aegis.dendritic.alert import DangerSignal, DendriticAlert, build_alert

logger = logging.getLogger(__name__)


@dataclass
class DendriticResult:
    """Result of dendritic processing on detected injection content."""

    cleaned_fragment: str
    danger_signal: DangerSignal
    original_hash: str
    modifications: list[dict[str, Any]] = field(default_factory=list)
    threat_score: float = 0.0
    source_agent_id: str = ""
    # True when the cleaned output still triggers the scanner, so content
    # was dropped entirely to prevent amplification.
    content_dropped: bool = False
    rescan_score: float | None = None


class DendriticProcessor:
    """Processes detected injections by stripping payloads and preparing alerts.

    Chains existing AEGIS components:
    - ContentGate sentence-level filtering (removes injection sentences)
    - OutboundSanitizer pattern stripping (removes authority markers, scaffolding)
    - Provenance tagging with dendritic-specific tags

    Args:
        content_gate: Optional ContentGate instance for sentence filtering.
        sanitizer: Optional OutboundSanitizer instance for pattern stripping.
        threat_score_thresholds: Dict mapping threat score ranges to danger signals.
    """

    # Default thresholds: score >= 0.7 → stop_and_alert_human,
    # >= 0.5 → quarantine_recommended, else → elevated_scrutiny
    DEFAULT_THRESHOLDS = {
        0.7: DangerSignal.STOP_AND_ALERT_HUMAN,
        0.5: DangerSignal.QUARANTINE_RECOMMENDED,
        0.0: DangerSignal.ELEVATED_SCRUTINY,
    }

    # If the re-scanned output scores at or above this fraction of the
    # original threat score, the content is dropped rather than retransmitted.
    DEFAULT_RESCAN_RATIO = 0.5

    def __init__(
        self,
        content_gate: Any = None,
        sanitizer: Any = None,
        scanner: Any = None,
        threat_score_thresholds: dict[float, DangerSignal] | None = None,
        rescan_ratio: float | None = None,
    ) -> None:
        self._content_gate = content_gate
        self._sanitizer = sanitizer
        self._scanner = scanner
        self._thresholds = threat_score_thresholds or self.DEFAULT_THRESHOLDS
        self._rescan_ratio = rescan_ratio if rescan_ratio is not None else self.DEFAULT_RESCAN_RATIO

    def process(
        self,
        text: str,
        threat_score: float,
        source_agent_id: str = "",
    ) -> DendriticResult:
        """Process detected injection content through the dendritic pipeline.

        1. Hash the original content for provenance tracking
        2. Filter through content gate (sentence-level injection removal)
        3. Strip through sanitizer (authority markers, scaffolding, tool-calls)
        4. Determine danger signal based on threat score
        5. Tag with dendritic provenance

        Args:
            text: The raw text containing a detected injection.
            threat_score: The scanner threat score from detection.
            source_agent_id: The agent that produced the injected content.

        Returns:
            DendriticResult with cleaned fragment and danger signal.
        """
        original_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        modifications: list[dict[str, Any]] = []
        cleaned = text

        # Step 1: Content gate sentence filtering (proteolysis phase 1)
        if self._content_gate is not None:
            try:
                gated = self._content_gate.process(cleaned, platform=None)
                if gated is not None:
                    modifications.append({
                        "type": "content_gate",
                        "description": f"Content gate applied ({gated.method})",
                        "original_length": gated.original_length,
                        "summary_length": len(gated.summary),
                    })
                    cleaned = gated.summary
            except Exception:
                logger.debug("Content gate processing failed during dendritic processing", exc_info=True)

        # Step 2: Sanitizer stripping (proteolysis phase 2)
        if self._sanitizer is not None:
            try:
                sanitize_result = self._sanitizer.sanitize(cleaned)
                if sanitize_result.modifications:
                    modifications.extend(sanitize_result.modifications)
                cleaned = sanitize_result.cleaned_text
            except Exception:
                logger.debug("Sanitizer failed during dendritic processing", exc_info=True)

        # Step 3: Re-scan gate — verify the cleaned output is actually clean.
        # If the output still triggers the scanner above the rescan threshold,
        # drop the content entirely to prevent amplification.
        content_dropped = False
        rescan_score: float | None = None

        if self._scanner is not None and cleaned.strip():
            try:
                rescan_result = self._scanner.scan_input(cleaned)
                rescan_score = rescan_result.threat_score
                # Drop if re-scan score >= rescan_ratio * original score,
                # OR if the re-scan independently flags it as a threat.
                threshold = self._rescan_ratio * threat_score
                if rescan_result.is_threat or rescan_score >= threshold:
                    logger.warning(
                        "Dendritic re-scan gate triggered: cleaned output still "
                        "scores %.3f (original: %.3f, threshold: %.3f). "
                        "Dropping content to prevent amplification.",
                        rescan_score,
                        threat_score,
                        threshold,
                    )
                    content_dropped = True
                    modifications.append({
                        "type": "rescan_gate",
                        "description": (
                            f"Content dropped: re-scan score {rescan_score:.3f} "
                            f"exceeded threshold {threshold:.3f}"
                        ),
                        "rescan_score": rescan_score,
                        "threshold": threshold,
                    })
                    cleaned = ""
            except Exception:
                logger.debug("Re-scan failed during dendritic processing", exc_info=True)

        # Step 4: Determine danger signal (MHC-II loading)
        danger_signal = self._resolve_danger_signal(threat_score)

        # Step 5: Tag with dendritic provenance (only if content survived)
        from aegis.scanner.envelope import DANGER_SIGNAL_TAG, DENDRITIC_PROCESSED
        if content_dropped:
            cleaned = f"{DENDRITIC_PROCESSED} {DANGER_SIGNAL_TAG} [CONTENT DROPPED — residual injection detected]"
        else:
            cleaned = f"{DENDRITIC_PROCESSED} {DANGER_SIGNAL_TAG} {cleaned}"

        return DendriticResult(
            cleaned_fragment=cleaned,
            danger_signal=danger_signal,
            original_hash=original_hash,
            modifications=modifications,
            threat_score=threat_score,
            source_agent_id=source_agent_id,
            content_dropped=content_dropped,
            rescan_score=rescan_score,
        )

    def build_signed_alert(
        self,
        result: DendriticResult,
        sentinel_id: str,
        signing_key: bytes,
        key_type: str = "hmac-sha256",
    ) -> DendriticAlert:
        """Build a signed DendriticAlert from a processing result.

        Args:
            result: The DendriticResult from process().
            sentinel_id: The sentinel's agent ID.
            signing_key: The sentinel's private/shared key.
            key_type: Key type for signing.

        Returns:
            A signed DendriticAlert ready for transmission via AlertChannel.
        """
        return build_alert(
            cleaned_fragment=result.cleaned_fragment,
            danger_signal=result.danger_signal,
            source_agent_id=result.source_agent_id,
            sentinel_id=sentinel_id,
            threat_score=result.threat_score,
            original_content_hash=result.original_hash,
            modifications=result.modifications,
            signing_key=signing_key,
            key_type=key_type,
        )

    def _resolve_danger_signal(self, threat_score: float) -> DangerSignal:
        """Map threat score to danger signal level."""
        for threshold in sorted(self._thresholds.keys(), reverse=True):
            if threat_score >= threshold:
                return self._thresholds[threshold]
        return DangerSignal.ELEVATED_SCRUTINY
