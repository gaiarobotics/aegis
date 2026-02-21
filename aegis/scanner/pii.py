"""Presidio PII detection — optional PII detection and redaction.

Wraps presidio-analyzer and presidio-anonymizer for detecting and redacting
personally identifiable information in model inputs and outputs.

Requires: pip install aegis-shield[pii]
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

from aegis.core.config import PiiConfig

logger = logging.getLogger(__name__)

_PRESIDIO_AVAILABLE: bool | None = None


def is_presidio_available() -> bool:
    """Check whether presidio-analyzer is importable."""
    global _PRESIDIO_AVAILABLE
    if _PRESIDIO_AVAILABLE is None:
        try:
            import presidio_analyzer  # noqa: F401

            _PRESIDIO_AVAILABLE = True
        except ImportError:
            _PRESIDIO_AVAILABLE = False
    return _PRESIDIO_AVAILABLE


@dataclass
class PiiEntity:
    """A single detected PII entity."""

    entity_type: str  # "EMAIL_ADDRESS", "PHONE_NUMBER", etc.
    text: str  # The detected PII text
    start: int
    end: int
    score: float


@dataclass
class PiiResult:
    """Result from PII detection or redaction."""

    entities: list[PiiEntity] = field(default_factory=list)
    redacted_text: str = ""
    had_pii: bool = False


class PiiDetector:
    """Detects and redacts PII using Microsoft Presidio.

    Lazily initializes Presidio engines on first use.

    Args:
        config: PiiConfig with entity types, thresholds, and redaction settings.
    """

    def __init__(self, config: PiiConfig | None = None) -> None:
        self._config = config or PiiConfig()
        self._analyzer: Any = None
        self._anonymizer: Any = None
        self._initialized = False
        self._init_lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    def _init_engines(self) -> None:
        """Lazily initialize Presidio engines on first call."""
        with self._init_lock:
            if self._initialized:
                return
            self._initialized = True

            if not is_presidio_available():
                logger.warning(
                    "presidio-analyzer package not installed. "
                    "Install with: pip install aegis-shield[pii]"
                )
                return

            try:
                from presidio_analyzer import AnalyzerEngine

                self._analyzer = AnalyzerEngine()
                logger.info("Presidio AnalyzerEngine initialized")
            except Exception:
                logger.warning(
                    "Failed to initialize Presidio AnalyzerEngine", exc_info=True
                )

            try:
                from presidio_anonymizer import AnonymizerEngine

                self._anonymizer = AnonymizerEngine()
                logger.info("Presidio AnonymizerEngine initialized")
            except Exception:
                logger.warning(
                    "Failed to initialize Presidio AnonymizerEngine", exc_info=True
                )

    def detect(self, text: str) -> PiiResult:
        """Detect PII entities in text without modifying it.

        Returns:
            PiiResult with detected entities. Returns empty result if
            Presidio is not available or detection is disabled.
        """
        if not self._config.enabled:
            return PiiResult(redacted_text=text)

        self._init_engines()

        if self._analyzer is None:
            return PiiResult(redacted_text=text)

        try:
            results = self._analyzer.analyze(
                text=text,
                entities=self._config.entities,
                language="en",
                score_threshold=self._config.score_threshold,
            )

            entities = [
                PiiEntity(
                    entity_type=r.entity_type,
                    text=text[r.start : r.end],
                    start=r.start,
                    end=r.end,
                    score=r.score,
                )
                for r in results
            ]

            return PiiResult(
                entities=entities,
                redacted_text=text,
                had_pii=len(entities) > 0,
            )
        except Exception:
            logger.warning("Presidio PII detection failed", exc_info=True)
            return PiiResult(redacted_text=text)

    def redact(self, text: str) -> PiiResult:
        """Detect and redact PII entities in text.

        Returns:
            PiiResult with redacted text and detected entities.
        """
        if not self._config.enabled:
            return PiiResult(redacted_text=text)

        self._init_engines()

        if self._analyzer is None:
            return PiiResult(redacted_text=text)

        try:
            results = self._analyzer.analyze(
                text=text,
                entities=self._config.entities,
                language="en",
                score_threshold=self._config.score_threshold,
            )

            entities = [
                PiiEntity(
                    entity_type=r.entity_type,
                    text=text[r.start : r.end],
                    start=r.start,
                    end=r.end,
                    score=r.score,
                )
                for r in results
            ]

            if not entities:
                return PiiResult(redacted_text=text, had_pii=False)

            # Redact using anonymizer if available, else manual redaction
            redacted = text
            if self._anonymizer is not None:
                try:
                    from presidio_anonymizer.entities import OperatorConfig

                    operators: dict[str, Any] = {
                        "DEFAULT": OperatorConfig(
                            "replace",
                            {"new_value": self._config.redact_char * 5},
                        )
                    }
                    if self._config.action == "redact":
                        operators = {
                            "DEFAULT": OperatorConfig(
                                "mask",
                                {
                                    "chars_to_mask": 100,
                                    "masking_char": self._config.redact_char,
                                    "from_end": False,
                                },
                            )
                        }
                    anon_result = self._anonymizer.anonymize(
                        text=text,
                        analyzer_results=results,
                        operators=operators,
                    )
                    redacted = anon_result.text
                except Exception:
                    logger.warning(
                        "Presidio anonymization failed, using manual redaction",
                        exc_info=True,
                    )
                    redacted = self._manual_redact(text, entities)
            else:
                redacted = self._manual_redact(text, entities)

            return PiiResult(
                entities=entities,
                redacted_text=redacted,
                had_pii=True,
            )
        except Exception:
            logger.warning("Presidio PII redaction failed", exc_info=True)
            return PiiResult(redacted_text=text)

    def _manual_redact(self, text: str, entities: list[PiiEntity]) -> str:
        """Manual redaction fallback when anonymizer is unavailable."""
        # Sort entities by start position in reverse to avoid index shifting
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        result = text
        for entity in sorted_entities:
            replacement = self._config.redact_char * len(entity.text)
            result = result[: entity.start] + replacement + result[entity.end :]
        return result
