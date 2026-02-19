"""LLM Guard integration — optional ML-based scanning via llm-guard scanners.

Wraps LLM Guard input scanners (PromptInjection, Toxicity, BanTopics) as an
additional detection tier alongside the existing regex/heuristic approach.

Requires: pip install aegis-shield[ml]
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Optional

from aegis.core.config import LLMGuardConfig

logger = logging.getLogger(__name__)

# Sentinel for "package not installed"
_LLM_GUARD_AVAILABLE: bool | None = None


def is_llm_guard_available() -> bool:
    """Check whether the llm-guard package is importable."""
    global _LLM_GUARD_AVAILABLE
    if _LLM_GUARD_AVAILABLE is None:
        try:
            import llm_guard  # noqa: F401

            _LLM_GUARD_AVAILABLE = True
        except ImportError:
            _LLM_GUARD_AVAILABLE = False
    return _LLM_GUARD_AVAILABLE


@dataclass
class LLMGuardScannerResult:
    """Result from a single LLM Guard scanner."""

    scanner_name: str
    sanitized_text: str
    is_valid: bool
    risk_score: float


@dataclass
class LLMGuardResult:
    """Aggregated result from all enabled LLM Guard scanners."""

    scanner_results: list[LLMGuardScannerResult] = field(default_factory=list)
    aggregate_score: float = 0.0
    is_threat: bool = False

    @property
    def active_scanner_count(self) -> int:
        return len(self.scanner_results)


class LLMGuardAdapter:
    """Adapter bridging LLM Guard scanners into the AEGIS scanner pipeline.

    Lazily initializes LLM Guard scanners on first use to avoid model
    download/load overhead until actually needed.

    Args:
        config: The ``scanner.llm_guard`` LLMGuardConfig. If not provided,
                defaults are used (all scanners disabled).
    """

    def __init__(self, config: LLMGuardConfig | None = None) -> None:
        self._config = config or LLMGuardConfig()
        self._scanners: dict[str, Any] | None = None
        self._initialized = False
        self._init_lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    def _init_scanners(self) -> None:
        """Lazily initialize LLM Guard scanners on first scan call."""
        with self._init_lock:
            if self._initialized:
                return
            self._initialized = True
            self._scanners = {}

            if not is_llm_guard_available():
                logger.warning(
                    "llm-guard package not installed. "
                    "Install with: pip install aegis-shield[ml]"
                )
                return

            if self._config.prompt_injection.enabled:
                try:
                    from llm_guard.input_scanners import PromptInjection

                    kwargs: dict[str, Any] = {}
                    kwargs["threshold"] = self._config.prompt_injection.threshold
                    if self._config.prompt_injection.model is not None:
                        kwargs["model"] = self._config.prompt_injection.model
                    self._scanners["prompt_injection"] = PromptInjection(**kwargs)
                    logger.info("LLM Guard PromptInjection scanner initialized")
                except Exception:
                    logger.warning("Failed to initialize LLM Guard PromptInjection scanner", exc_info=True)

            if self._config.toxicity.enabled:
                try:
                    from llm_guard.input_scanners import Toxicity

                    kwargs = {}
                    kwargs["threshold"] = self._config.toxicity.threshold
                    if self._config.toxicity.model is not None:
                        kwargs["model"] = self._config.toxicity.model
                    self._scanners["toxicity"] = Toxicity(**kwargs)
                    logger.info("LLM Guard Toxicity scanner initialized")
                except Exception:
                    logger.warning("Failed to initialize LLM Guard Toxicity scanner", exc_info=True)

            if self._config.ban_topics.enabled:
                topics = self._config.ban_topics.topics
                if topics:
                    try:
                        from llm_guard.input_scanners import BanTopics

                        kwargs = {"topics": topics}
                        kwargs["threshold"] = self._config.ban_topics.threshold
                        if self._config.ban_topics.model is not None:
                            kwargs["model"] = self._config.ban_topics.model
                        self._scanners["ban_topics"] = BanTopics(**kwargs)
                        logger.info("LLM Guard BanTopics scanner initialized")
                    except Exception:
                        logger.warning("Failed to initialize LLM Guard BanTopics scanner", exc_info=True)

    def scan(self, text: str) -> LLMGuardResult:
        """Run all enabled LLM Guard scanners on the input text.

        Returns:
            LLMGuardResult with per-scanner results and an aggregate score.
        """
        if not self.enabled:
            return LLMGuardResult()

        self._init_scanners()

        if not self._scanners:
            return LLMGuardResult()

        results: list[LLMGuardScannerResult] = []

        for name, scanner in self._scanners.items():
            try:
                sanitized_text, is_valid, risk_score = scanner.scan(text)
                results.append(
                    LLMGuardScannerResult(
                        scanner_name=name,
                        sanitized_text=sanitized_text,
                        is_valid=is_valid,
                        risk_score=risk_score,
                    )
                )
            except Exception:
                logger.warning("LLM Guard scanner '%s' failed", name, exc_info=True)

        aggregate = self._compute_aggregate(results)

        return LLMGuardResult(
            scanner_results=results,
            aggregate_score=aggregate,
            is_threat=any(not r.is_valid for r in results),
        )

    @staticmethod
    def _compute_aggregate(results: list[LLMGuardScannerResult]) -> float:
        """Compute aggregate score from individual scanner results.

        Uses max score weighted by number of agreeing scanners.
        """
        if not results:
            return 0.0

        scores = [r.risk_score for r in results]
        max_score = max(scores)

        if len(scores) == 1:
            return max_score

        # Boost when multiple scanners flag a threat
        flagging = sum(1 for r in results if not r.is_valid)
        if flagging > 1:
            boost = min(0.1 * (flagging - 1), 0.2)
            return min(max_score + boost, 1.0)

        return max_score
