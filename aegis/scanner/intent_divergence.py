"""Intent-Context Divergence Detector for indirect prompt injection.

Measures cosine divergence between user intent and external context,
optionally amplified by SimHash proximity to known-compromised agent
content hashes from RemoteThreatIntel.

Requires ``aegis-shield[embeddings]`` (``sentence-transformers``).  When
the package is not installed, ``check()`` returns a skipped result.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from aegis.core.config import IntentDivergenceConfig

if TYPE_CHECKING:
    from aegis.behavior.content_hash import SemanticHasher

logger = logging.getLogger(__name__)

_BITS = 128  # SimHash width


def _hamming_distance(a: int, b: int) -> int:
    """Count differing bits between two integers."""
    return bin(a ^ b).count("1")


@dataclass
class ContextAnalysis:
    """Per-context-item analysis result."""

    text_snippet: str = ""
    divergence_score: float = 0.0
    contagion_proximity: float = 0.0
    composite_score: float = 0.0
    is_threat: bool = False


@dataclass
class IntentDivergenceResult:
    """Aggregated result across all context items."""

    context_analyses: list[ContextAnalysis] = field(default_factory=list)
    max_composite: float = 0.0
    is_threat: bool = False
    skipped: bool = False


class IntentDivergenceDetector:
    """Detects indirect prompt injection via intent-context divergence.

    Combines two signals:
    1. Cosine divergence between user intent and external context
    2. SimHash proximity to known-compromised agent content hashes

    Args:
        config: IntentDivergenceConfig with thresholds and amplification params.
        hasher: Optional pre-configured ``SemanticHasher``.  When provided the
            detector uses it directly; when ``None`` a hasher is lazy-created
            (backward compat, requires ``sentence-transformers``).
    """

    def __init__(
        self,
        config: IntentDivergenceConfig,
        hasher: SemanticHasher | None = None,
    ) -> None:
        self._config = config
        self._hasher = hasher
        self._available: bool | None = True if hasher is not None else None

    def _ensure_hasher(self) -> bool:
        """Lazy-init SemanticHasher. Returns True if available."""
        if self._available is False:
            return False
        if self._hasher is not None:
            return True
        # Legacy path: create a default hasher (requires sentence-transformers)
        try:
            from aegis.behavior.content_hash import SemanticHasher
            from aegis.behavior.embedding_providers import SentenceTransformerProvider
            self._hasher = SemanticHasher(SentenceTransformerProvider())
            # Probe availability
            import sentence_transformers  # noqa: F401
            self._available = True
        except ImportError:
            self._available = False
            return False
        return True

    async def check(
        self,
        intent_text: str,
        context_texts: list[str],
        compromised_hashes: set[int] | None = None,
    ) -> IntentDivergenceResult:
        """Check context texts for divergence from user intent.

        Args:
            intent_text: The user's original intent/query.
            context_texts: External content (tool outputs, retrieved docs, etc.).
            compromised_hashes: Known-compromised SimHash integers from threat intel.

        Returns:
            IntentDivergenceResult with per-item analyses and aggregate threat flag.
        """
        if not self._config.enabled:
            return IntentDivergenceResult(skipped=True)

        if not context_texts:
            return IntentDivergenceResult(skipped=True)

        if not self._ensure_hasher():
            logger.debug("Intent divergence skipped: sentence-transformers not available")
            return IntentDivergenceResult(skipped=True)

        try:
            intent_emb = await self._hasher.embed(intent_text)
        except Exception:
            logger.debug("Intent embedding failed", exc_info=True)
            return IntentDivergenceResult(skipped=True)

        analyses: list[ContextAnalysis] = []
        max_composite = 0.0

        for ctx_text in context_texts:
            try:
                ctx_emb = await self._hasher.embed(ctx_text)
            except Exception:
                logger.debug("Context embedding failed", exc_info=True)
                continue

            # Cosine divergence
            divergence = 1.0 - self._cosine_similarity(intent_emb, ctx_emb)

            # Contagion proximity via SimHash
            contagion = 0.0
            if compromised_hashes:
                ctx_hash = self._hasher.hash_from_embedding(ctx_emb)
                max_sim = 0.0
                for comp_hash in compromised_hashes:
                    dist = _hamming_distance(ctx_hash, comp_hash)
                    sim = 1.0 - (dist / _BITS)
                    if sim > max_sim:
                        max_sim = sim
                contagion = max_sim

            # Composite score with contagion amplification
            if contagion >= self._config.contagion_floor:
                composite = divergence * (1.0 + self._config.contagion_amplification * contagion)
            else:
                composite = divergence

            is_threat = composite >= self._config.divergence_threshold

            analysis = ContextAnalysis(
                text_snippet=ctx_text[:100],
                divergence_score=divergence,
                contagion_proximity=contagion,
                composite_score=composite,
                is_threat=is_threat,
            )
            analyses.append(analysis)

            if composite > max_composite:
                max_composite = composite

        any_threat = any(a.is_threat for a in analyses)

        return IntentDivergenceResult(
            context_analyses=analyses,
            max_composite=max_composite,
            is_threat=any_threat,
            skipped=False,
        )

    @staticmethod
    def _cosine_similarity(a: list[float], b: list[float]) -> float:
        """Compute cosine similarity between two vectors.

        Uses pure Python; falls back gracefully without numpy.
        Returns 0.0 for zero-magnitude vectors.
        """
        dot = sum(x * y for x, y in zip(a, b))
        mag_a = math.sqrt(sum(x * x for x in a))
        mag_b = math.sqrt(sum(x * x for x in b))
        if mag_a == 0.0 or mag_b == 0.0:
            return 0.0
        return dot / (mag_a * mag_b)
