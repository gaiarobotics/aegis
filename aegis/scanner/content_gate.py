"""AEGIS content gate — pre-LLM extractive summarization for untrusted content."""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from aegis.core.config import ContentGateConfig

logger = logging.getLogger(__name__)

# Try to import transformers for ML-based summarization
_TRANSFORMERS_AVAILABLE = False
_summarizer_pipeline = None

try:
    from transformers import pipeline as hf_pipeline
    _TRANSFORMERS_AVAILABLE = True
except ImportError:
    pass


@dataclass
class GatedResult:
    """Result from content gate processing."""
    summary: str
    tagged_summary: str
    metadata: dict[str, Any] = field(default_factory=dict)
    original_length: int = 0
    method: str = "textrank"  # "textrank" or "bart"


class ContentGate:
    """Pre-LLM content gate using extractive summarization.

    Replaces raw untrusted content with structured summaries so that
    injection payloads never reach the main LLM's context.

    Uses BART/Pegasus when transformers is available, falls back to
    pure-Python TextRank extractive summarization.

    Args:
        config: ContentGateConfig controlling activation and behavior.
    """

    def __init__(self, config: Optional[ContentGateConfig] = None) -> None:
        self._config = config or ContentGateConfig()
        self._ml_summarizer = None

        if _TRANSFORMERS_AVAILABLE and self._config.enabled:
            try:
                self._ml_summarizer = hf_pipeline(
                    "summarization",
                    model="facebook/bart-large-cnn",
                    max_length=self._config.max_summary_tokens,
                    min_length=20,
                    truncation=True,
                )
            except Exception:
                logger.debug("BART summarizer init failed, using TextRank fallback", exc_info=True)

    def process(
        self,
        text: str,
        platform: Optional[str] = None,
    ) -> Optional[GatedResult]:
        """Process text through the content gate.

        Returns None if gating is not active for this platform/config.
        Returns GatedResult with structured summary if active.
        """
        if not self._should_gate(platform):
            return None

        # Summarize
        if self._ml_summarizer is not None and len(text) > 100:
            try:
                result = self._ml_summarizer(text, do_sample=False)
                summary = result[0]["summary_text"]
                method = "bart"
            except Exception:
                logger.debug("BART summarization failed, falling back to TextRank", exc_info=True)
                summary = _textrank_summarize(text, max_sentences=3)
                method = "textrank"
        else:
            summary = _textrank_summarize(text, max_sentences=3)
            method = "textrank"

        # Extract structured metadata
        metadata: dict[str, Any] = {}
        extract_fields = self._config.extract_fields

        if "sentiment" in extract_fields:
            metadata["sentiment"] = _extract_sentiment(text)
        if "mentions" in extract_fields:
            metadata["mentions"] = _extract_mentions(text)
        if "topic" in extract_fields:
            metadata["topic"] = _extract_topic(text)
        if "key_claims" in extract_fields:
            metadata["key_claims"] = summary

        from aegis.scanner.envelope import GATED_SUMMARY
        tagged = f"{GATED_SUMMARY} {summary}"

        return GatedResult(
            summary=summary,
            tagged_summary=tagged,
            metadata=metadata,
            original_length=len(text),
            method=method,
        )

    def _should_gate(self, platform: Optional[str]) -> bool:
        """Check if content should be gated for this platform."""
        if not self._config.enabled:
            return False
        if self._config.gate_all_social:
            return True
        if platform and self._config.platforms.get(platform, False):
            return True
        return False


# ---------------------------------------------------------------------------
# TextRank extractive summarization (pure Python, no ML dependencies)
# ---------------------------------------------------------------------------

def _textrank_summarize(text: str, max_sentences: int = 3) -> str:
    """Extract top sentences by TextRank graph centrality."""
    if not text.strip():
        return ""

    sentences = _split_sentences(text)
    if len(sentences) <= max_sentences:
        return text

    # Build word sets per sentence
    word_sets = [set(_tokenize(s)) for s in sentences]

    # Power iteration (simplified TextRank)
    n = len(sentences)
    scores = [1.0] * n
    damping = 0.85

    for _ in range(10):
        new_scores = [0.0] * n
        for i in range(n):
            for j in range(n):
                if i == j or not word_sets[j]:
                    continue
                overlap = len(word_sets[i] & word_sets[j])
                if overlap == 0:
                    continue
                similarity = overlap / (math.log(len(word_sets[i]) + 1) + math.log(len(word_sets[j]) + 1) + 1e-6)
                out_degree = sum(
                    1 for k in range(n) if k != j and len(word_sets[j] & word_sets[k]) > 0
                )
                if out_degree > 0:
                    new_scores[i] += similarity / out_degree * scores[j]
            new_scores[i] = (1 - damping) + damping * new_scores[i]
        scores = new_scores

    # Select top sentences, preserving original order
    ranked = sorted(range(n), key=lambda i: scores[i], reverse=True)
    selected = sorted(ranked[:max_sentences])
    return " ".join(sentences[i] for i in selected)


def _split_sentences(text: str) -> list[str]:
    """Split text into sentences."""
    parts = re.split(r'(?<=[.!?])\s+', text.strip())
    return [p.strip() for p in parts if p.strip()]


def _tokenize(text: str) -> list[str]:
    """Simple word tokenization: lowercase, alphanumeric only."""
    return re.findall(r'[a-z0-9]+', text.lower())


# ---------------------------------------------------------------------------
# Structured metadata extraction (regex/heuristic)
# ---------------------------------------------------------------------------

_POSITIVE_WORDS = frozenset({
    "great", "good", "excellent", "wonderful", "amazing", "fantastic",
    "love", "happy", "pleased", "nice", "awesome", "brilliant", "perfect",
    "beautiful", "best", "enjoy", "glad", "positive", "superb", "outstanding",
})
_NEGATIVE_WORDS = frozenset({
    "bad", "terrible", "awful", "horrible", "hate", "angry", "sad",
    "worst", "poor", "ugly", "disgusting", "disappointing", "annoying",
    "frustrating", "broken", "fail", "failed", "wrong", "stupid", "useless",
})


def _extract_sentiment(text: str) -> str:
    """Simple word-count sentiment classifier."""
    words = set(_tokenize(text))
    pos = len(words & _POSITIVE_WORDS)
    neg = len(words & _NEGATIVE_WORDS)
    if pos > neg:
        return "positive"
    elif neg > pos:
        return "negative"
    return "neutral"


_MENTION_PATTERN = re.compile(r'@([a-zA-Z0-9_]+)')


def _extract_mentions(text: str) -> list[str]:
    """Extract @mentions from text."""
    return _MENTION_PATTERN.findall(text)


def _extract_topic(text: str) -> str:
    """Extract a rough topic from the first sentence."""
    sentences = _split_sentences(text)
    if not sentences:
        return ""
    first = sentences[0]
    if len(first) > 100:
        first = first[:97] + "..."
    return first
