"""Lightweight message-level drift detection using statistical style profiling.

Detects personality and communication style changes across LLM responses
without requiring ML dependencies.  Uses vocabulary entropy, lexical diversity,
sentence length, question frequency, and uppercase ratio as proxy signals.
"""

from __future__ import annotations

import math
import re
import threading
from collections import Counter, deque
from dataclasses import dataclass
from typing import Any

from aegis.core.config import MessageDriftConfig


@dataclass
class MessageProfile:
    """Statistical style profile for a single message."""

    vocabulary_entropy: float
    lexical_diversity: float
    avg_sentence_length: float
    question_frequency: float
    uppercase_ratio: float


class MessageDriftDetector:
    """Detects message-level style drift using lightweight statistical features.

    Maintains a per-agent rolling window of :class:`MessageProfile` vectors.
    After ``baseline_size`` profiles are collected the baseline is frozen and
    subsequent profiles are compared via z-score anomaly detection.

    Args:
        config: Optional dict with ``window_size``, ``baseline_size``,
            and ``threshold`` keys.
    """

    def __init__(self, config: MessageDriftConfig | None = None) -> None:
        config = config or MessageDriftConfig()
        self._window_size: int = config.window_size
        self._baseline_size: int = config.baseline_size
        self._threshold: float = config.threshold
        self._profiles: dict[str, deque[MessageProfile]] = {}
        self._baselines: dict[str, tuple[MessageProfile, MessageProfile] | None] = {}
        self._lock = threading.Lock()

    @staticmethod
    def compute_profile(text: str) -> MessageProfile:
        """Compute a style profile from *text* using only stdlib operations."""
        words = re.findall(r"\b\w+\b", text.lower())
        total_words = len(words)

        # --- vocabulary entropy (Shannon) ---
        if total_words > 0:
            counts = Counter(words)
            entropy = -sum(
                (c / total_words) * math.log2(c / total_words)
                for c in counts.values()
            )
        else:
            entropy = 0.0

        # --- lexical diversity (type-token ratio) ---
        lexical_diversity = len(set(words)) / total_words if total_words > 0 else 0.0

        # --- average sentence length ---
        sentences = [s.strip() for s in re.split(r"[.!?]+", text) if s.strip()]
        if sentences:
            avg_sentence_length = sum(
                len(re.findall(r"\b\w+\b", s)) for s in sentences
            ) / len(sentences)
        else:
            avg_sentence_length = 0.0

        # --- question frequency ---
        question_sentences = len(re.findall(r"[^.!?]*\?", text))
        total_sentences = max(len(sentences), 1)
        question_frequency = question_sentences / total_sentences

        # --- uppercase ratio ---
        alpha_chars = sum(1 for c in text if c.isalpha())
        upper_chars = sum(1 for c in text if c.isupper())
        uppercase_ratio = upper_chars / alpha_chars if alpha_chars > 0 else 0.0

        return MessageProfile(
            vocabulary_entropy=entropy,
            lexical_diversity=lexical_diversity,
            avg_sentence_length=avg_sentence_length,
            question_frequency=question_frequency,
            uppercase_ratio=uppercase_ratio,
        )

    def record_and_check(self, agent_id: str, text: str) -> float:
        """Record a response profile and return drift sigma.

        Returns 0.0 while the baseline is still being established (fewer
        than ``baseline_size`` profiles recorded).
        """
        profile = self.compute_profile(text)

        with self._lock:
            if agent_id not in self._profiles:
                self._profiles[agent_id] = deque(maxlen=self._window_size)
                self._baselines[agent_id] = None
            self._profiles[agent_id].append(profile)

            # Still collecting baseline
            if len(self._profiles[agent_id]) < self._baseline_size:
                return 0.0

            # Freeze baseline on first opportunity
            if self._baselines[agent_id] is None:
                baseline_profiles = list(self._profiles[agent_id])[: self._baseline_size]
                self._baselines[agent_id] = self._compute_baseline(baseline_profiles)

            mean_profile, std_profile = self._baselines[agent_id]

        return self._compute_max_zscore(profile, mean_profile, std_profile)

    @staticmethod
    def _compute_baseline(
        profiles: list[MessageProfile],
    ) -> tuple[MessageProfile, MessageProfile]:
        """Compute mean and std profiles from a list of profiles."""
        n = len(profiles)

        def _mean_std(values: list[float]) -> tuple[float, float]:
            mean = sum(values) / n
            variance = sum((v - mean) ** 2 for v in values) / n
            return mean, math.sqrt(variance)

        fields = [
            "vocabulary_entropy",
            "lexical_diversity",
            "avg_sentence_length",
            "question_frequency",
            "uppercase_ratio",
        ]

        means: dict[str, float] = {}
        stds: dict[str, float] = {}
        for f in fields:
            values = [getattr(p, f) for p in profiles]
            m, s = _mean_std(values)
            means[f] = m
            stds[f] = s

        return (MessageProfile(**means), MessageProfile(**stds))

    @staticmethod
    def _compute_max_zscore(
        current: MessageProfile,
        mean: MessageProfile,
        std: MessageProfile,
    ) -> float:
        """Return max z-score across all profile dimensions."""
        max_sigma = 0.0
        for f in (
            "vocabulary_entropy",
            "lexical_diversity",
            "avg_sentence_length",
            "question_frequency",
            "uppercase_ratio",
        ):
            val = getattr(current, f)
            m = getattr(mean, f)
            s = getattr(std, f)
            if s == 0.0:
                if val == m:
                    sigma = 0.0
                elif m != 0.0:
                    sigma = abs(val - m) / abs(m) * 10.0
                else:
                    sigma = float("inf") if val != 0.0 else 0.0
            else:
                sigma = abs(val - m) / s
            if sigma > max_sigma:
                max_sigma = sigma
        return max_sigma
