"""Privacy-preserving Locality-Sensitive Hashing for content fingerprinting.

Provides two tiers of content hashing:

* **Tier B (style hash):** Always available.  LSH from the 5 ``MessageProfile``
  features already computed by ``MessageDriftDetector``.  Zero extra dependencies.

* **Tier A (semantic hash):** Optional.  SimHash from sentence-transformer
  embeddings.  Requires ``aegis-shield[embeddings]``.

Both hashes are 128-bit integers, displayed as 32-char hex strings.  A rolling
majority-vote window smooths per-message noise into a stable "topic fingerprint."
"""

from __future__ import annotations

import random
import threading
from collections import deque
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aegis.behavior.message_drift import MessageProfile


def _projection_matrix(rows: int, cols: int, seed: int = 42) -> list[list[float]]:
    """Generate a reproducible random projection matrix using only stdlib.

    Returns a *rows* x *cols* matrix of floats drawn from N(0, 1) using the
    Box-Muller transform seeded with ``random.Random(seed)``.
    """
    import math

    rng = random.Random(seed)
    matrix: list[list[float]] = []
    for _ in range(rows):
        row: list[float] = []
        j = 0
        while j < cols:
            u1 = rng.random()
            u2 = rng.random()
            # Avoid log(0)
            if u1 == 0.0:
                u1 = 1e-10
            z0 = math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
            row.append(z0)
            j += 1
            if j < cols:
                z1 = math.sqrt(-2.0 * math.log(u1)) * math.sin(2.0 * math.pi * u2)
                row.append(z1)
                j += 1
        matrix.append(row)
    return matrix


def _dot(row: list[float], vec: list[float]) -> float:
    """Dot product of two equal-length sequences."""
    return sum(a * b for a, b in zip(row, vec))


def _simhash(matrix: list[list[float]], vec: list[float]) -> int:
    """Compute a SimHash: dot each projection row with *vec*, threshold at 0."""
    h = 0
    for i, row in enumerate(matrix):
        if _dot(row, vec) >= 0.0:
            h |= 1 << i
    return h


class StyleHasher:
    """Tier B — LSH from the 5 ``MessageProfile`` statistical features.

    Uses a ``(128, 5)`` random projection matrix seeded deterministically.
    """

    _BITS = 128
    _DIMS = 5

    def __init__(self) -> None:
        self._matrix = _projection_matrix(self._BITS, self._DIMS, seed=42)

    def hash(self, profile: MessageProfile) -> int:
        """Return a 128-bit SimHash integer for *profile*."""
        vec = [
            profile.vocabulary_entropy,
            profile.lexical_diversity,
            profile.avg_sentence_length,
            profile.question_frequency,
            profile.uppercase_ratio,
        ]
        return _simhash(self._matrix, vec)


class SemanticHasher:
    """Tier A — SimHash from sentence-transformer embeddings.

    Lazy-loads ``sentence_transformers.SentenceTransformer("all-MiniLM-L6-v2")``
    on first call.  If the package is missing, ``hash()`` raises ``ImportError``
    with a helpful message.
    """

    _BITS = 128
    _DIMS = 384  # all-MiniLM-L6-v2 output dimensionality

    def __init__(self) -> None:
        self._matrix = _projection_matrix(self._BITS, self._DIMS, seed=42)
        self._model = None
        self._available: bool | None = None

    def hash(self, text: str) -> int:
        """Return a 128-bit SimHash integer for *text*.

        Raises:
            ImportError: If ``sentence-transformers`` is not installed.
        """
        if self._available is False:
            raise ImportError(
                "SemanticHasher requires sentence-transformers. "
                "Install with: pip install 'aegis-shield[embeddings]'"
            )
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer("all-MiniLM-L6-v2")
                self._available = True
            except ImportError:
                self._available = False
                raise ImportError(
                    "SemanticHasher requires sentence-transformers. "
                    "Install with: pip install 'aegis-shield[embeddings]'"
                )
        embedding = self._model.encode(text, convert_to_numpy=True)
        vec = embedding.tolist()
        return _simhash(self._matrix, vec)


def _hamming(a: int, b: int) -> int:
    """Hamming distance between two integers."""
    return bin(a ^ b).count("1")


class ContentHashTracker:
    """Wraps one or both hashers and maintains a rolling majority-vote window.

    Also tracks **topic velocity** — how rapidly the agent's content hash
    changes between consecutive messages.  Organic conversation drifts
    gradually (low velocity); a prompt injection snaps the topic instantly
    (high velocity spike).

    Args:
        window_size: Number of per-message hashes to keep for majority vote.
        semantic_enabled: Whether to attempt Tier A (graceful fallback).
        velocity_window: Number of consecutive step-distances to average
            for the velocity calculation.
    """

    _BITS = 128

    def __init__(
        self,
        window_size: int = 20,
        semantic_enabled: bool = True,
        velocity_window: int = 10,
    ) -> None:
        self._style_hasher = StyleHasher()
        self._semantic_hasher: SemanticHasher | None = None
        self._semantic_available = False

        if semantic_enabled:
            self._semantic_hasher = SemanticHasher()
            # Probe availability without requiring actual text
            try:
                import sentence_transformers  # noqa: F401
                self._semantic_available = True
            except ImportError:
                self._semantic_available = False

        self._style_window: deque[int] = deque(maxlen=window_size)
        self._content_window: deque[int] = deque(maxlen=window_size)

        # Velocity tracking: Hamming distance between consecutive raw hashes
        self._prev_style_hash: int | None = None
        self._velocity_window: deque[int] = deque(maxlen=velocity_window)

        self._lock = threading.Lock()

    def update(self, text: str, profile: MessageProfile | None = None) -> None:
        """Compute hash(es) for a message and append to the rolling window.

        Args:
            text: The message text (used for Tier A if available).
            profile: Pre-computed ``MessageProfile`` (Tier B).  If *None* and
                behavior module is active, the caller should compute it first.
        """
        style_hash: int | None = None
        content_hash: int | None = None

        if profile is not None:
            style_hash = self._style_hasher.hash(profile)

        if self._semantic_available and self._semantic_hasher is not None:
            try:
                content_hash = self._semantic_hasher.hash(text)
            except (ImportError, Exception):
                self._semantic_available = False

        with self._lock:
            if style_hash is not None:
                # Track step-distance for velocity
                if self._prev_style_hash is not None:
                    step = _hamming(self._prev_style_hash, style_hash)
                    self._velocity_window.append(step)
                self._prev_style_hash = style_hash
                self._style_window.append(style_hash)
            if content_hash is not None:
                self._content_window.append(content_hash)

    def get_hashes(self) -> dict[str, str | float]:
        """Return majority-vote aggregated hashes and topic velocity.

        Returns:
            Dict with:
            - ``style_hash``: 32-char hex (when data exists)
            - ``content_hash``: 32-char hex (when Tier A available and has data)
            - ``topic_velocity``: float in [0.0, 1.0] — mean Hamming distance
              between consecutive raw hashes, normalized by bit count.
              0.0 = topic unchanged, 1.0 = every bit flipped each step.
        """
        result: dict[str, str | float] = {}

        with self._lock:
            if self._style_window:
                agg = self._majority_vote(list(self._style_window))
                result["style_hash"] = f"{agg:032x}"
            if self._content_window:
                agg = self._majority_vote(list(self._content_window))
                result["content_hash"] = f"{agg:032x}"
            if self._velocity_window:
                mean_dist = sum(self._velocity_window) / len(self._velocity_window)
                result["topic_velocity"] = mean_dist / self._BITS

        return result

    @classmethod
    def _majority_vote(cls, hashes: list[int]) -> int:
        """Compute per-bit majority across a list of 128-bit hashes."""
        n = len(hashes)
        if n == 0:
            return 0
        if n == 1:
            return hashes[0]

        threshold = n / 2.0
        result = 0
        for bit in range(cls._BITS):
            ones = sum(1 for h in hashes if h & (1 << bit))
            if ones > threshold:
                result |= 1 << bit
        return result
