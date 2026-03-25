"""Privacy-preserving Locality-Sensitive Hashing for content fingerprinting.

Uses SimHash from embedding-provider vectors to produce 128-bit content hashes
displayed as 32-char hex strings.  A rolling majority-vote window smooths
per-message noise into a stable "topic fingerprint."

The embedding backend is pluggable via ``EmbeddingProvider``.  When no provider
is given, ``ContentHashTracker`` defaults to ``SentenceTransformerProvider``
(requires ``aegis-shield[embeddings]``).  When the required SDK is not
installed, ``ContentHashTracker.update()`` is a no-op.
"""

from __future__ import annotations

import asyncio
import random
from collections import deque

from aegis.behavior.embedding_providers import EmbeddingProvider


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


class SemanticHasher:
    """SimHash from an ``EmbeddingProvider``.

    The provider supplies the embedding vector; this class projects it down
    to a 128-bit SimHash via a random projection matrix.
    """

    _BITS = 128

    def __init__(self, provider: EmbeddingProvider) -> None:
        self._provider = provider
        self._matrix = _projection_matrix(self._BITS, provider.dims, seed=42)

    @property
    def model_name(self) -> str:
        """Canonical model identifier, delegated to the provider."""
        return self._provider.model_name

    async def embed(self, text: str) -> list[float]:
        """Return raw embedding vector for *text* via the provider."""
        return await self._provider.embed(text)

    def hash_from_embedding(self, vec: list[float]) -> int:
        """Compute 128-bit SimHash from a pre-computed embedding vector."""
        return _simhash(self._matrix, vec)

    async def hash(self, text: str) -> int:
        """Return a 128-bit SimHash integer for *text*."""
        vec = await self.embed(text)
        return self.hash_from_embedding(vec)


def _hamming(a: int, b: int) -> int:
    """Hamming distance between two integers."""
    return bin(a ^ b).count("1")


class ContentHashTracker:
    """Wraps ``SemanticHasher`` and maintains a rolling majority-vote window.

    Also tracks **topic velocity** — how rapidly the agent's content hash
    changes between consecutive messages.  Organic conversation drifts
    gradually (low velocity); a prompt injection snaps the topic instantly
    (high velocity spike).

    If the embedding provider's SDK is not installed, ``update()`` is a no-op
    (graceful degradation).

    Args:
        window_size: Number of per-message hashes to keep for majority vote.
        velocity_window: Number of consecutive step-distances to average
            for the velocity calculation.
        provider: Optional ``EmbeddingProvider``.  Defaults to
            ``SentenceTransformerProvider()`` when not supplied.
    """

    _BITS = 128

    def __init__(
        self,
        window_size: int = 20,
        velocity_window: int = 10,
        provider: EmbeddingProvider | None = None,
    ) -> None:
        self._semantic_available = False

        if provider is not None:
            self._semantic_hasher = SemanticHasher(provider)
            self._semantic_available = True
        else:
            # Default: SentenceTransformerProvider (graceful degradation)
            try:
                import sentence_transformers  # noqa: F401
                from aegis.behavior.embedding_providers import SentenceTransformerProvider
                self._semantic_hasher = SemanticHasher(SentenceTransformerProvider())
                self._semantic_available = True
            except ImportError:
                # Create a dummy hasher — it will never be called
                self._semantic_hasher = None  # type: ignore[assignment]
                self._semantic_available = False

        self._content_window: deque[int] = deque(maxlen=window_size)

        # Velocity tracking: Hamming distance between consecutive raw hashes
        self._prev_hash: int | None = None
        self._velocity_window: deque[int] = deque(maxlen=velocity_window)

        self._lock = asyncio.Lock()

    async def update(self, text: str) -> None:
        """Compute semantic hash for a message and append to the rolling window.

        No-op if the embedding provider's SDK is not installed.

        Args:
            text: The message text.
        """
        if not self._semantic_available:
            return

        content_hash: int | None = None
        try:
            content_hash = await self._semantic_hasher.hash(text)
        except (ImportError, Exception):
            self._semantic_available = False
            return

        async with self._lock:
            if content_hash is not None:
                # Track step-distance for velocity
                if self._prev_hash is not None:
                    step = _hamming(self._prev_hash, content_hash)
                    self._velocity_window.append(step)
                self._prev_hash = content_hash
                self._content_window.append(content_hash)

    def get_hashes(self) -> dict[str, str | float]:
        """Return majority-vote aggregated content hash and topic velocity.

        Returns:
            Dict with:
            - ``content_hash``: 32-char hex (when data exists)
            - ``topic_velocity``: float in [0.0, 1.0] — mean Hamming distance
              between consecutive raw hashes, normalized by bit count.
              0.0 = topic unchanged, 1.0 = every bit flipped each step.
            - ``embedding_model``: model name string (when semantic hashing
              is available)
        """
        result: dict[str, str | float] = {}

        if self._content_window:
            agg = self._majority_vote(list(self._content_window))
            result["content_hash"] = f"{agg:032x}"
        if self._velocity_window:
            mean_dist = sum(self._velocity_window) / len(self._velocity_window)
            result["topic_velocity"] = mean_dist / self._BITS

        if self._semantic_available and self._semantic_hasher is not None:
            result["embedding_model"] = self._semantic_hasher.model_name

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
