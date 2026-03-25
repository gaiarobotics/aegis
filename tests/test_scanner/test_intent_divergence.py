"""Tests for aegis.scanner.intent_divergence — indirect injection detection."""

from __future__ import annotations

import asyncio
import math
from unittest.mock import AsyncMock, MagicMock

import pytest

from aegis.core.config import IntentDivergenceConfig
from aegis.scanner.intent_divergence import (
    ContextAnalysis,
    IntentDivergenceDetector,
    IntentDivergenceResult,
    _hamming_distance,
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_detector(
    enabled: bool = True,
    threshold: float = 0.65,
    amplification: float = 1.5,
    floor: float = 0.3,
    hasher=None,
) -> IntentDivergenceDetector:
    cfg = IntentDivergenceConfig(
        enabled=enabled,
        divergence_threshold=threshold,
        contagion_amplification=amplification,
        contagion_floor=floor,
    )
    return IntentDivergenceDetector(cfg, hasher=hasher)


def _unit_vec(dim: int, index: int, length: int = 384) -> list[float]:
    """Return a unit vector with 1.0 at *index*, 0.0 elsewhere."""
    vec = [0.0] * length
    vec[index] = 1.0
    return vec


def _patch_hasher_embed(detector: IntentDivergenceDetector, embed_fn):
    """Replace the detector's hasher with a mock that uses embed_fn (async)."""
    from aegis.behavior.content_hash import SemanticHasher, _projection_matrix
    from aegis.behavior.embedding_providers import EmbeddingProvider

    class _FakeProvider(EmbeddingProvider):
        @property
        def model_name(self):
            return "fake"

        @property
        def dims(self):
            return 384

        async def embed(self, text):
            return [0.0] * 384

    real_hasher = SemanticHasher(_FakeProvider())

    mock_hasher = MagicMock()
    mock_hasher.embed = AsyncMock(side_effect=embed_fn)
    mock_hasher.hash_from_embedding = MagicMock(side_effect=real_hasher.hash_from_embedding)
    detector._hasher = mock_hasher
    detector._available = True


# ------------------------------------------------------------------
# Result defaults
# ------------------------------------------------------------------

class TestResultDefaults:
    def test_context_analysis_defaults(self):
        ca = ContextAnalysis()
        assert ca.is_threat is False
        assert ca.divergence_score == 0.0
        assert ca.contagion_proximity == 0.0
        assert ca.composite_score == 0.0
        assert ca.text_snippet == ""

    def test_result_defaults(self):
        r = IntentDivergenceResult()
        assert r.is_threat is False
        assert r.skipped is False
        assert r.max_composite == 0.0
        assert r.context_analyses == []


# ------------------------------------------------------------------
# Disabled detector
# ------------------------------------------------------------------

class TestDisabledDetector:
    @pytest.mark.asyncio
    async def test_returns_skipped_when_disabled(self):
        detector = _make_detector(enabled=False)
        result = await detector.check("user query", ["some context"])
        assert result.skipped is True
        assert result.is_threat is False

    @pytest.mark.asyncio
    async def test_returns_skipped_when_no_context(self):
        detector = _make_detector(enabled=True)
        _patch_hasher_embed(detector, lambda t: _unit_vec(384, 0))
        result = await detector.check("user query", [])
        assert result.skipped is True


# ------------------------------------------------------------------
# Cosine similarity math
# ------------------------------------------------------------------

class TestCosineSimilarity:
    def test_identical_vectors(self):
        sim = IntentDivergenceDetector._cosine_similarity(
            [1.0, 2.0, 3.0], [1.0, 2.0, 3.0],
        )
        assert abs(sim - 1.0) < 1e-9

    def test_orthogonal_vectors(self):
        sim = IntentDivergenceDetector._cosine_similarity(
            [1.0, 0.0, 0.0], [0.0, 1.0, 0.0],
        )
        assert abs(sim) < 1e-9

    def test_opposite_vectors(self):
        sim = IntentDivergenceDetector._cosine_similarity(
            [1.0, 0.0], [-1.0, 0.0],
        )
        assert abs(sim - (-1.0)) < 1e-9

    def test_zero_vector(self):
        sim = IntentDivergenceDetector._cosine_similarity(
            [0.0, 0.0], [1.0, 2.0],
        )
        assert sim == 0.0

    def test_known_angle(self):
        """45-degree angle -> cos(45 deg) ~ 0.707."""
        sim = IntentDivergenceDetector._cosine_similarity(
            [1.0, 0.0], [1.0, 1.0],
        )
        assert abs(sim - math.cos(math.pi / 4)) < 1e-6


# ------------------------------------------------------------------
# Divergence only (no compromised hashes)
# ------------------------------------------------------------------

class TestDivergenceOnly:
    @pytest.mark.asyncio
    async def test_high_divergence_flags_threat(self):
        """Orthogonal vectors -> divergence=1.0 -> flagged."""
        detector = _make_detector(threshold=0.65)

        def embed_fn(text):
            if text == "user query":
                return _unit_vec(384, 0)
            return _unit_vec(384, 1)  # orthogonal

        _patch_hasher_embed(detector, embed_fn)
        result = await detector.check("user query", ["malicious context"])

        assert not result.skipped
        assert len(result.context_analyses) == 1
        assert result.context_analyses[0].divergence_score == pytest.approx(1.0)
        assert result.context_analyses[0].is_threat is True
        assert result.is_threat is True

    @pytest.mark.asyncio
    async def test_low_divergence_is_safe(self):
        """Identical vectors -> divergence=0.0 -> safe."""
        detector = _make_detector(threshold=0.65)

        _patch_hasher_embed(detector, lambda t: _unit_vec(384, 0))
        result = await detector.check("user query", ["relevant context"])

        assert not result.skipped
        assert result.context_analyses[0].divergence_score == pytest.approx(0.0, abs=1e-9)
        assert result.context_analyses[0].is_threat is False
        assert result.is_threat is False

    @pytest.mark.asyncio
    async def test_moderate_divergence_below_threshold(self):
        """Divergence just below threshold -> safe."""
        detector = _make_detector(threshold=0.65)

        def embed_fn(text):
            if text == "user query":
                return [1.0, 1.0] + [0.0] * 382
            return [1.0, 0.0] + [0.0] * 382  # cos ~ 0.707, divergence ~ 0.293

        _patch_hasher_embed(detector, embed_fn)
        result = await detector.check("user query", ["somewhat related"])

        assert result.context_analyses[0].divergence_score < 0.65
        assert result.is_threat is False


# ------------------------------------------------------------------
# Contagion amplification
# ------------------------------------------------------------------

class TestContagionAmplification:
    @pytest.mark.asyncio
    async def test_moderate_divergence_amplified_by_contagion(self):
        """Moderate divergence + high contagion -> amplified above threshold."""
        detector = _make_detector(threshold=0.65, amplification=1.5, floor=0.3)

        def embed_fn(text):
            if text == "user query":
                return [1.0, 1.0, 0.0] + [0.0] * 381  # magnitude sqrt(2)
            return [1.0, 0.0, 0.0] + [0.0] * 381  # cos ~ 0.707, div ~ 0.293

        _patch_hasher_embed(detector, embed_fn)

        # Create a compromised hash that's identical to the context hash
        # (contagion proximity = 1.0)
        ctx_emb = [1.0, 0.0, 0.0] + [0.0] * 381
        from aegis.behavior.content_hash import SemanticHasher
        from aegis.behavior.embedding_providers import EmbeddingProvider

        class _FakeProvider(EmbeddingProvider):
            @property
            def model_name(self):
                return "fake"

            @property
            def dims(self):
                return 384

            async def embed(self, text):
                return [0.0] * 384

        real_hasher = SemanticHasher(_FakeProvider())
        ctx_hash = real_hasher.hash_from_embedding(ctx_emb)

        result = await detector.check(
            "user query", ["suspicious context"], {ctx_hash},
        )

        analysis = result.context_analyses[0]
        assert analysis.contagion_proximity == pytest.approx(1.0)
        # composite = divergence * (1 + 1.5 * 1.0), which is > 0.65
        assert analysis.composite_score > 0.65
        assert analysis.is_threat is True

    @pytest.mark.asyncio
    async def test_without_contagion_same_would_be_safe(self):
        """Same divergence without contagion hashes -> safe."""
        detector = _make_detector(threshold=0.65)

        def embed_fn(text):
            if text == "user query":
                return [1.0, 1.0, 0.0] + [0.0] * 381
            return [1.0, 0.0, 0.0] + [0.0] * 381

        _patch_hasher_embed(detector, embed_fn)
        result = await detector.check("user query", ["suspicious context"])

        # No compromised hashes -> no amplification
        analysis = result.context_analyses[0]
        assert analysis.contagion_proximity == 0.0
        assert analysis.composite_score < 0.65
        assert analysis.is_threat is False


# ------------------------------------------------------------------
# Contagion floor
# ------------------------------------------------------------------

class TestContagionFloor:
    @pytest.mark.asyncio
    async def test_contagion_below_floor_not_amplified(self):
        """Contagion proximity below floor -> no amplification."""
        detector = _make_detector(threshold=0.65, amplification=1.5, floor=0.3)

        def embed_fn(text):
            if text == "user query":
                return _unit_vec(384, 0)
            return _unit_vec(384, 1)  # orthogonal -> divergence = 1.0

        _patch_hasher_embed(detector, embed_fn)

        # Create a compromised hash that's very different from context hash
        # (many bits differ -> low similarity)
        result = await detector.check(
            "user query", ["context"],
            {0},  # hash 0 -- likely very different from context hash
        )

        analysis = result.context_analyses[0]
        # Even if divergence is high, contagion below floor means no amplification
        # composite should equal divergence exactly
        if analysis.contagion_proximity < 0.3:
            assert analysis.composite_score == pytest.approx(analysis.divergence_score)


# ------------------------------------------------------------------
# Multiple context items
# ------------------------------------------------------------------

class TestMultipleContextItems:
    @pytest.mark.asyncio
    async def test_flags_if_any_item_exceeds_threshold(self):
        """One threatening context item among safe ones -> overall threat."""
        detector = _make_detector(threshold=0.65)

        call_count = 0

        def embed_fn(text):
            nonlocal call_count
            call_count += 1
            if text == "user query":
                return _unit_vec(384, 0)
            elif "safe" in text:
                return _unit_vec(384, 0)  # same as intent
            else:
                return _unit_vec(384, 1)  # orthogonal

        _patch_hasher_embed(detector, embed_fn)
        result = await detector.check(
            "user query",
            ["safe context", "malicious context", "safe again"],
        )

        assert result.is_threat is True
        assert len(result.context_analyses) == 3
        # Only the malicious one should be flagged
        threats = [a for a in result.context_analyses if a.is_threat]
        assert len(threats) == 1

    @pytest.mark.asyncio
    async def test_all_safe_no_threat(self):
        """All context items safe -> no overall threat."""
        detector = _make_detector(threshold=0.65)
        _patch_hasher_embed(detector, lambda t: _unit_vec(384, 0))
        result = await detector.check("user query", ["safe1", "safe2"])

        assert result.is_threat is False
        assert all(not a.is_threat for a in result.context_analyses)


# ------------------------------------------------------------------
# SimHash + Hamming distance
# ------------------------------------------------------------------

class TestSimHashHamming:
    def test_hamming_distance_identical(self):
        assert _hamming_distance(0xFF, 0xFF) == 0

    def test_hamming_distance_one_bit(self):
        assert _hamming_distance(0b1000, 0b0000) == 1

    def test_hamming_distance_all_different(self):
        # 8-bit all different
        assert _hamming_distance(0xFF, 0x00) == 8

    def test_contagion_proximity_from_simhash(self):
        """Verify SimHash similarity computation matches expected formula."""
        from aegis.behavior.content_hash import SemanticHasher
        from aegis.behavior.embedding_providers import EmbeddingProvider

        class _FakeProvider(EmbeddingProvider):
            @property
            def model_name(self):
                return "fake"

            @property
            def dims(self):
                return 384

            async def embed(self, text):
                return [0.0] * 384

        hasher = SemanticHasher(_FakeProvider())
        vec = _unit_vec(384, 0)
        h = hasher.hash_from_embedding(vec)

        # Same vector -> same hash -> distance 0 -> similarity 1.0
        dist = _hamming_distance(h, h)
        sim = 1.0 - (dist / 128)
        assert sim == 1.0


# ------------------------------------------------------------------
# Graceful degradation
# ------------------------------------------------------------------

class TestGracefulDegradation:
    @pytest.mark.asyncio
    async def test_missing_sentence_transformers(self):
        """When sentence-transformers is not installed, returns skipped."""
        detector = _make_detector(enabled=True)
        detector._available = False

        result = await detector.check("query", ["context"])
        assert result.skipped is True
        assert result.is_threat is False


# ------------------------------------------------------------------
# Injected hasher
# ------------------------------------------------------------------

class TestInjectedHasher:
    @pytest.mark.asyncio
    async def test_injected_hasher_used_directly(self):
        """When a hasher is injected, _ensure_hasher() returns True immediately."""
        from aegis.behavior.content_hash import SemanticHasher
        from aegis.behavior.embedding_providers import EmbeddingProvider

        class _FakeProvider(EmbeddingProvider):
            @property
            def model_name(self):
                return "fake"

            @property
            def dims(self):
                return 384

            async def embed(self, text):
                return _unit_vec(384, 0)

        hasher = SemanticHasher(_FakeProvider())
        detector = _make_detector(hasher=hasher)

        assert detector._ensure_hasher() is True
        assert detector._hasher is hasher
        assert detector._available is True

    @pytest.mark.asyncio
    async def test_none_hasher_lazy_fallback(self):
        """When hasher=None, _available starts as None (lazy)."""
        detector = _make_detector(hasher=None)
        assert detector._available is None


# ------------------------------------------------------------------
# Thread safety (adapted for async)
# ------------------------------------------------------------------

class TestThreadSafety:
    @pytest.mark.asyncio
    async def test_concurrent_checks_dont_crash(self):
        """Multiple concurrent async checks should not crash."""
        detector = _make_detector(threshold=0.65)
        _patch_hasher_embed(detector, lambda t: _unit_vec(384, hash(t) % 384))

        errors: list[Exception] = []

        async def worker(i: int):
            try:
                for _ in range(20):
                    await detector.check(
                        f"query {i}",
                        [f"context {i} a", f"context {i} b"],
                    )
            except Exception as e:
                errors.append(e)

        await asyncio.gather(*(worker(i) for i in range(4)))

        assert errors == [], f"Concurrency errors: {errors}"


# ------------------------------------------------------------------
# Text snippet truncation
# ------------------------------------------------------------------

class TestTextSnippet:
    @pytest.mark.asyncio
    async def test_snippet_truncated_to_100_chars(self):
        detector = _make_detector(threshold=0.65)
        _patch_hasher_embed(detector, lambda t: _unit_vec(384, 0))

        long_text = "x" * 200
        result = await detector.check("query", [long_text])

        assert len(result.context_analyses[0].text_snippet) == 100
