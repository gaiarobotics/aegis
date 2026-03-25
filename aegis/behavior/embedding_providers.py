"""Pluggable embedding providers for AEGIS behavior analysis.

Supports three backends:

- **SentenceTransformerProvider** — local CPU inference via ``sentence-transformers``
  (default: ``all-MiniLM-L6-v2``, 384-dim).
- **GeminiEmbeddingProvider** — Google Gemini API via ``google-genai``
  (default: ``gemini-embedding-2-preview``, 3072-dim).
- **OpenAIEmbeddingProvider** — OpenAI API via ``openai``
  (default: ``text-embedding-3-small``, 1536-dim).

Each provider lazy-loads its SDK on first use and raises ``ImportError`` with
install instructions when the required package is missing.

The ``create_provider(model, base_url)`` factory dispatches on model name.
"""

from __future__ import annotations

import abc
import asyncio
from typing import TYPE_CHECKING


# ---------------------------------------------------------------------------
# Lazy SDK import helpers — allow mocking in tests
# ---------------------------------------------------------------------------

def _import_sentence_transformers():
    """Return ``SentenceTransformer`` class, raising ImportError if missing."""
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        raise ImportError(
            "SentenceTransformerProvider requires sentence-transformers. "
            "Install with: pip install 'aegis-shield[embeddings]'"
        )
    return SentenceTransformer


def _import_google_genai():
    """Return the ``google.genai`` module, raising ImportError if missing."""
    try:
        from google import genai  # type: ignore[import-untyped]
    except ImportError:
        raise ImportError(
            "GeminiEmbeddingProvider requires google-genai. "
            "Install with: pip install google-genai"
        )
    return genai


def _import_openai():
    """Return the ``openai`` module, raising ImportError if missing."""
    try:
        import openai  # type: ignore[import-untyped]
    except ImportError:
        raise ImportError(
            "OpenAIEmbeddingProvider requires openai. "
            "Install with: pip install openai"
        )
    return openai


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class EmbeddingProvider(abc.ABC):
    """Abstract base class for embedding providers."""

    @property
    @abc.abstractmethod
    def model_name(self) -> str:
        """Canonical model identifier used as a storage key."""

    @property
    @abc.abstractmethod
    def dims(self) -> int:
        """Embedding vector dimensionality."""

    @abc.abstractmethod
    async def embed(self, text: str) -> list[float]:
        """Produce an embedding vector for *text*."""


# ---------------------------------------------------------------------------
# SentenceTransformerProvider
# ---------------------------------------------------------------------------

class SentenceTransformerProvider(EmbeddingProvider):
    """Local CPU inference via ``sentence-transformers``.

    The model is lazy-loaded on the first call to ``embed()``.  CPU-bound
    inference is offloaded to ``run_in_executor`` so the event loop stays
    responsive.
    """

    def __init__(
        self,
        model: str = "all-MiniLM-L6-v2",
        dims: int = 384,
    ) -> None:
        self._model_name = model
        self._dims = dims
        self._model = None  # lazy-loaded

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def dims(self) -> int:
        return self._dims

    def _ensure_model(self) -> None:
        if self._model is None:
            SentenceTransformer = _import_sentence_transformers()
            self._model = SentenceTransformer(self._model_name)

    async def embed(self, text: str) -> list[float]:
        self._ensure_model()
        loop = asyncio.get_running_loop()
        embedding = await loop.run_in_executor(
            None,
            lambda: self._model.encode(text, convert_to_numpy=True),
        )
        return embedding.tolist()


# ---------------------------------------------------------------------------
# GeminiEmbeddingProvider
# ---------------------------------------------------------------------------

class GeminiEmbeddingProvider(EmbeddingProvider):
    """Google Gemini embedding API via ``google-genai``.

    Requires ``GOOGLE_API_KEY`` environment variable for authentication.
    The client is lazy-loaded on the first call to ``embed()``.
    """

    def __init__(
        self,
        model: str = "gemini-embedding-2-preview",
        dims: int = 3072,
    ) -> None:
        self._model_name = model
        self._dims = dims
        self._client = None  # lazy-loaded

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def dims(self) -> int:
        return self._dims

    def _ensure_client(self) -> None:
        if self._client is None:
            genai = _import_google_genai()
            self._client = genai.Client()

    async def embed(self, text: str) -> list[float]:
        self._ensure_client()
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._client.models.embed_content(
                model=self._model_name,
                contents=text,
            ),
        )
        return response.embeddings[0].values


# ---------------------------------------------------------------------------
# OpenAIEmbeddingProvider
# ---------------------------------------------------------------------------

class OpenAIEmbeddingProvider(EmbeddingProvider):
    """OpenAI embedding API via ``openai``.

    Requires ``OPENAI_API_KEY`` environment variable for authentication.
    Supports custom ``base_url`` for compatible endpoints (e.g. Ollama).
    The client is lazy-loaded on the first call to ``embed()``.
    """

    def __init__(
        self,
        model: str = "text-embedding-3-small",
        dims: int = 1536,
        base_url: str = "",
    ) -> None:
        self._model_name = model
        self._dims = dims
        self._base_url = base_url
        self._client = None  # lazy-loaded

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def dims(self) -> int:
        return self._dims

    def _ensure_client(self) -> None:
        if self._client is None:
            openai = _import_openai()
            kwargs: dict = {}
            if self._base_url:
                kwargs["base_url"] = self._base_url
            self._client = openai.OpenAI(**kwargs)

    async def embed(self, text: str) -> list[float]:
        self._ensure_client()
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._client.embeddings.create(
                model=self._model_name,
                input=text,
            ),
        )
        return response.data[0].embedding


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

# Known model → provider mappings
_KNOWN_MODELS: dict[str, type[EmbeddingProvider]] = {
    "all-MiniLM-L6-v2": SentenceTransformerProvider,
    "all-mpnet-base-v2": SentenceTransformerProvider,
    "gemini-embedding-2-preview": GeminiEmbeddingProvider,
    "text-embedding-3-small": OpenAIEmbeddingProvider,
    "text-embedding-3-large": OpenAIEmbeddingProvider,
}

# Default dims for known models
_KNOWN_DIMS: dict[str, int] = {
    "all-MiniLM-L6-v2": 384,
    "all-mpnet-base-v2": 768,
    "gemini-embedding-2-preview": 3072,
    "text-embedding-3-small": 1536,
    "text-embedding-3-large": 3072,
}


def create_provider(model: str, base_url: str = "") -> EmbeddingProvider:
    """Create an embedding provider for the given model name.

    Args:
        model: Model identifier (e.g. ``"all-MiniLM-L6-v2"``,
            ``"gemini-embedding-2-preview"``, ``"text-embedding-3-small"``).
        base_url: Optional base URL override (only used for OpenAI-compatible
            providers).

    Returns:
        An ``EmbeddingProvider`` instance.

    Raises:
        ValueError: If the model name is not recognized.
    """
    provider_cls = _KNOWN_MODELS.get(model)

    # Also accept any model whose name suggests sentence-transformers
    if provider_cls is None and (model.startswith("all-") or "MiniLM" in model):
        provider_cls = SentenceTransformerProvider

    if provider_cls is None:
        raise ValueError(
            f"Unknown embedding model: {model!r}. "
            f"Supported models: {sorted(_KNOWN_MODELS.keys())}"
        )

    dims = _KNOWN_DIMS.get(model, 384)

    if provider_cls is SentenceTransformerProvider:
        return SentenceTransformerProvider(model=model, dims=dims)
    elif provider_cls is GeminiEmbeddingProvider:
        return GeminiEmbeddingProvider(model=model, dims=dims)
    elif provider_cls is OpenAIEmbeddingProvider:
        return OpenAIEmbeddingProvider(model=model, dims=dims, base_url=base_url)
    else:
        raise ValueError(f"Unknown embedding model: {model!r}")
