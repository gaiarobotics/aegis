"""Tests for aegis.behavior.embedding_providers — pluggable embedding providers."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis.behavior.embedding_providers import (
    EmbeddingProvider,
    GeminiEmbeddingProvider,
    OpenAIEmbeddingProvider,
    SentenceTransformerProvider,
    create_provider,
)


# ------------------------------------------------------------------
# EmbeddingProvider ABC
# ------------------------------------------------------------------


class TestEmbeddingProviderABC:
    def test_cannot_instantiate(self):
        """EmbeddingProvider is abstract and cannot be instantiated directly."""
        with pytest.raises(TypeError):
            EmbeddingProvider()  # type: ignore[abstract]

    def test_subclass_must_implement_all(self):
        """A subclass missing any method/property raises TypeError."""

        class Incomplete(EmbeddingProvider):
            pass

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]


# ------------------------------------------------------------------
# SentenceTransformerProvider
# ------------------------------------------------------------------


class TestSentenceTransformerProvider:
    def test_model_name(self):
        provider = SentenceTransformerProvider()
        assert provider.model_name == "all-MiniLM-L6-v2"

    def test_dims(self):
        provider = SentenceTransformerProvider()
        assert provider.dims == 384

    def test_custom_model(self):
        provider = SentenceTransformerProvider(
            model="all-mpnet-base-v2", dims=768
        )
        assert provider.model_name == "all-mpnet-base-v2"
        assert provider.dims == 768

    @pytest.mark.asyncio
    async def test_embed_lazy_loads_model(self):
        """embed() lazy-loads SentenceTransformer on first call."""
        provider = SentenceTransformerProvider()

        fake_embedding = MagicMock()
        fake_embedding.tolist.return_value = [0.1] * 384

        fake_model = MagicMock()
        fake_model.encode.return_value = fake_embedding

        fake_cls = MagicMock(return_value=fake_model)

        with patch.dict("sys.modules", {"sentence_transformers": MagicMock()}):
            with patch(
                "aegis.behavior.embedding_providers._import_sentence_transformers",
                return_value=fake_cls,
            ):
                result = await provider.embed("hello world")

        assert result == [0.1] * 384
        fake_cls.assert_called_once_with("all-MiniLM-L6-v2")
        fake_model.encode.assert_called_once_with("hello world", convert_to_numpy=True)

    @pytest.mark.asyncio
    async def test_import_error_when_missing(self):
        """Raises ImportError with install instructions when sentence-transformers missing."""
        provider = SentenceTransformerProvider()
        provider._model = None

        with patch(
            "aegis.behavior.embedding_providers._import_sentence_transformers",
            side_effect=ImportError(
                "SentenceTransformerProvider requires sentence-transformers. "
                "Install with: pip install 'aegis-shield[embeddings]'"
            ),
        ):
            with pytest.raises(ImportError, match="sentence-transformers"):
                await provider.embed("hello")


# ------------------------------------------------------------------
# GeminiEmbeddingProvider
# ------------------------------------------------------------------


class TestGeminiEmbeddingProvider:
    def test_model_name_default(self):
        provider = GeminiEmbeddingProvider()
        assert provider.model_name == "gemini-embedding-2-preview"

    def test_dims(self):
        provider = GeminiEmbeddingProvider()
        assert provider.dims == 3072

    def test_custom_model(self):
        provider = GeminiEmbeddingProvider(model="custom-gemini", dims=1024)
        assert provider.model_name == "custom-gemini"
        assert provider.dims == 1024

    @pytest.mark.asyncio
    async def test_embed_calls_api(self):
        """embed() calls the Gemini embedding API."""
        provider = GeminiEmbeddingProvider()

        fake_client = MagicMock()
        fake_response = MagicMock()
        fake_response.embeddings = [MagicMock(values=[0.2] * 3072)]
        fake_client.models.embed_content.return_value = fake_response
        provider._client = fake_client

        result = await provider.embed("test text")
        assert result == [0.2] * 3072

    @pytest.mark.asyncio
    async def test_import_error_when_missing(self):
        """Raises ImportError with install instructions when google-genai missing."""
        provider = GeminiEmbeddingProvider()
        provider._client = None

        with patch(
            "aegis.behavior.embedding_providers._import_google_genai",
            side_effect=ImportError(
                "GeminiEmbeddingProvider requires google-genai. "
                "Install with: pip install google-genai"
            ),
        ):
            with pytest.raises(ImportError, match="google-genai"):
                await provider.embed("hello")

    @pytest.mark.asyncio
    async def test_lazy_loads_client(self):
        """Client is created lazily on first embed call."""
        provider = GeminiEmbeddingProvider()
        assert provider._client is None

        fake_module = MagicMock()
        fake_client = MagicMock()
        fake_module.Client.return_value = fake_client
        fake_response = MagicMock()
        fake_response.embeddings = [MagicMock(values=[0.1] * 3072)]
        fake_client.models.embed_content.return_value = fake_response

        with patch(
            "aegis.behavior.embedding_providers._import_google_genai",
            return_value=fake_module,
        ):
            with patch.dict("os.environ", {"GOOGLE_API_KEY": "test-key"}):
                result = await provider.embed("test")

        assert provider._client is fake_client
        assert len(result) == 3072


# ------------------------------------------------------------------
# OpenAIEmbeddingProvider
# ------------------------------------------------------------------


class TestOpenAIEmbeddingProvider:
    def test_model_name_default(self):
        provider = OpenAIEmbeddingProvider()
        assert provider.model_name == "text-embedding-3-small"

    def test_dims_default(self):
        provider = OpenAIEmbeddingProvider()
        assert provider.dims == 1536

    def test_large_model(self):
        provider = OpenAIEmbeddingProvider(
            model="text-embedding-3-large", dims=3072
        )
        assert provider.model_name == "text-embedding-3-large"
        assert provider.dims == 3072

    def test_custom_base_url(self):
        provider = OpenAIEmbeddingProvider(base_url="http://localhost:11434/v1")
        assert provider._base_url == "http://localhost:11434/v1"

    @pytest.mark.asyncio
    async def test_embed_calls_api(self):
        """embed() calls the OpenAI embedding API."""
        provider = OpenAIEmbeddingProvider()

        fake_client = MagicMock()
        fake_embedding = MagicMock()
        fake_embedding.embedding = [0.3] * 1536
        fake_response = MagicMock()
        fake_response.data = [fake_embedding]
        fake_client.embeddings.create.return_value = fake_response
        provider._client = fake_client

        result = await provider.embed("test text")
        assert result == [0.3] * 1536

    @pytest.mark.asyncio
    async def test_import_error_when_missing(self):
        """Raises ImportError with install instructions when openai missing."""
        provider = OpenAIEmbeddingProvider()
        provider._client = None

        with patch(
            "aegis.behavior.embedding_providers._import_openai",
            side_effect=ImportError("No module named 'openai'"),
        ):
            with pytest.raises(ImportError, match="openai"):
                await provider.embed("hello")

    @pytest.mark.asyncio
    async def test_lazy_loads_client(self):
        """Client is created lazily on first embed call."""
        provider = OpenAIEmbeddingProvider()
        assert provider._client is None

        fake_module = MagicMock()
        fake_client = MagicMock()
        fake_module.OpenAI.return_value = fake_client
        fake_embedding = MagicMock()
        fake_embedding.embedding = [0.1] * 1536
        fake_response = MagicMock()
        fake_response.data = [fake_embedding]
        fake_client.embeddings.create.return_value = fake_response

        with patch(
            "aegis.behavior.embedding_providers._import_openai",
            return_value=fake_module,
        ):
            result = await provider.embed("test")

        assert provider._client is fake_client
        assert len(result) == 1536


# ------------------------------------------------------------------
# create_provider factory
# ------------------------------------------------------------------


class TestCreateProvider:
    def test_default_sentence_transformer(self):
        provider = create_provider("all-MiniLM-L6-v2")
        assert isinstance(provider, SentenceTransformerProvider)
        assert provider.model_name == "all-MiniLM-L6-v2"

    def test_gemini_model(self):
        provider = create_provider("gemini-embedding-2-preview")
        assert isinstance(provider, GeminiEmbeddingProvider)

    def test_openai_small(self):
        provider = create_provider("text-embedding-3-small")
        assert isinstance(provider, OpenAIEmbeddingProvider)
        assert provider.dims == 1536

    def test_openai_large(self):
        provider = create_provider("text-embedding-3-large")
        assert isinstance(provider, OpenAIEmbeddingProvider)
        assert provider.dims == 3072

    def test_openai_with_base_url(self):
        provider = create_provider(
            "text-embedding-3-small", base_url="http://localhost:11434/v1"
        )
        assert isinstance(provider, OpenAIEmbeddingProvider)
        assert provider._base_url == "http://localhost:11434/v1"

    def test_unknown_model_raises(self):
        with pytest.raises(ValueError, match="Unknown embedding model"):
            create_provider("nonexistent-model-xyz")

    def test_sentence_transformer_custom(self):
        """Known sentence-transformer model all-mpnet-base-v2 maps to ST provider."""
        provider = create_provider("all-mpnet-base-v2")
        assert isinstance(provider, SentenceTransformerProvider)
