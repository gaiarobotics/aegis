"""Tests for embedding model configuration."""

from aegis.core.config import AegisConfig, ContentHashConfig, load_config


class TestContentHashConfigFields:
    def test_defaults(self):
        cfg = ContentHashConfig()
        assert cfg.embedding_model == "all-MiniLM-L6-v2"
        assert cfg.embedding_api_base_url == ""

    def test_custom_model(self):
        cfg = ContentHashConfig(embedding_model="gemini-embedding-2-preview")
        assert cfg.embedding_model == "gemini-embedding-2-preview"

    def test_custom_base_url(self):
        cfg = ContentHashConfig(
            embedding_model="text-embedding-3-small",
            embedding_api_base_url="http://localhost:8080/v1",
        )
        assert cfg.embedding_api_base_url == "http://localhost:8080/v1"

    def test_full_config_round_trip(self):
        cfg = AegisConfig(
            behavior={"content_hash": {"embedding_model": "text-embedding-3-large"}},
        )
        assert cfg.behavior.content_hash.embedding_model == "text-embedding-3-large"


class TestEnvOverrideEmbeddingModel:
    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("AEGIS_EMBEDDING_MODEL", "gemini-embedding-2-preview")
        cfg = load_config()
        assert cfg.behavior.content_hash.embedding_model == "gemini-embedding-2-preview"
