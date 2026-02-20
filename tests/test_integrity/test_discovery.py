"""Tests for aegis.integrity.discovery."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from aegis.integrity.discovery import (
    _get_hf_cache_path,
    _get_ollama_base_path,
    _parse_ollama_model_name,
    discover_ollama_files,
    discover_vllm_files,
)


# ---------------------------------------------------------------------------
# Ollama name parsing
# ---------------------------------------------------------------------------


class TestOllamaNameParsing:
    def test_name_with_tag(self):
        name, tag = _parse_ollama_model_name("llama3:70b")
        assert name == "llama3"
        assert tag == "70b"

    def test_name_without_tag(self):
        name, tag = _parse_ollama_model_name("llama3")
        assert name == "llama3"
        assert tag == "latest"

    def test_name_with_namespace(self):
        name, tag = _parse_ollama_model_name("library/llama3:latest")
        assert name == "llama3"
        assert tag == "latest"

    def test_name_with_namespace_no_tag(self):
        name, tag = _parse_ollama_model_name("myorg/mymodel")
        assert name == "mymodel"
        assert tag == "latest"


# ---------------------------------------------------------------------------
# Ollama discovery
# ---------------------------------------------------------------------------


class TestOllamaDiscovery:
    def test_discover_with_manifest(self, tmp_path):
        """Full discovery from a mock Ollama directory structure."""
        # Build directory structure
        manifests = tmp_path / "manifests" / "registry.ollama.ai" / "library" / "testmodel"
        manifests.mkdir(parents=True)

        blobs_dir = tmp_path / "blobs"
        blobs_dir.mkdir()

        digest_hex = "a" * 64
        blob_file = blobs_dir / f"sha256-{digest_hex}"
        blob_file.write_bytes(b"model data")

        manifest = {
            "layers": [
                {"digest": f"sha256:{digest_hex}", "mediaType": "application/vnd.ollama.image.model"},
            ],
        }
        (manifests / "latest").write_text(json.dumps(manifest))

        files, digests = discover_ollama_files("testmodel", ollama_models_path=str(tmp_path))
        assert len(files) == 1
        assert str(blob_file) in files
        assert digests[str(blob_file)] == digest_hex

    def test_discover_missing_manifest(self, tmp_path):
        """Missing manifest returns empty."""
        manifests = tmp_path / "manifests" / "registry.ollama.ai" / "library" / "nope"
        manifests.mkdir(parents=True)

        files, digests = discover_ollama_files("nope", ollama_models_path=str(tmp_path))
        assert files == []
        assert digests == {}

    def test_discover_bad_json(self, tmp_path):
        """Invalid JSON manifest returns empty."""
        manifests = tmp_path / "manifests" / "registry.ollama.ai" / "library" / "bad"
        manifests.mkdir(parents=True)
        (manifests / "latest").write_text("not json")

        files, digests = discover_ollama_files("bad", ollama_models_path=str(tmp_path))
        assert files == []
        assert digests == {}

    def test_discover_nonexistent_path(self):
        files, digests = discover_ollama_files("test", ollama_models_path="/nonexistent/path")
        assert files == []
        assert digests == {}

    def test_config_layer_included(self, tmp_path):
        """Config layer is also tracked."""
        manifests = tmp_path / "manifests" / "registry.ollama.ai" / "library" / "testmodel"
        manifests.mkdir(parents=True)

        blobs_dir = tmp_path / "blobs"
        blobs_dir.mkdir()

        layer_hex = "b" * 64
        config_hex = "c" * 64
        (blobs_dir / f"sha256-{layer_hex}").write_bytes(b"layer")
        (blobs_dir / f"sha256-{config_hex}").write_bytes(b"config")

        manifest = {
            "layers": [
                {"digest": f"sha256:{layer_hex}", "mediaType": "application/vnd.ollama.image.model"},
            ],
            "config": {
                "digest": f"sha256:{config_hex}", "mediaType": "application/vnd.ollama.image.config",
            },
        }
        (manifests / "latest").write_text(json.dumps(manifest))

        files, digests = discover_ollama_files("testmodel", ollama_models_path=str(tmp_path))
        assert len(files) == 2

    def test_env_override(self, tmp_path, monkeypatch):
        """OLLAMA_MODELS env var overrides default path."""
        monkeypatch.setenv("OLLAMA_MODELS", str(tmp_path))
        base = _get_ollama_base_path()
        assert base == tmp_path


# ---------------------------------------------------------------------------
# vLLM / HuggingFace discovery
# ---------------------------------------------------------------------------


class TestVLLMDiscovery:
    def test_local_dir(self, tmp_path):
        """Discovers model files from a local directory."""
        model_dir = tmp_path / "my-model"
        model_dir.mkdir()
        (model_dir / "model.safetensors").write_bytes(b"weights")
        (model_dir / "config.json").write_bytes(b"{}")  # not a model file
        (model_dir / "adapter.bin").write_bytes(b"adapter")

        files, digests = discover_vllm_files("my-model", model_path=str(model_dir))
        assert len(files) == 2
        exts = {Path(f).suffix for f in files}
        assert ".safetensors" in exts
        assert ".bin" in exts
        assert ".json" not in exts

    def test_model_name_as_dir(self, tmp_path):
        """model_name pointing to a directory works."""
        model_dir = tmp_path / "direct-model"
        model_dir.mkdir()
        (model_dir / "weights.pt").write_bytes(b"data")

        files, digests = discover_vllm_files(str(model_dir))
        assert len(files) == 1

    def test_hf_cache_discovery(self, tmp_path):
        """Discovers from HuggingFace cache structure."""
        safe_name = "org--model"
        model_cache = tmp_path / f"models--{safe_name}" / "snapshots" / "abc123"
        model_cache.mkdir(parents=True)
        (model_cache / "model.safetensors").write_bytes(b"weights")

        files, digests = discover_vllm_files(
            "org/model",
            hf_cache_path=str(tmp_path),
        )
        assert len(files) == 1

    def test_extension_filter(self, tmp_path):
        """Custom extension filter works."""
        model_dir = tmp_path / "filtered"
        model_dir.mkdir()
        (model_dir / "model.safetensors").write_bytes(b"data")
        (model_dir / "model.gguf").write_bytes(b"data")

        files, _ = discover_vllm_files(
            "filtered",
            model_path=str(model_dir),
            extensions=[".gguf"],
        )
        assert len(files) == 1
        assert files[0].endswith(".gguf")

    def test_nonexistent_path(self):
        files, digests = discover_vllm_files(
            "nonexistent-model",
            model_path="/nonexistent/path",
        )
        assert files == []

    def test_hf_env_override(self, tmp_path, monkeypatch):
        """HF_HOME env var is used for cache lookup."""
        hub_dir = tmp_path / "hub"
        hub_dir.mkdir()
        monkeypatch.setenv("HF_HOME", str(tmp_path))
        base = _get_hf_cache_path()
        assert base == hub_dir


# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_get_ollama_base_path_override(self, tmp_path):
        result = _get_ollama_base_path(str(tmp_path))
        assert result == tmp_path

    def test_get_ollama_base_path_nonexistent(self):
        result = _get_ollama_base_path("/nonexistent")
        assert result is None

    def test_get_hf_cache_path_override(self, tmp_path):
        result = _get_hf_cache_path(str(tmp_path))
        assert result == tmp_path

    def test_get_hf_cache_path_nonexistent(self):
        result = _get_hf_cache_path("/nonexistent")
        assert result is None
