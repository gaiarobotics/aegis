"""Model file discovery for Ollama and vLLM."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def discover_ollama_files(
    model_name: str,
    ollama_models_path: str = "",
) -> tuple[list[str], dict[str, str]]:
    """Discover model files for an Ollama model.

    Parses the Ollama local manifest to find blob files.

    Returns:
        (file_paths, {file_path: expected_sha256_hex})
    """
    base_path = _get_ollama_base_path(ollama_models_path)
    if base_path is None:
        return [], {}

    name, tag = _parse_ollama_model_name(model_name)

    manifest_path = (
        base_path / "manifests" / "registry.ollama.ai" / "library" / name / tag
    )

    if not manifest_path.is_file():
        logger.debug("Ollama manifest not found: %s", manifest_path)
        return [], {}

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.debug("Failed to parse Ollama manifest: %s", manifest_path)
        return [], {}

    blobs_dir = base_path / "blobs"
    files: list[str] = []
    digests: dict[str, str] = {}

    layers = list(manifest.get("layers", []))
    config_layer = manifest.get("config")
    if config_layer:
        layers.append(config_layer)

    for layer in layers:
        digest = layer.get("digest", "")
        if not digest.startswith("sha256:"):
            continue
        hex_digest = digest[7:]
        blob_name = f"sha256-{hex_digest}"
        blob_path = blobs_dir / blob_name
        if blob_path.is_file():
            fpath = str(blob_path)
            files.append(fpath)
            digests[fpath] = hex_digest

    return sorted(files), digests


def discover_vllm_files(
    model_name: str,
    model_path: str | None = None,
    hf_cache_path: str = "",
    extensions: list[str] | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Discover model files for a vLLM model.

    Returns:
        (file_paths, {file_path: digest_if_known})
    """
    if extensions is None:
        extensions = [
            ".safetensors", ".bin", ".pt", ".pth",
            ".gguf", ".ggml", ".model",
        ]

    # Strategy 1: explicit local path
    if model_path and Path(model_path).is_dir():
        files = _find_model_files(Path(model_path), extensions)
        return files, {}

    # Strategy 2: model_name is a local directory
    if Path(model_name).is_dir():
        files = _find_model_files(Path(model_name), extensions)
        return files, {}

    # Strategy 3: HuggingFace cache
    hf_base = _get_hf_cache_path(hf_cache_path)
    if hf_base is not None:
        safe_name = model_name.replace("/", "--")
        model_cache_dir = hf_base / f"models--{safe_name}"
        if model_cache_dir.is_dir():
            snapshots_dir = model_cache_dir / "snapshots"
            if snapshots_dir.is_dir():
                snapshot_dirs = sorted(
                    [d for d in snapshots_dir.iterdir() if d.is_dir()],
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                if snapshot_dirs:
                    files = _find_model_files(snapshot_dirs[0], extensions)
                    digests = _read_hf_digests(model_cache_dir, files)
                    return files, digests

    return [], {}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_ollama_base_path(override: str = "") -> Path | None:
    if override:
        p = Path(override)
        return p if p.is_dir() else None
    env_path = os.environ.get("OLLAMA_MODELS")
    if env_path:
        p = Path(env_path)
        return p if p.is_dir() else None
    default = Path.home() / ".ollama" / "models"
    return default if default.is_dir() else None


def _parse_ollama_model_name(model_name: str) -> tuple[str, str]:
    """Parse 'llama3:70b' -> ('llama3', '70b')."""
    if ":" in model_name:
        name, tag = model_name.rsplit(":", 1)
    else:
        name = model_name
        tag = "latest"
    parts = name.split("/")
    name = parts[-1]
    return name, tag


def _get_hf_cache_path(override: str = "") -> Path | None:
    if override:
        p = Path(override)
        return p if p.is_dir() else None
    env_path = os.environ.get("HF_HOME")
    if env_path:
        p = Path(env_path) / "hub"
        return p if p.is_dir() else None
    env_path = os.environ.get("HUGGINGFACE_HUB_CACHE")
    if env_path:
        p = Path(env_path)
        return p if p.is_dir() else None
    default = Path.home() / ".cache" / "huggingface" / "hub"
    return default if default.is_dir() else None


def _find_model_files(directory: Path, extensions: list[str]) -> list[str]:
    """Find model files in a directory (recursive)."""
    ext_set = set(extensions)
    files: list[str] = []
    for fpath in directory.rglob("*"):
        if fpath.is_file() and fpath.suffix in ext_set:
            files.append(str(fpath))
    return sorted(files)


def _read_hf_digests(
    model_cache_dir: Path,
    files: list[str],
) -> dict[str, str]:
    """Read SHA256 digests from HuggingFace cache symlinks."""
    digests: dict[str, str] = {}
    blobs_dir = model_cache_dir / "blobs"
    for fpath in files:
        p = Path(fpath)
        if p.is_symlink():
            target = p.resolve()
            if str(blobs_dir) in str(target.parent):
                digests[fpath] = target.name
    return digests
