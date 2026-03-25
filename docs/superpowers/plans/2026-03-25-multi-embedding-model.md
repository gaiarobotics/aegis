# Multi-Embedding Model Support — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add pluggable embedding provider support (local SentenceTransformer, Google Gemini, OpenAI) with model-tagged hash storage and same-model-only comparisons.

**Architecture:** Introduce an `EmbeddingProvider` ABC with three implementations. `SemanticHasher` takes a provider and adapts its projection matrix to the provider's dimensionality. All hash storage gains an `embedding_model` tag. Comparison logic (clustering, contagion, threat intel) filters by model before comparing.

**Tech Stack:** Python 3.10+, pydantic, sentence-transformers, google-genai, openai, pytest, pytest-asyncio

**Spec:** `docs/superpowers/specs/2026-03-25-multi-embedding-model-design.md`

---

### Task 1: Embedding Provider Interface and Factory

**Files:**
- Create: `aegis/behavior/embedding_providers.py`
- Create: `tests/test_behavior/test_embedding_providers.py`

- [ ] **Step 1: Write the provider tests**

```python
"""Tests for aegis.behavior.embedding_providers."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis.behavior.embedding_providers import (
    EmbeddingProvider,
    SentenceTransformerProvider,
    GeminiEmbeddingProvider,
    OpenAIEmbeddingProvider,
    create_provider,
)
from aegis.core.config import ContentHashConfig


class TestSentenceTransformerProvider:
    def test_model_name(self):
        provider = SentenceTransformerProvider()
        assert provider.model_name == "all-MiniLM-L6-v2"

    def test_dims(self):
        provider = SentenceTransformerProvider()
        assert provider.dims == 384

    @pytest.mark.asyncio
    async def test_embed_returns_correct_length(self):
        provider = SentenceTransformerProvider()

        class FakeArray(list):
            def tolist(self):
                return list(self)

        mock_model = MagicMock()
        mock_model.encode.return_value = FakeArray([0.1] * 384)
        provider._model = mock_model
        provider._available = True

        result = await provider.embed("hello")
        assert len(result) == 384
        assert all(isinstance(x, float) for x in result)

    def test_raises_import_error_when_unavailable(self):
        provider = SentenceTransformerProvider()
        provider._available = False
        with pytest.raises(ImportError, match="sentence-transformers"):
            asyncio.get_event_loop().run_until_complete(provider.embed("hello"))


class TestGeminiEmbeddingProvider:
    def test_model_name(self):
        provider = GeminiEmbeddingProvider()
        assert provider.model_name == "gemini-embedding-2-preview"

    def test_dims(self):
        provider = GeminiEmbeddingProvider()
        assert provider.dims == 3072

    @pytest.mark.asyncio
    async def test_embed_calls_api(self):
        provider = GeminiEmbeddingProvider()

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.embeddings = [MagicMock(values=[0.1] * 3072)]
        mock_client.models.embed_content.return_value = mock_response
        provider._client = mock_client
        provider._available = True

        result = await provider.embed("hello")
        assert len(result) == 3072
        mock_client.models.embed_content.assert_called_once()


class TestOpenAIEmbeddingProvider:
    def test_model_name_small(self):
        provider = OpenAIEmbeddingProvider(model="text-embedding-3-small")
        assert provider.model_name == "text-embedding-3-small"
        assert provider.dims == 1536

    def test_model_name_large(self):
        provider = OpenAIEmbeddingProvider(model="text-embedding-3-large")
        assert provider.model_name == "text-embedding-3-large"
        assert provider.dims == 3072

    @pytest.mark.asyncio
    async def test_embed_calls_api(self):
        provider = OpenAIEmbeddingProvider(model="text-embedding-3-small")

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.data = [MagicMock(embedding=[0.1] * 1536)]
        mock_client.embeddings.create.return_value = mock_response
        provider._client = mock_client
        provider._available = True

        result = await provider.embed("hello")
        assert len(result) == 1536
        mock_client.embeddings.create.assert_called_once()


class TestCreateProvider:
    def test_default_returns_sentence_transformer(self):
        config = ContentHashConfig()
        provider = create_provider(config)
        assert isinstance(provider, SentenceTransformerProvider)

    def test_gemini_model(self):
        config = ContentHashConfig(embedding_model="gemini-embedding-2-preview")
        provider = create_provider(config)
        assert isinstance(provider, GeminiEmbeddingProvider)

    def test_openai_small(self):
        config = ContentHashConfig(embedding_model="text-embedding-3-small")
        provider = create_provider(config)
        assert isinstance(provider, OpenAIEmbeddingProvider)
        assert provider.dims == 1536

    def test_openai_large(self):
        config = ContentHashConfig(embedding_model="text-embedding-3-large")
        provider = create_provider(config)
        assert isinstance(provider, OpenAIEmbeddingProvider)
        assert provider.dims == 3072

    def test_unknown_model_raises(self):
        config = ContentHashConfig(embedding_model="unknown-model")
        with pytest.raises(ValueError, match="unknown-model"):
            create_provider(config)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace && python -m pytest tests/test_behavior/test_embedding_providers.py -v`
Expected: FAIL — module `aegis.behavior.embedding_providers` does not exist.

- [ ] **Step 3: Implement the providers**

```python
"""Pluggable embedding providers for AEGIS content hashing.

Supports local (SentenceTransformer) and remote (Google Gemini, OpenAI)
embedding models.  Each provider lazily imports its SDK and raises
``ImportError`` with install instructions if missing.

Requires ``aegis-shield[embeddings]``.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod

from aegis.core.config import ContentHashConfig

# Model name -> (provider class suffix, dims)
_OPENAI_MODELS: dict[str, int] = {
    "text-embedding-3-small": 1536,
    "text-embedding-3-large": 3072,
}


class EmbeddingProvider(ABC):
    """Abstract base for embedding providers."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Canonical model identifier, used as the storage key."""
        ...

    @property
    @abstractmethod
    def dims(self) -> int:
        """Dimensionality of the embedding vectors produced by this model."""
        ...

    @abstractmethod
    async def embed(self, text: str) -> list[float]:
        """Return the embedding vector for the given text."""
        ...


class SentenceTransformerProvider(EmbeddingProvider):
    """Local embedding via sentence-transformers (all-MiniLM-L6-v2)."""

    def __init__(self) -> None:
        self._model = None
        self._available: bool | None = None

    @property
    def model_name(self) -> str:
        return "all-MiniLM-L6-v2"

    @property
    def dims(self) -> int:
        return 384

    def _ensure_model(self) -> None:
        if self._available is False:
            raise ImportError(
                "SentenceTransformerProvider requires sentence-transformers. "
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
                    "SentenceTransformerProvider requires sentence-transformers. "
                    "Install with: pip install 'aegis-shield[embeddings]'"
                )

    async def embed(self, text: str) -> list[float]:
        self._ensure_model()
        loop = asyncio.get_event_loop()
        embedding = await loop.run_in_executor(
            None, lambda: self._model.encode(text, convert_to_numpy=True),
        )
        return embedding.tolist()


class GeminiEmbeddingProvider(EmbeddingProvider):
    """Google Gemini embedding via google-genai SDK."""

    def __init__(self, base_url: str = "") -> None:
        self._base_url = base_url
        self._client = None
        self._available: bool | None = None

    @property
    def model_name(self) -> str:
        return "gemini-embedding-2-preview"

    @property
    def dims(self) -> int:
        return 3072

    def _ensure_client(self) -> None:
        if self._available is False:
            raise ImportError(
                "GeminiEmbeddingProvider requires google-genai. "
                "Install with: pip install 'aegis-shield[embeddings]'"
            )
        if self._client is None:
            try:
                from google import genai
                self._client = genai.Client()
                self._available = True
            except ImportError:
                self._available = False
                raise ImportError(
                    "GeminiEmbeddingProvider requires google-genai. "
                    "Install with: pip install 'aegis-shield[embeddings]'"
                )

    async def embed(self, text: str) -> list[float]:
        self._ensure_client()
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._client.models.embed_content(
                model=self.model_name, contents=[text],
            ),
        )
        return list(response.embeddings[0].values)


class OpenAIEmbeddingProvider(EmbeddingProvider):
    """OpenAI embedding via openai SDK."""

    def __init__(self, model: str = "text-embedding-3-small", base_url: str = "") -> None:
        if model not in _OPENAI_MODELS:
            raise ValueError(
                f"Unsupported OpenAI model: {model}. "
                f"Supported: {', '.join(_OPENAI_MODELS)}"
            )
        self._model_id = model
        self._dims = _OPENAI_MODELS[model]
        self._base_url = base_url
        self._client = None
        self._available: bool | None = None

    @property
    def model_name(self) -> str:
        return self._model_id

    @property
    def dims(self) -> int:
        return self._dims

    def _ensure_client(self) -> None:
        if self._available is False:
            raise ImportError(
                "OpenAIEmbeddingProvider requires openai. "
                "Install with: pip install 'aegis-shield[embeddings]'"
            )
        if self._client is None:
            try:
                import openai
                kwargs = {}
                if self._base_url:
                    kwargs["base_url"] = self._base_url
                self._client = openai.OpenAI(**kwargs)
                self._available = True
            except ImportError:
                self._available = False
                raise ImportError(
                    "OpenAIEmbeddingProvider requires openai. "
                    "Install with: pip install 'aegis-shield[embeddings]'"
                )

    async def embed(self, text: str) -> list[float]:
        self._ensure_client()
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._client.embeddings.create(
                model=self._model_id, input=text,
            ),
        )
        return list(response.data[0].embedding)


def create_provider(config: ContentHashConfig) -> EmbeddingProvider:
    """Create an EmbeddingProvider from config."""
    model = config.embedding_model
    base_url = config.embedding_api_base_url

    if model == "all-MiniLM-L6-v2":
        return SentenceTransformerProvider()
    elif model == "gemini-embedding-2-preview":
        return GeminiEmbeddingProvider(base_url=base_url)
    elif model in _OPENAI_MODELS:
        return OpenAIEmbeddingProvider(model=model, base_url=base_url)
    else:
        supported = ["all-MiniLM-L6-v2", "gemini-embedding-2-preview"] + list(_OPENAI_MODELS)
        raise ValueError(
            f"Unsupported embedding model: {model}. Supported: {', '.join(supported)}"
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace && python -m pytest tests/test_behavior/test_embedding_providers.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/behavior/embedding_providers.py tests/test_behavior/test_embedding_providers.py
git commit -m "feat: add EmbeddingProvider ABC with local, Gemini, and OpenAI implementations"
```

---

### Task 2: Configuration Changes

**Files:**
- Modify: `aegis/core/config.py:243-247` (ContentHashConfig)
- Modify: `aegis/core/config.py:452-464` (_ENV_OVERRIDES)

- [ ] **Step 1: Write a test for the new config fields**

Add to an existing config test file or create a minimal one. The pydantic model validation serves as the primary test here — verify the fields parse correctly:

```python
# tests/test_core/test_config_embedding.py
"""Tests for embedding model configuration."""

from aegis.core.config import ContentHashConfig, AegisConfig, load_config


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace && python -m pytest tests/test_core/test_config_embedding.py -v`
Expected: FAIL — `ContentHashConfig` has no field `embedding_model`.

- [ ] **Step 3: Add the new config fields**

In `aegis/core/config.py`, update `ContentHashConfig`:

```python
class ContentHashConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = True
    window_size: int = 20
    embedding_model: str = "all-MiniLM-L6-v2"
    embedding_api_base_url: str = ""
```

Add to `_ENV_OVERRIDES` list. Since the existing pattern only supports two-level nesting, add a new three-level entry with a small extension to `_apply_env_overrides`:

```python
# Add to _ENV_OVERRIDES:
# Three-level overrides use a tuple of (env_var, section, subsection, key, type)
_ENV_OVERRIDES_NESTED: list[tuple[str, str, str, str, type]] = [
    ("AEGIS_EMBEDDING_MODEL", "behavior", "content_hash", "embedding_model", str),
]
```

And extend `_apply_env_overrides` to handle the nested list:

```python
def _apply_env_overrides(data: dict) -> dict:
    """Apply AEGIS_* environment variable overrides."""
    for env_var, section, key, converter in _ENV_OVERRIDES:
        value = os.environ.get(env_var)
        if value is None:
            continue
        converted = converter(value)
        if key is None:
            data[section] = converted
        else:
            if section not in data:
                data[section] = {}
            data[section][key] = converted
    for env_var, section, subsection, key, converter in _ENV_OVERRIDES_NESTED:
        value = os.environ.get(env_var)
        if value is None:
            continue
        converted = converter(value)
        data.setdefault(section, {}).setdefault(subsection, {})[key] = converted
    return data
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace && python -m pytest tests/test_core/test_config_embedding.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Run existing config tests to verify no regressions**

Run: `cd /workspace && python -m pytest tests/test_core/ -v`
Expected: All existing tests PASS.

- [ ] **Step 6: Commit**

```bash
git add aegis/core/config.py tests/test_core/test_config_embedding.py
git commit -m "feat: add embedding_model and embedding_api_base_url to ContentHashConfig"
```

---

### Task 3: Refactor SemanticHasher to Use Provider

**Files:**
- Modify: `aegis/behavior/content_hash.py:62-237`
- Modify: `tests/test_behavior/test_content_hash.py`

- [ ] **Step 1: Update tests for async SemanticHasher**

The existing tests mock `SemanticHasher.hash()` as sync. Update them to work with the new async interface. Key changes:

- `SemanticHasher.__init__` takes an `EmbeddingProvider`
- `SemanticHasher.embed()` and `hash()` become `async`
- `SemanticHasher` exposes `model_name` property
- `ContentHashTracker.update()` becomes `async`
- `ContentHashTracker._lock` becomes `asyncio.Lock`
- `ContentHashTracker.get_hashes()` returns `"embedding_model"` key

Update `tests/test_behavior/test_content_hash.py`:

- Replace `mock_hasher.hash.return_value = X` with `mock_hasher.hash = AsyncMock(return_value=X)`
- Replace `tracker.update(text)` with `await tracker.update(text)`
- Add `@pytest.mark.asyncio` to async test classes
- Update `TestSemanticHasher` to construct with a mock provider
- Add test for `model_name` property
- Add test for `get_hashes()` returning `"embedding_model"`
- Keep `TestSimHashLocality` sync (it tests the pure-math `_simhash` function)

For the mock provider in tests, create a helper:

```python
class FakeProvider(EmbeddingProvider):
    """Test provider with configurable dimensionality."""

    def __init__(self, dims: int = 384, model_name: str = "fake-model"):
        self._dims = dims
        self._model_name = model_name
        self._embed_fn = lambda text: [0.1] * dims

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def dims(self) -> int:
        return self._dims

    async def embed(self, text: str) -> list[float]:
        return self._embed_fn(text)
```

Add a test that verifies projection matrix adapts to different dimensionalities:

```python
class TestSemanticHasherMultiDim:
    def test_projection_matrix_adapts_to_dims(self):
        """Different dims produce different projection matrices."""
        provider_384 = FakeProvider(dims=384)
        provider_1536 = FakeProvider(dims=1536)
        hasher_384 = SemanticHasher(provider_384)
        hasher_1536 = SemanticHasher(provider_1536)
        assert len(hasher_384._matrix[0]) == 384
        assert len(hasher_1536._matrix[0]) == 1536

    @pytest.mark.asyncio
    async def test_hash_produces_128_bit_regardless_of_dims(self):
        """Hash output is always 128 bits regardless of input dims."""
        for dims in (384, 1536, 3072):
            provider = FakeProvider(dims=dims)
            hasher = SemanticHasher(provider)
            h = await hasher.hash("test")
            hex_str = f"{h:032x}"
            assert len(hex_str) == 32

    def test_model_name_delegates_to_provider(self):
        provider = FakeProvider(model_name="test-model")
        hasher = SemanticHasher(provider)
        assert hasher.model_name == "test-model"
```

Add a test for `get_hashes()` returning `embedding_model`:

```python
@pytest.mark.asyncio
class TestContentHashTrackerAsync:
    async def test_get_hashes_includes_embedding_model(self):
        provider = FakeProvider(model_name="test-model")
        tracker = ContentHashTracker(provider=provider, window_size=5)
        tracker._semantic_available = True

        mock_hasher = MagicMock()
        mock_hasher.hash = AsyncMock(return_value=0xDEADBEEF)
        mock_hasher.model_name = "test-model"
        tracker._semantic_hasher = mock_hasher

        await tracker.update("hello")
        hashes = tracker.get_hashes()
        assert hashes["embedding_model"] == "test-model"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace && python -m pytest tests/test_behavior/test_content_hash.py -v`
Expected: FAIL — `SemanticHasher` doesn't accept a provider yet.

- [ ] **Step 3: Refactor SemanticHasher and ContentHashTracker**

In `aegis/behavior/content_hash.py`:

**SemanticHasher changes:**
- Constructor takes `provider: EmbeddingProvider`
- Projection matrix: `_projection_matrix(self._BITS, provider.dims, seed=42)`
- Remove `_ensure_model()`, `_model`, `_available`, `_DIMS`
- `embed()` → `async def embed()` delegating to `await self._provider.embed(text)`
- `hash()` → `async def hash()`
- Add `model_name` property
- Keep `hash_from_embedding()` sync

**ContentHashTracker changes:**
- Constructor takes optional `provider: EmbeddingProvider | None = None`
- If no provider given, create `SentenceTransformerProvider()` as default (preserves backward compat)
- `SemanticHasher` instantiated with the provider
- `update()` → `async def update()`
- `_lock` → `asyncio.Lock()`
- `get_hashes()` adds `"embedding_model": self._semantic_hasher.model_name` to result
- Availability probing: try creating the provider; if ImportError, set `_semantic_available = False`

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace && python -m pytest tests/test_behavior/test_content_hash.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/behavior/content_hash.py tests/test_behavior/test_content_hash.py
git commit -m "refactor: SemanticHasher takes EmbeddingProvider, async embed/hash"
```

---

### Task 4: Update IntentDivergenceDetector

**Files:**
- Modify: `aegis/scanner/intent_divergence.py:50-181`
- Modify: `tests/test_scanner/test_intent_divergence.py`
- Modify: `aegis/scanner/__init__.py:88-93`

- [ ] **Step 1: Update intent divergence tests**

Key changes:
- `IntentDivergenceDetector.__init__` now accepts a `SemanticHasher` (injected) instead of creating its own
- `check()` → `async def check()`
- The `_patch_hasher_embed` helper needs to mock async `embed()`
- Add `@pytest.mark.asyncio` to test classes that call `check()`

Update `_make_detector` helper:

```python
def _make_detector(
    enabled: bool = True,
    threshold: float = 0.65,
    amplification: float = 1.5,
    floor: float = 0.3,
) -> IntentDivergenceDetector:
    cfg = IntentDivergenceConfig(
        enabled=enabled,
        divergence_threshold=threshold,
        contagion_amplification=amplification,
        contagion_floor=floor,
    )
    # Create with a mock hasher — tests will replace via _patch_hasher_embed
    return IntentDivergenceDetector(cfg, hasher=None)
```

Update `_patch_hasher_embed`:

```python
def _patch_hasher_embed(detector, embed_fn):
    """Replace the detector's hasher with a mock that uses embed_fn (async-compatible)."""
    mock_hasher = MagicMock()
    mock_hasher.embed = AsyncMock(side_effect=embed_fn)
    from aegis.behavior.content_hash import SemanticHasher
    real_hasher = SemanticHasher.__new__(SemanticHasher)
    real_hasher._matrix = _projection_matrix(128, 384, seed=42)
    mock_hasher.hash_from_embedding.side_effect = real_hasher.hash_from_embedding
    detector._hasher = mock_hasher
    detector._available = True
```

All `detector.check(...)` calls → `await detector.check(...)` with `@pytest.mark.asyncio` on the class.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace && python -m pytest tests/test_scanner/test_intent_divergence.py -v`
Expected: FAIL — `check()` is still sync, constructor doesn't accept `hasher`.

- [ ] **Step 3: Update IntentDivergenceDetector**

In `aegis/scanner/intent_divergence.py`:

- Constructor accepts `hasher: SemanticHasher | None = None`
- If `hasher` is provided, use it directly; if `None`, lazy-create one (backward compat)
- `_ensure_hasher()` updated: if `hasher` was injected, just return `True`
- `check()` → `async def check()`: replace `self._hasher.embed(text)` with `await self._hasher.embed(text)`

In `aegis/scanner/__init__.py` (lines 88-93):

- When constructing `IntentDivergenceDetector`, pass the `SemanticHasher` if available
- This requires the `Scanner` to have access to the `ContentHashConfig` to create the provider

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace && python -m pytest tests/test_scanner/test_intent_divergence.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/scanner/intent_divergence.py tests/test_scanner/test_intent_divergence.py aegis/scanner/__init__.py
git commit -m "refactor: IntentDivergenceDetector accepts injected hasher, async check()"
```

---

### Task 5: Database Migration — Add embedding_model Column

**Files:**
- Modify: `aegis-monitor/monitor/backends/_sqlite.py:14-86,136-144`
- Modify: `aegis-monitor/monitor/backends/_postgres.py:16-94`
- Modify: `aegis-monitor/monitor/models.py:50-62`
- Modify: `aegis-monitor/monitor/db.py:182-242`

- [ ] **Step 1: Write migration tests**

```python
# aegis-monitor/tests/test_embedding_model_migration.py
"""Tests for embedding_model column migration."""

import sqlite3
import pytest
from monitor.backends._sqlite import SqliteBackend
from monitor.db import Database
from monitor.models import CompromiseRecord


class TestSqliteMigration:
    def test_new_db_has_embedding_model_column(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        backend = SqliteBackend(db_path)
        backend.init_schema()
        conn = sqlite3.connect(db_path)
        cols = [row[1] for row in conn.execute("PRAGMA table_info(compromises)").fetchall()]
        assert "embedding_model" in cols

    def test_legacy_rows_have_empty_embedding_model(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        backend = SqliteBackend(db_path)
        backend.init_schema()
        # Insert without embedding_model (simulating legacy data)
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO compromises (record_id, reporter_agent_id, compromised_agent_id, timestamp) "
            "VALUES ('r1', 'a1', 'a2', 1.0)"
        )
        conn.commit()
        row = conn.execute("SELECT embedding_model FROM compromises WHERE record_id='r1'").fetchone()
        assert row[0] == ""


class TestCompromiseRecordModel:
    def test_embedding_model_default(self):
        record = CompromiseRecord()
        assert record.embedding_model == ""

    def test_embedding_model_set(self):
        record = CompromiseRecord(embedding_model="all-MiniLM-L6-v2")
        assert record.embedding_model == "all-MiniLM-L6-v2"


class TestDatabaseInsertWithModel:
    def test_insert_stores_embedding_model(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        backend = SqliteBackend(db_path)
        backend.init_schema()
        db = Database(backend)

        record = CompromiseRecord(
            record_id="r1",
            reporter_agent_id="a1",
            compromised_agent_id="a2",
            content_hash_hex="abcd" * 8,
            embedding_model="gemini-embedding-2-preview",
        )
        db.insert_compromise(record)
        records = db.get_compromises()
        assert len(records) == 1
        assert records[0].embedding_model == "gemini-embedding-2-preview"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_embedding_model_migration.py -v`
Expected: FAIL — `CompromiseRecord` has no `embedding_model` field.

- [ ] **Step 3: Add the column and update models**

**`monitor/models.py`** — add field to `CompromiseRecord`:
```python
content_hash_hex: str = ""
embedding_model: str = ""
timestamp: float = field(default_factory=time.time)
```

**`monitor/backends/_sqlite.py`** — add to `_SCHEMA` (in the `CREATE TABLE compromises` block):
```sql
embedding_model      TEXT NOT NULL DEFAULT '',
```

Add migration in `init_schema()` after the `verified` migration:
```python
try:
    conn.execute("ALTER TABLE compromises ADD COLUMN embedding_model TEXT NOT NULL DEFAULT ''")
except sqlite3.OperationalError:
    pass  # Column already exists
```

**`monitor/backends/_postgres.py`** — add to the compromises CREATE TABLE:
```sql
embedding_model      TEXT NOT NULL DEFAULT '',
```

Add migration statement to `_SCHEMA_STATEMENTS`:
```python
"ALTER TABLE compromises ADD COLUMN IF NOT EXISTS embedding_model TEXT NOT NULL DEFAULT ''",
```

**`monitor/db.py`** — update `insert_compromise` to include `embedding_model` in the INSERT and UPDATE:
- Add `embedding_model` to the column list and values
- Add `embedding_model = excluded.embedding_model` to the ON CONFLICT SET clause
- Update `get_compromises` to read `embedding_model` from rows

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_embedding_model_migration.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Run existing DB tests for regressions**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/ -v -k "not postgres"`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add aegis-monitor/monitor/models.py aegis-monitor/monitor/db.py \
    aegis-monitor/monitor/backends/_sqlite.py aegis-monitor/monitor/backends/_postgres.py \
    aegis-monitor/tests/test_embedding_model_migration.py
git commit -m "feat: add embedding_model column to compromises table"
```

---

### Task 6: Update TopicClusterer for Model-Aware Clustering

**Files:**
- Modify: `aegis-monitor/monitor/contagion.py:78-531`
- Modify: `aegis-monitor/tests/test_contagion.py`

- [ ] **Step 1: Write tests for model-partitioned clustering**

Add to `aegis-monitor/tests/test_contagion.py`:

```python
class TestTopicClustererModelAware:
    def test_same_model_clusters_together(self):
        """Agents with same model and similar hashes cluster together."""
        tc = TopicClusterer(threshold=16)
        tc.update("agent-1", "a" * 32, model="model-a")
        tc.update("agent-2", "a" * 32, model="model-a")
        clusters = tc.cluster()
        assert clusters["agent-1"] == clusters["agent-2"]

    def test_different_models_never_cluster(self):
        """Agents with different models never cluster, even with identical hashes."""
        tc = TopicClusterer(threshold=16)
        tc.update("agent-1", "a" * 32, model="model-a")
        tc.update("agent-2", "a" * 32, model="model-b")
        clusters = tc.cluster()
        assert clusters["agent-1"] != clusters["agent-2"]

    def test_mixed_models_partition_correctly(self):
        """Three agents: two share model-a (cluster), one on model-b (separate)."""
        tc = TopicClusterer(threshold=16)
        tc.update("a1", "a" * 32, model="model-a")
        tc.update("a2", "a" * 32, model="model-a")
        tc.update("b1", "a" * 32, model="model-b")
        clusters = tc.cluster()
        assert clusters["a1"] == clusters["a2"]
        assert clusters["a1"] != clusters["b1"]

    def test_nearest_neighbors_filtered_by_model(self):
        """Nearest neighbors only include same-model agents."""
        tc = TopicClusterer(threshold=16)
        tc.update("a1", "a" * 32, model="model-a")
        tc.update("a2", "a" * 32, model="model-a")
        tc.update("b1", "a" * 32, model="model-b")
        nn = tc.get_nearest_neighbors()
        # a1's neighbors should not include b1
        a1_entry = [e for e in nn["entries"] if e["agent_id"] == "a1"][0]
        neighbor_ids = [n["agent_id"] for n in a1_entry["neighbors"]]
        assert "b1" not in neighbor_ids
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_contagion.py::TestTopicClustererModelAware -v`
Expected: FAIL — `update()` doesn't accept `model` parameter.

- [ ] **Step 3: Update TopicClusterer**

In `aegis-monitor/monitor/contagion.py`:

- `TopicClusterer._hashes` changes from `dict[str, int]` to `dict[str, tuple[str, int]]` — `{agent_id: (model, hash_int)}`
- `update(agent_id, hash_hex, model="")` — stores `(model, hash_int)`
- `cluster()` — partition `_hashes` by model, run clustering per partition, merge results with globally unique cluster IDs
- `get_nearest_neighbors()` — filter to same-model before computing distances
- `build_distance_matrix()` — partition by model
- Update all internal methods that access `self._hashes[agent_id]` to unpack the tuple

Update existing tests that call `update()` without a `model` parameter — they should still work since `model` defaults to `""`.

- [ ] **Step 4: Run all contagion tests**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_contagion.py -v`
Expected: All tests PASS (existing + new).

- [ ] **Step 5: Commit**

```bash
git add aegis-monitor/monitor/contagion.py aegis-monitor/tests/test_contagion.py
git commit -m "feat: TopicClusterer partitions clustering by embedding model"
```

---

### Task 7: Update ContagionDetector for Model-Aware Comparisons

**Files:**
- Modify: `aegis-monitor/monitor/contagion.py:537-616` (ContagionDetector class)
- Modify: `aegis-monitor/tests/test_contagion.py`

- [ ] **Step 1: Write tests for model-aware contagion detection**

Add to `aegis-monitor/tests/test_contagion.py`:

```python
class TestContagionDetectorModelAware:
    def test_same_model_detects_similarity(self):
        cd = ContagionDetector()
        cd.mark_compromised("bad-1", "a" * 32, model="model-a")
        score = cd.check("agent-1", "a" * 32, model="model-a")
        assert score == 1.0  # identical hash

    def test_different_model_returns_zero(self):
        cd = ContagionDetector()
        cd.mark_compromised("bad-1", "a" * 32, model="model-a")
        score = cd.check("agent-1", "a" * 32, model="model-b")
        assert score == 0.0  # different model, no comparison

    def test_check_with_velocity_model_aware(self):
        cd = ContagionDetector()
        cd.mark_compromised("bad-1", "a" * 32, model="model-a")
        score = cd.check_with_velocity("agent-1", "a" * 32, model="model-b", topic_velocity=1.0)
        assert score == 0.0  # different model
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_contagion.py::TestContagionDetectorModelAware -v`
Expected: FAIL — `mark_compromised()` / `check()` don't accept `model`.

- [ ] **Step 3: Update ContagionDetector**

- `_compromised` changes from `dict[str, int]` to `dict[str, tuple[str, int]]`
- `mark_compromised(agent_id, hash_hex, model="")` stores `(model, hash_int)`
- `check(agent_id, hash_hex, model="")` filters `_compromised` to same-model entries
- `check_with_velocity(agent_id, hash_hex, model="", ...)` passes `model` through

- [ ] **Step 4: Run all contagion tests**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_contagion.py -v`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis-monitor/monitor/contagion.py aegis-monitor/tests/test_contagion.py
git commit -m "feat: ContagionDetector filters by embedding model"
```

---

### Task 8: Update RemoteThreatIntel for Model-Keyed Hashes

**Files:**
- Modify: `aegis/core/remote_threat_intel.py`
- Create: `tests/test_core/test_remote_threat_intel_models.py`

- [ ] **Step 1: Write tests**

```python
# tests/test_core/test_remote_threat_intel_models.py
"""Tests for model-aware RemoteThreatIntel."""

from aegis.core.remote_threat_intel import RemoteThreatIntel


class TestRemoteThreatIntelModelAware:
    def test_get_compromised_hashes_by_model(self):
        rti = RemoteThreatIntel("http://example.com/api/v1", "key")
        # Manually populate with model-keyed data
        rti._compromised_hashes = {
            "model-a": {0xAAAA},
            "model-b": {0xBBBB},
        }
        assert rti.get_compromised_hashes("model-a") == {0xAAAA}
        assert rti.get_compromised_hashes("model-b") == {0xBBBB}
        assert rti.get_compromised_hashes("model-c") == set()

    def test_check_hash_filters_by_model(self):
        rti = RemoteThreatIntel("http://example.com/api/v1", "key")
        rti._compromised_hashes = {
            "model-a": {0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA},
        }
        # Same model → should find match
        is_sus, sim = rti.check_hash("0000aaaaaaaaaaaaaaaaaaaaaaaaaaaa", model="model-a")
        assert sim > 0.0

        # Different model → no match
        is_sus, sim = rti.check_hash("0000aaaaaaaaaaaaaaaaaaaaaaaaaaaa", model="model-b")
        assert sim == 0.0

    def test_poll_parses_model_keyed_hashes(self):
        """Verify _poll correctly parses the new wire format."""
        import json
        from unittest.mock import MagicMock, patch

        rti = RemoteThreatIntel("http://example.com/api/v1", "key")

        response_data = {
            "compromised_agents": ["agent-1"],
            "compromised_hashes": {
                "model-a": ["aaaa" + "0" * 28],
                "model-b": ["bbbb" + "0" * 28],
            },
            "quarantined_agents": [],
        }

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(response_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            rti._poll()

        assert "model-a" in rti._compromised_hashes
        assert "model-b" in rti._compromised_hashes
        assert len(rti._compromised_hashes["model-a"]) == 1
        assert len(rti._compromised_hashes["model-b"]) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace && python -m pytest tests/test_core/test_remote_threat_intel_models.py -v`
Expected: FAIL — `get_compromised_hashes` doesn't accept `model`, `_compromised_hashes` is `set[int]` not `dict`.

- [ ] **Step 3: Update RemoteThreatIntel**

In `aegis/core/remote_threat_intel.py`:

- `_compromised_hashes` changes from `set[int]` to `dict[str, set[int]]` — `{model: {hash_ints}}`
- `get_compromised_hashes(model: str | None = None)` → returns hashes for specific model, or empty set if not found
- `check_hash(hash_hex, model="", threshold=0.85)` → filters to model's hash set before comparing
- `_poll()` — parse new wire format where `compromised_hashes` is `dict[str, list[str]]`

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace && python -m pytest tests/test_core/test_remote_threat_intel_models.py -v`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis/core/remote_threat_intel.py tests/test_core/test_remote_threat_intel_models.py
git commit -m "feat: RemoteThreatIntel uses model-keyed compromised hashes"
```

---

### Task 9: Update Monitor Threat-Intel API Endpoint

**Files:**
- Modify: `aegis-monitor/monitor/app.py:880-905`
- Modify: `aegis-monitor/tests/test_app.py` (add threat-intel response format test)

- [ ] **Step 1: Write test for new wire format**

Add to `aegis-monitor/tests/test_app.py`:

```python
class TestThreatIntelModelKeyed:
    def test_compromised_hashes_keyed_by_model(self, client):
        """Threat-intel response has model-keyed compromised_hashes."""
        # Report a compromise with embedding_model
        client.post("/api/v1/reports/compromise", json={
            "reporter_agent_id": "scanner-1",
            "compromised_agent_id": "bad-1",
            "nk_score": 0.9,
            "content_hash_hex": "a" * 32,
            "embedding_model": "all-MiniLM-L6-v2",
        })

        resp = client.get("/api/v1/threat-intel")
        data = resp.json()

        assert isinstance(data["compromised_hashes"], dict)
        # Should have at least the model key
        if data["compromised_hashes"]:
            for model, hashes in data["compromised_hashes"].items():
                assert isinstance(model, str)
                assert isinstance(hashes, list)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_app.py::TestThreatIntelModelKeyed -v`
Expected: FAIL — response still has flat list.

- [ ] **Step 3: Update the threat-intel endpoint**

In `aegis-monitor/monitor/app.py` (around line 880):

Update the `get_threat_intel` handler to build model-keyed hashes:

```python
# Replace the flat compromised_hashes list:
compromised_hashes_by_model: dict[str, list[str]] = {}
for agent_id, (model, hash_int) in contagion_detector._compromised.items():
    model_key = model or ""
    compromised_hashes_by_model.setdefault(model_key, []).append(f"{hash_int:032x}")

result = {
    "compromised_agents": compromised_agents,
    "compromised_hashes": compromised_hashes_by_model,
    "quarantined_agents": quarantined_agents,
    "generated_at": time.time(),
}
```

Also update the compromise report handler to pass `embedding_model` through when calling `contagion_detector.mark_compromised()`.

- [ ] **Step 4: Run tests**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_app.py -v`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add aegis-monitor/monitor/app.py aegis-monitor/tests/test_app.py
git commit -m "feat: threat-intel API returns model-keyed compromised hashes"
```

---

### Task 10: Update Dependencies

**Files:**
- Modify: `/workspace/pyproject.toml:38`
- Modify: `/workspace/aegis-monitor/pyproject.toml:28-33`

- [ ] **Step 1: Update pyproject.toml**

In `/workspace/pyproject.toml`, update the `embeddings` extra:

```toml
embeddings = ["sentence-transformers>=2.6", "google-genai>=1.0", "openai>=1.0"]
```

In `/workspace/aegis-monitor/pyproject.toml`, update the `ml` extra to include the new SDKs:

```toml
ml = ["sentence-transformers>=2.6", "umap-learn>=0.5", "hdbscan>=0.8", "scikit-learn>=1.3", "google-genai>=1.0", "openai>=1.0"]
```

- [ ] **Step 2: Commit**

```bash
git add pyproject.toml aegis-monitor/pyproject.toml
git commit -m "deps: add google-genai and openai to embeddings extra"
```

---

### Task 11: Final Integration Test and Cleanup

**Files:**
- All modified files from previous tasks

- [ ] **Step 1: Run full test suite for aegis-shield**

Run: `cd /workspace && python -m pytest tests/ -v`
Expected: All PASS.

- [ ] **Step 2: Run full test suite for aegis-monitor**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/ -v -k "not postgres"`
Expected: All PASS.

- [ ] **Step 3: Run linter**

Run: `cd /workspace && ruff check aegis/ tests/`
Expected: No errors.

Run: `cd /workspace/aegis-monitor && ruff check monitor/ tests/`
Expected: No errors.

- [ ] **Step 4: Final commit (if any lint fixes needed)**

```bash
git add -A
git commit -m "fix: lint cleanup for multi-embedding model support"
```
