# Multi-Embedding Model Support

**Date:** 2026-03-25
**Status:** Draft

## Summary

Add support for multiple embedding models in AEGIS, including external API-based models (Google `gemini-embedding-2-preview`, OpenAI `text-embedding-3-small`/`text-embedding-3-large`) alongside the existing local `all-MiniLM-L6-v2`. A deployment uses one active model at a time, configured at startup. Hashes from different models are stored with a model tag and only compared within the same model cohort.

## Motivation

- **Better accuracy:** Higher-quality external embeddings may improve contagion detection and intent divergence analysis.
- **Flexibility:** Different deployments can pick whichever embedding model fits their constraints (cost, latency, quality, offline requirements).
- **Comparison/evaluation:** Operators can evaluate which model performs best by switching models and comparing results across cohorts.

## Design Decisions

- **Single active model per process.** No hot-reloading — the embedding model is fixed for the lifetime of a process.
- **Model-tagged storage.** Hashes are stored with the model name that produced them. Comparisons only happen within the same model cohort.
- **Legacy compatibility.** Existing hashes with an empty `embedding_model` field are treated as a distinct cohort. They are not compared against named-model hashes. All new writes (including from the default `all-MiniLM-L6-v2`) always store the model name.
- **Async provider interface.** All providers expose `async def embed()`. The local provider runs CPU-bound inference in a thread executor.
- **Credentials via standard env vars.** External providers use `GOOGLE_API_KEY`, `OPENAI_API_KEY` — no AEGIS-specific API key config.
- **Single extras bundle.** `aegis-shield[embeddings]` includes all provider SDKs (`sentence-transformers`, `google-genai`, `openai`). Each SDK is only imported when its provider is selected.
- **SimHash output is model-independent.** The 128-bit SimHash output dimensionality is fixed regardless of input embedding dimensionality. The projection matrix adapts: `_projection_matrix(128, provider.dims)`.

## Architecture

### 1. Embedding Provider Interface

New module: `aegis/behavior/embedding_providers.py`

```python
class EmbeddingProvider(ABC):
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
```

#### Implementations

**`SentenceTransformerProvider`**
- Model: `all-MiniLM-L6-v2` (384-dim)
- Lazy-loads `sentence_transformers.SentenceTransformer` on first call
- Runs `model.encode()` in `asyncio.get_event_loop().run_in_executor()` (CPU-bound)
- Raises `ImportError` with install instructions if `sentence-transformers` is not installed

**`GeminiEmbeddingProvider`**
- Model: `gemini-embedding-2-preview`
- Lazy-imports `google.genai` on first call
- Reads `GOOGLE_API_KEY` from environment
- Raises `ImportError` with install instructions if `google-genai` is not installed

**`OpenAIEmbeddingProvider`**
- Models: `text-embedding-3-small` (1536-dim), `text-embedding-3-large` (3072-dim)
- Lazy-imports `openai` on first call
- Reads `OPENAI_API_KEY` from environment
- Raises `ImportError` with install instructions if `openai` is not installed

#### Factory

```python
def create_provider(config: ContentHashConfig) -> EmbeddingProvider:
    """Dispatch on config.embedding_model to create the appropriate provider."""
```

Unrecognized model names raise `ValueError` at startup with the list of supported models.

### 2. Configuration

`ContentHashConfig` gains two fields:

```python
class ContentHashConfig(BaseModel):
    enabled: bool = True
    window_size: int = 20
    embedding_model: str = "all-MiniLM-L6-v2"
    embedding_api_base_url: str = ""
```

- `embedding_model`: Selects the provider. Default preserves current behavior.
- `embedding_api_base_url`: Optional override for self-hosted or proxy endpoints (follows `LLMScreenConfig.base_url` pattern).

Environment variable override: `AEGIS_EMBEDDING_MODEL` maps to `behavior.content_hash.embedding_model`. Read once at config load time — no mid-process changes.

Supported `embedding_model` values:
- `all-MiniLM-L6-v2` (local, default)
- `gemini-embedding-2-preview` (Google API)
- `text-embedding-3-small` (OpenAI API, 1536-dim)
- `text-embedding-3-large` (OpenAI API, 3072-dim)

### 3. SemanticHasher Changes

`SemanticHasher` becomes a thin orchestrator over an `EmbeddingProvider`:

- Constructor takes an `EmbeddingProvider` instead of hardcoding the model.
- Projection matrix generated as `_projection_matrix(128, provider.dims)` — adapts to dimensionality.
- `embed()` becomes `async def embed()`, delegating to `provider.embed()`.
- `hash()` becomes `async def hash()`.
- `hash_from_embedding()` stays sync (pure math).
- Exposes `model_name` property (delegates to provider).
- Lazy-loading / availability-probing logic moves into the providers.

`ContentHashTracker`:
- `update()` becomes `async def update()`.
- `_lock` switches from `threading.Lock` to `asyncio.Lock`.
- `get_hashes()` return dict includes `"embedding_model": str`.

### 4. Storage: Model-tagged Hashes

Database migration adds a column to the `compromises` table:

```sql
ALTER TABLE compromises ADD COLUMN embedding_model TEXT NOT NULL DEFAULT '';
```

- `DEFAULT ''` handles legacy rows without error.
- All new writes always populate `embedding_model` with the actual model name (e.g., `"all-MiniLM-L6-v2"`).
- Legacy rows (`''`) form their own comparison cohort — they are never compared against named-model hashes.

Both SQLite and PostgreSQL backends receive this migration.

### 5. Downstream Consumer Changes

**`IntentDivergenceDetector`:**
- Receives `SemanticHasher` via constructor injection (already configured with the right provider) instead of constructing its own.
- `check()` becomes `async def check()`.
- Cosine similarity comparison remains valid — operates on raw embeddings from the same model within a single call.

**`TopicClusterer`:**
- `update(agent_id, hash_hex)` gains a `model: str` parameter.
- Internal `_hashes` becomes `dict[str, tuple[str, int]]` — `{agent_id: (model, hash_int)}`.
- `cluster()` partitions agents by model before running DBSCAN/union-find; returns clusters only within same-model cohorts.
- `get_nearest_neighbors()` filters by model.

**`ContagionDetector`:**
- `mark_compromised()` gains a `model: str` parameter.
- `_compromised` becomes `dict[str, tuple[str, int]]` — `{agent_id: (model, hash_int)}`.
- `check()` / `check_with_velocity()` gain a `model: str` parameter; only compare against same-model hashes.

**`RemoteThreatIntel`:**
- Threat-intel API response includes model name per hash entry.
- `check_hash()` gains a `model: str` parameter; filters by model before Hamming comparison.
- `get_compromised_hashes()` returns model-tagged data.

**Monitor API (`/api/v1/threat-intel`):**
- Queries `compromises` table with `embedding_model` filter.
- Response payload includes model info.

### 6. Dependencies

`aegis-shield[embeddings]` extra grows to include all three SDKs:

```toml
[project.optional-dependencies]
embeddings = [
    "sentence-transformers>=2.0",
    "google-genai>=1.0",
    "openai>=1.0",
]
```

Each SDK is only imported when its corresponding provider is instantiated. Using `all-MiniLM-L6-v2` never imports `openai` or `google-genai`, and vice versa.

### 7. Testing Strategy

- **Unit tests** for each provider behind a mock (no real API calls in CI).
- **Unit tests** for `SemanticHasher` with a fake provider (fixed-dimension dummy embeddings) to verify projection matrix adapts to different dimensionalities.
- **Unit tests** for `TopicClusterer` and `ContagionDetector` with mixed-model data to verify cross-model isolation (hashes from different models never cluster together or match).
- **Integration test** for the DB migration — verify `embedding_model` column exists, legacy rows have `''`, new rows get the model name.
- **Existing tests** updated for async interface changes.

No end-to-end tests against live APIs — those belong in a manual test suite.

## Invariants

1. The embedding model is fixed for the lifetime of a process. No hot-reloading.
2. Hashes are never compared across different embedding models.
3. Legacy hashes (empty `embedding_model`) form their own cohort.
4. The 128-bit SimHash output is constant regardless of input embedding dimensionality.
5. All new hash writes include the model name, even when using the default model.
