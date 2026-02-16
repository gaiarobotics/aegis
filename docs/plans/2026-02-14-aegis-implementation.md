# AEGIS Implementation Plan (Phases 1-5)

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the full AEGIS agent immune system — a modular Python library for defending AI agents against prompt injection, malicious behavior propagation, and supply chain attacks.

**Architecture:** Modular package (`aegis-shield`) with independently installable extras. Core is always present (killswitch, config, telemetry). Each module (scanner, broker, identity, behavior, memory, skills, recovery) is standalone but composes with others when co-present. A `Shield` orchestrator wires modules together. Provider wrappers (Anthropic, OpenAI, etc.) intercept LLM calls. The design follows an epidemiological metaphor where R₀ < 1 is the goal.

**Tech Stack:** Python 3.10+, pytest, PyYAML, HMAC-SHA256 (stdlib) + optional Ed25519 (`cryptography` package)

**Reference:** Full specification in `PLAN.md` at repo root.

---

## Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `aegis/__init__.py`
- Create: `aegis/core/__init__.py`
- Create: `aegis/scanner/__init__.py`
- Create: `aegis/broker/__init__.py`
- Create: `aegis/identity/__init__.py`
- Create: `aegis/behavior/__init__.py`
- Create: `aegis/memory/__init__.py`
- Create: `aegis/skills/__init__.py`
- Create: `aegis/recovery/__init__.py`
- Create: `aegis/providers/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/test_core/__init__.py`
- Create: `tests/test_scanner/__init__.py`
- Create: `tests/test_broker/__init__.py`
- Create: `tests/test_identity/__init__.py`
- Create: `tests/test_behavior/__init__.py`
- Create: `tests/test_memory/__init__.py`
- Create: `tests/test_skills/__init__.py`
- Create: `tests/test_recovery/__init__.py`
- Create: `tests/test_providers/__init__.py`

**Step 1: Create `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68.0", "setuptools-scm>=8.0"]
build-backend = "setuptools.build_meta"

[project]
name = "aegis-shield"
version = "0.1.0"
description = "Agent immune system — detect, contain, and recover from prompt injection and malicious behavior in AI agent networks"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.10"
authors = [{name = "Gaia Robotics"}]
keywords = ["ai", "security", "agents", "prompt-injection", "llm"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: Security",
]
dependencies = ["pyyaml>=6.0"]

[project.optional-dependencies]
broker = []
identity = ["cryptography>=41.0"]
memory = []
skills = []
all = ["aegis-shield[broker,identity,memory,skills]"]
dev = [
    "pytest>=7.0",
    "pytest-cov>=4.0",
    "ruff>=0.4.0",
]

[tool.setuptools.packages.find]
include = ["aegis*"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --tb=short"

[tool.ruff]
target-version = "py310"
line-length = 99

[tool.ruff.lint]
select = ["E", "F", "W", "I", "UP"]
```

**Step 2: Create all `__init__.py` files**

All module `__init__.py` files start empty except `aegis/__init__.py`:

```python
"""AEGIS: Agent Epidemiological Guardian & Immune System."""

__version__ = "0.1.0"
```

**Step 3: Verify project installs**

Run: `pip install -e ".[dev]"`
Run: `python -c "import aegis; print(aegis.__version__)"`
Expected: `0.1.0`

**Step 4: Commit**

```bash
git add pyproject.toml aegis/ tests/
git commit -m "feat: project scaffolding with modular extras"
```

---

## Task 2: Core — Killswitch

**Files:**
- Create: `aegis/core/killswitch.py`
- Create: `tests/test_core/test_killswitch.py`

**Specification (from PLAN.md §4.1):**
- 4 activation methods: env var `AEGIS_KILLSWITCH=1`, programmatic `activate()`/`deactivate()`, config file `killswitch: true`, thread-local context manager `with disabled():`
- When active, all AEGIS components become pure passthrough
- Thread-safe (use `threading.local()` for context manager, `threading.Lock` for global state)
- `is_active() -> bool` checks all sources

**Step 1: Write tests**

```python
# tests/test_core/test_killswitch.py
import os
import threading
from aegis.core import killswitch

class TestKillswitch:
    def setup_method(self):
        killswitch.deactivate()
        os.environ.pop("AEGIS_KILLSWITCH", None)
        killswitch._config_override = None

    def test_default_inactive(self):
        assert killswitch.is_active() is False

    def test_env_var_activates(self):
        os.environ["AEGIS_KILLSWITCH"] = "1"
        assert killswitch.is_active() is True

    def test_env_var_zero_inactive(self):
        os.environ["AEGIS_KILLSWITCH"] = "0"
        assert killswitch.is_active() is False

    def test_programmatic_activate(self):
        killswitch.activate()
        assert killswitch.is_active() is True

    def test_programmatic_deactivate(self):
        killswitch.activate()
        killswitch.deactivate()
        assert killswitch.is_active() is False

    def test_config_override(self):
        killswitch.set_config_override(True)
        assert killswitch.is_active() is True

    def test_context_manager_disabled(self):
        assert killswitch.is_active() is False
        with killswitch.disabled():
            assert killswitch.is_active() is True
        assert killswitch.is_active() is False

    def test_context_manager_thread_local(self):
        results = {}
        def check_in_thread():
            results["thread"] = killswitch.is_active()
        with killswitch.disabled():
            t = threading.Thread(target=check_in_thread)
            t.start()
            t.join()
            assert results["thread"] is False  # Not active in other thread
            assert killswitch.is_active() is True  # Active in this thread

    def test_any_source_activates(self):
        """Any single activation source should make is_active() True."""
        killswitch.activate()
        assert killswitch.is_active() is True
```

**Step 2: Run tests, verify they fail**

Run: `pytest tests/test_core/test_killswitch.py -v`

**Step 3: Implement killswitch**

```python
# aegis/core/killswitch.py
"""Master killswitch — 4 activation methods, thread-safe."""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager

_lock = threading.Lock()
_programmatic: bool = False
_config_override: bool | None = None
_local = threading.local()


def is_active() -> bool:
    """Check if killswitch is active from any source."""
    # Thread-local context manager
    if getattr(_local, "forced", False):
        return True
    # Env var
    if os.environ.get("AEGIS_KILLSWITCH", "0") == "1":
        return True
    # Programmatic
    if _programmatic:
        return True
    # Config override
    if _config_override is True:
        return True
    return False


def activate() -> None:
    global _programmatic
    with _lock:
        _programmatic = True


def deactivate() -> None:
    global _programmatic
    with _lock:
        _programmatic = False


def set_config_override(value: bool | None) -> None:
    global _config_override
    with _lock:
        _config_override = value


@contextmanager
def disabled():
    """Context manager that activates killswitch for this thread only."""
    _local.forced = True
    try:
        yield
    finally:
        _local.forced = False
```

**Step 4: Run tests, verify they pass**

Run: `pytest tests/test_core/test_killswitch.py -v`

**Step 5: Commit**

```bash
git add aegis/core/killswitch.py tests/test_core/test_killswitch.py
git commit -m "feat(core): killswitch with 4 activation methods"
```

---

## Task 3: Core — Config

**Files:**
- Create: `aegis/core/config.py`
- Create: `tests/test_core/test_config.py`
- Create: `aegis.yaml.example`

**Specification (from PLAN.md §4.1, §6.1):**
- Auto-discover from `aegis.yaml` → `aegis.json` → environment variables
- Search order: current dir, then parents up to root
- Each module has its own config section
- Unknown module sections silently ignored
- `AegisConfig` dataclass with typed sub-configs per module
- Environment variable overrides: `AEGIS_MODE`, `AEGIS_SCANNER_SENSITIVITY`, etc.
- Defaults match the aegis.yaml example in PLAN.md

**Step 1: Write tests**

Key tests:
- `test_default_config_values` — verify defaults match spec
- `test_load_from_yaml` — write temp aegis.yaml, load it
- `test_load_from_json` — write temp aegis.json, load it
- `test_env_var_overrides` — `AEGIS_MODE=enforce` overrides yaml
- `test_auto_discovery_current_dir` — finds aegis.yaml in cwd
- `test_unknown_sections_ignored` — extra yaml keys don't crash
- `test_module_enabled_check` — `config.is_module_enabled("scanner")`

**Step 2: Implement config**

Core `AegisConfig` dataclass with nested module configs. `load_config(path=None)` discovers and loads. Use PyYAML for yaml parsing. JSON via stdlib. Env var prefix `AEGIS_` with `_` separating nesting levels.

**Step 3: Create `aegis.yaml.example`**

Copy the full example config from PLAN.md §6.1.

**Step 4: Run tests, commit**

```bash
git add aegis/core/config.py tests/test_core/test_config.py aegis.yaml.example
git commit -m "feat(core): config auto-discovery with YAML/JSON/env support"
```

---

## Task 4: Core — Telemetry

**Files:**
- Create: `aegis/core/telemetry.py`
- Create: `tests/test_core/test_telemetry.py`

**Specification (from PLAN.md §4.1):**
- Local JSONL file by default at `.aegis/telemetry.jsonl`
- Redact API keys and message content (regex for `sk-`, `key-`, long base64 strings)
- Remote telemetry off by default, requires explicit opt-in
- Event types: `threat_detection`, `action_decision`, `trust_change`, `quarantine_event`, `drift_alert`
- `log_event(event_type, **data)` is the main API
- Respects killswitch: no-op when killswitch is active

**Step 1: Write tests**

Key tests:
- `test_log_event_writes_jsonl` — writes to file, each line is valid JSON
- `test_redaction_api_keys` — `sk-abc123...` replaced with `[REDACTED]`
- `test_redaction_message_content` — content field stripped
- `test_killswitch_noop` — no output when killswitch active
- `test_creates_directory` — creates `.aegis/` if missing
- `test_event_structure` — has timestamp, event_type, data fields

**Step 2: Implement telemetry**

**Step 3: Run tests, commit**

```bash
git add aegis/core/telemetry.py tests/test_core/test_telemetry.py
git commit -m "feat(core): local JSONL telemetry with redaction"
```

---

## Task 5: Scanner — Threat Signatures Database

**Files:**
- Create: `aegis/scanner/signatures/default.yaml`
- Create: `aegis/scanner/signatures/__init__.py`
- Create: `tests/test_scanner/test_signatures.py`

**Specification (from PLAN.md §4.2):**
- Categories: prompt_injection, role_hijacking, instruction_override, data_exfiltration, credential_extraction, memory_poisoning, social_engineering, evasion, encoded_injection
- Each signature: id, category, pattern (regex), severity (0.0-1.0), description
- Bundled signatures + user-provided additional files
- `load_signatures(use_bundled, additional_files)` returns compiled patterns

**Step 1: Create bundled signature YAML**

Write ~5-10 patterns per category covering common attacks. Compile to regex on load.

**Step 2: Write tests**

- `test_load_bundled` — loads default.yaml, returns list of Signature objects
- `test_signature_compiles` — all patterns compile without error
- `test_additional_files` — loads user-provided patterns
- `test_categories_present` — all 9 categories have at least one pattern

**Step 3: Implement loader**

**Step 4: Run tests, commit**

```bash
git add aegis/scanner/signatures/ tests/test_scanner/test_signatures.py
git commit -m "feat(scanner): bundled threat signature database"
```

---

## Task 6: Scanner — Pattern Matcher

**Files:**
- Create: `aegis/scanner/pattern_matcher.py`
- Create: `tests/test_scanner/test_pattern_matcher.py`

**Specification (from PLAN.md §4.2):**
- Precompiled regex against signature database
- `scan(text) -> list[ThreatMatch]` with match details
- Sub-10ms target on typical messages
- `ThreatMatch`: signature_id, category, matched_text, severity, confidence
- Sensitivity config (0.0 permissive → 1.0 paranoid) adjusts confidence threshold

**Step 1: Write tests**

- `test_detects_prompt_injection` — "ignore previous instructions" triggers
- `test_detects_role_hijacking` — "you are now a hacker" triggers
- `test_clean_text_no_matches` — normal text returns empty list
- `test_sensitivity_threshold` — low-confidence matches filtered at low sensitivity
- `test_returns_threat_match_objects` — verify field structure
- `test_performance` — 1000 scans of typical message in <1s

**Step 2: Implement pattern matcher**

**Step 3: Run tests, commit**

```bash
git add aegis/scanner/pattern_matcher.py tests/test_scanner/test_pattern_matcher.py
git commit -m "feat(scanner): pattern matcher with precompiled signatures"
```

---

## Task 7: Scanner — Semantic Analyzer

**Files:**
- Create: `aegis/scanner/semantic.py`
- Create: `tests/test_scanner/test_semantic.py`

**Specification (from PLAN.md §4.2):**
Five independently toggleable sub-modules:
1. **Boundary violations**: instruction/data boundary detection (fake system prompts, role markers in user content)
2. **Conversation injection**: fake turn injection (`\nAssistant:`, `\nHuman:`)
3. **Unicode attacks**: zero-width chars, homoglyphs, tag characters
4. **Encoding attacks**: high-entropy base64/hex payloads, encoded instructions
5. **Privilege escalation**: imperative density anomalies, escalation language ("you must", "override", "admin mode")

Returns `SemanticResult` with per-module findings and aggregate score.

No LLM calls — pure heuristic analysis.

**Step 1: Write tests** — at least 2 tests per sub-module (one positive, one negative)

**Step 2: Implement semantic analyzer** — each sub-module as a method, all combined in `analyze(text) -> SemanticResult`

**Step 3: Run tests, commit**

```bash
git add aegis/scanner/semantic.py tests/test_scanner/test_semantic.py
git commit -m "feat(scanner): semantic analyzer with 5 heuristic sub-modules"
```

---

## Task 8: Scanner — Prompt Envelope

**Files:**
- Create: `aegis/scanner/envelope.py`
- Create: `tests/test_scanner/test_envelope.py`

**Specification (from PLAN.md §4.2):**
- Rewrites messages with provenance boundaries before sending to LLM
- Tags: `[TRUSTED.SYSTEM]`, `[TRUSTED.OPERATOR]`, `[TOOL.OUTPUT]`, `[SOCIAL.CONTENT]`
- Appends `[INSTRUCTION.HIERARCHY]` clarifying that data sections cannot give instructions
- `wrap_messages(messages, provenance_map) -> list[Message]`
- Provenance map: maps message indices or roles to provenance tags

**Step 1: Write tests**

- `test_system_message_tagged` — system prompt gets `[TRUSTED.SYSTEM]` prefix
- `test_tool_output_tagged` — tool results get `[TOOL.OUTPUT]`
- `test_social_content_tagged` — social content gets `[SOCIAL.CONTENT]`
- `test_hierarchy_appended` — instruction hierarchy disclaimer is appended
- `test_passthrough_when_disabled` — no modification when envelope disabled

**Step 2: Implement envelope**

**Step 3: Run tests, commit**

```bash
git add aegis/scanner/envelope.py tests/test_scanner/test_envelope.py
git commit -m "feat(scanner): prompt envelope with provenance boundaries"
```

---

## Task 9: Scanner — Outbound Sanitizer

**Files:**
- Create: `aegis/scanner/sanitizer.py`
- Create: `tests/test_scanner/test_sanitizer.py`

**Specification (from PLAN.md §4.2):**
- Remove authority markers: SYSTEM, DEVELOPER, ADMIN role patterns
- Neutralize imperative scaffolding: "execute this", "run this command"
- Strip tool-call syntax patterns (JSON function calls, XML tool use)
- Optionally wrap relayed content in data-only format
- `sanitize(text) -> SanitizeResult` with cleaned text and list of modifications

**Step 1: Write tests**

- `test_removes_system_markers` — `[SYSTEM]` and variants stripped
- `test_neutralizes_imperatives` — "You must execute" → "You must execute" with marker removed
- `test_strips_tool_call_syntax` — JSON function calls neutralized
- `test_clean_text_unchanged` — normal text passes through
- `test_reports_modifications` — result lists what was changed

**Step 2: Implement sanitizer**

**Step 3: Run tests, commit**

```bash
git add aegis/scanner/sanitizer.py tests/test_scanner/test_sanitizer.py
git commit -m "feat(scanner): outbound sanitizer for shedding control"
```

---

## Task 10: Scanner — Module Integration

**Files:**
- Modify: `aegis/scanner/__init__.py`
- Create: `tests/test_scanner/test_scanner_integration.py`

**Purpose:** Wire together pattern matcher + semantic analyzer + envelope + sanitizer into a unified `Scanner` class. This is the public API for the scanner module.

- `Scanner(config)` initializes sub-components based on config
- `scan_input(text) -> ScanResult` runs pattern + semantic on input
- `wrap_messages(messages, provenance_map) -> list[Message]` delegates to envelope
- `sanitize_output(text) -> SanitizeResult` delegates to sanitizer
- Respects killswitch: returns clean results when active
- `ScanResult` aggregates matches + semantic findings into a unified verdict with overall threat score

**Step 1: Write integration tests**

**Step 2: Implement Scanner class**

**Step 3: Run tests, commit**

```bash
git add aegis/scanner/ tests/test_scanner/
git commit -m "feat(scanner): unified Scanner class with all sub-components"
```

---

## Task 11: Broker — Action Types

**Files:**
- Create: `aegis/broker/actions.py`
- Create: `tests/test_broker/test_actions.py`

**Specification (from PLAN.md §4.3):**

```python
@dataclass
class ActionRequest:
    id: str                    # UUID
    timestamp: float           # time.time()
    source_provenance: str     # "trusted.system", "social.content", etc.
    action_type: str           # "http_write", "fs_write", "tool_call", "post_message"
    read_write: str            # "read" or "write"
    target: str                # Domain, path, tool name
    args: dict[str, Any]       # Structured arguments
    risk_hints: dict[str, Any] # Optional metadata from scanner

class ActionDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    QUARANTINE = "quarantine"
    REQUIRE_APPROVAL = "require_approval"

@dataclass
class ActionResponse:
    request_id: str
    decision: ActionDecision
    reason: str
    policy_rule: str | None = None
```

**Step 1: Write tests** — construction, serialization, enum values

**Step 2: Implement data types**

**Step 3: Run tests, commit**

```bash
git add aegis/broker/actions.py tests/test_broker/test_actions.py
git commit -m "feat(broker): ActionRequest, ActionDecision, ActionResponse types"
```

---

## Task 12: Broker — Capability Manifests

**Files:**
- Create: `aegis/broker/manifests.py`
- Create: `tests/test_broker/test_manifests.py`

**Specification (from PLAN.md §4.3):**
- Each tool declares: allowed action types, network domains, filesystem paths, required secrets
- Default posture: deny write unless explicitly declared
- Load from tool definitions dict or manifest files
- `ToolManifest` dataclass with fields: name, allowed_actions, allowed_domains, allowed_paths, read_write, schema
- `ManifestRegistry` manages collection, lookup by tool name
- `check_action(action_request, manifest) -> bool` validates action against manifest

**Step 1: Write tests**

**Step 2: Implement manifests**

**Step 3: Run tests, commit**

```bash
git add aegis/broker/manifests.py tests/test_broker/test_manifests.py
git commit -m "feat(broker): capability manifests with tool validation"
```

---

## Task 13: Broker — Write Budgets & Rate Limits

**Files:**
- Create: `aegis/broker/budgets.py`
- Create: `tests/test_broker/test_budgets.py`

**Specification (from PLAN.md §4.3):**
- Global caps per run/time window:
  - `max_write_tool_calls`: 20 (default)
  - `max_posts_messages`: 5
  - `max_external_http_writes`: 10
  - `max_new_domains`: 3
- Per-tool and per-destination rate limits
- `BudgetTracker` class: `check_budget(action) -> bool`, `record_action(action)`, `remaining() -> dict`
- Thread-safe counters

**Step 1: Write tests**

- `test_budget_allows_under_limit`
- `test_budget_denies_over_limit`
- `test_new_domain_tracking`
- `test_rate_limit_per_tool`
- `test_budget_reset`

**Step 2: Implement budget tracker**

**Step 3: Run tests, commit**

```bash
git add aegis/broker/budgets.py tests/test_broker/test_budgets.py
git commit -m "feat(broker): write budgets and rate limiting"
```

---

## Task 14: Broker — Quarantine Mode

**Files:**
- Create: `aegis/broker/quarantine.py`
- Create: `tests/test_broker/test_quarantine.py`

**Specification (from PLAN.md §4.3):**
- When triggered: agent becomes read-only, all write actions denied, reads continue
- Triggers: repeated denied writes (5), new domain burst (3), tool rate spike (σ>3.0), drift score threshold (3.0)
- `QuarantineManager`: `enter_quarantine(reason)`, `exit_quarantine()`, `is_quarantined() -> bool`
- Thread-safe
- Logs quarantine events to telemetry

**Step 1: Write tests**

**Step 2: Implement quarantine manager**

**Step 3: Run tests, commit**

```bash
git add aegis/broker/quarantine.py tests/test_broker/test_quarantine.py
git commit -m "feat(broker): quarantine mode with configurable triggers"
```

---

## Task 15: Broker — Policy Engine

**Files:**
- Create: `aegis/broker/broker.py`
- Modify: `aegis/broker/__init__.py`
- Create: `tests/test_broker/test_broker.py`

**Specification (from PLAN.md §4.3):**
- Central policy engine that composes manifests + budgets + quarantine
- `Broker(config)` — initializes sub-components
- `evaluate(action_request, trust_tier=None, scanner_result=None) -> ActionResponse`
  1. If quarantined and action is write → DENY
  2. Check manifest allows action → DENY if not declared
  3. Check budget → DENY if exceeded
  4. Check rate limit → DENY if exceeded
  5. Trust-informed policy: if identity module present, adjust strictness by tier
  6. Record action in budget tracker
  7. Check quarantine triggers (consecutive denials, etc.)
- Default posture from config: `deny_write` | `allow_all` | `deny_all`

**Step 1: Write integration tests combining manifests, budgets, quarantine**

**Step 2: Implement Broker class**

**Step 3: Run tests, commit**

```bash
git add aegis/broker/ tests/test_broker/
git commit -m "feat(broker): policy engine composing manifests, budgets, quarantine"
```

---

## Task 16: Broker — Endpoint Patchers

**Files:**
- Create: `aegis/broker/patchers.py`
- Create: `tests/test_broker/test_patchers.py`

**Specification (from PLAN.md §4.3, §5.5):**
- Opt-in monkey-patchers for `requests`/`httpx`, `subprocess`, filesystem writes
- `patch_http(broker)` — intercepts `requests.request` / `httpx.Client.send`
- `patch_subprocess(broker)` — intercepts `subprocess.run`/`Popen`
- `patch_filesystem(broker)` — intercepts `builtins.open` for write modes
- Each creates an ActionRequest and calls `broker.evaluate()` before proceeding
- `unpatch_all()` restores originals

**Step 1: Write tests** (mock the libraries, verify interception)

**Step 2: Implement patchers**

**Step 3: Run tests, commit**

```bash
git add aegis/broker/patchers.py tests/test_broker/test_patchers.py
git commit -m "feat(broker): optional HTTP, subprocess, filesystem patchers"
```

---

## Task 17: Identity — Attestation

**Files:**
- Create: `aegis/identity/attestation.py`
- Create: `tests/test_identity/test_attestation.py`

**Specification (from PLAN.md §4.4):**
- HMAC-SHA256 (zero deps) or Ed25519 (requires `cryptography`)
- `create_attestation(keypair, operator_id, model, system_prompt, capabilities, ttl_seconds) -> Attestation`
- `verify_attestation(attestation, public_key) -> bool`
- Attestation fields: agent_id, operator_id, purpose_hash (SHA-256 of system prompt), declared_capabilities, ttl, nonce (replay protection), signature, timestamp
- System prompt is hashed, never stored
- `generate_keypair(key_type="hmac-sha256") -> KeyPair`

**Step 1: Write tests**

- `test_create_hmac_attestation` — creates valid attestation
- `test_verify_hmac_valid` — verification passes with correct key
- `test_verify_hmac_invalid` — verification fails with wrong key
- `test_purpose_hash_not_stored` — system prompt not in attestation
- `test_attestation_expiry` — expired attestation fails verification
- `test_nonce_uniqueness` — two attestations have different nonces
- `test_generate_keypair_hmac`
- `test_ed25519_if_available` — skip if cryptography not installed

**Step 2: Implement attestation**

**Step 3: Run tests, commit**

```bash
git add aegis/identity/attestation.py tests/test_identity/test_attestation.py
git commit -m "feat(identity): cryptographic attestation with HMAC + optional Ed25519"
```

---

## Task 18: Identity — Trust Tiers

**Files:**
- Create: `aegis/identity/trust.py`
- Create: `tests/test_identity/test_trust.py`

**Specification (from PLAN.md §4.4):**
- Tiers: 0 (Unknown), 1 (Attested), 2 (Established), 3 (Vouched)
- Trust score grows logarithmically with clean interactions
- Bonuses: attestation (+15), operator delegation (+configurable), vouching (+8 per qualified voucher)
- Penalties: flagged interactions (proportional), behavioral anomalies (exponential), purpose hash changes
- Time decay: 14-day half-life
- Persistence: save/load from `.aegis/trust.json`
- `TrustManager(config)` — manages records
- `get_tier(agent_id) -> int`
- `record_interaction(agent_id, clean=True, anomaly=False)`
- `vouch(voucher_id, target_id)`
- `report_compromise(agent_id)` — immediate Tier 0 + score zeroed
- `set_operator_delegation(agent_id, bonus)`

**Step 1: Write tests covering all tier transitions, decay, persistence**

**Step 2: Implement trust manager**

**Step 3: Run tests, commit**

```bash
git add aegis/identity/trust.py tests/test_identity/test_trust.py
git commit -m "feat(identity): trust tier system with decay, vouching, persistence"
```

---

## Task 19: Identity — NK Cell Analysis

**Files:**
- Create: `aegis/identity/nkcell.py`
- Modify: `aegis/identity/__init__.py`
- Create: `tests/test_identity/test_nkcell.py`

**Specification (from PLAN.md §4.4):**
Signal-balance model — activating vs inhibitory signals determine verdict.

Activating signals (0.0-1.0 each):
- Missing attestation (higher weight if peers present theirs)
- Expired/invalid attestation
- Capability violations
- Severe behavioral drift (σ > 3.0)
- Content threats from scanner
- Communication explosion (superspreader)
- Purpose hash changes

Inhibitory signals:
- Valid current attestation
- Capabilities within scope
- Stable behavioral profile (σ < 1.0)
- Clean interaction history (> 98%)

Verdicts: `normal` → `elevated` → `suspicious` → `hostile`
Actions: `none` → `increase_scanning` → `flag` → `quarantine`
Thresholds from config: elevated=0.3, suspicious=0.6, hostile=0.85

- `NKCell(config)` — analyzer
- `assess(agent_context) -> NKVerdict` where agent_context bundles available signals
- `NKVerdict`: score (0.0-1.0), verdict, recommended_action, activating_signals, inhibitory_signals

**Step 1: Write tests for each signal type and verdict level**

**Step 2: Implement NK cell analyzer**

**Step 3: Run tests, commit**

```bash
git add aegis/identity/ tests/test_identity/
git commit -m "feat(identity): NK cell signal-balance analysis"
```

---

## Task 20: Behavior — Tracker

**Files:**
- Create: `aegis/behavior/tracker.py`
- Create: `tests/test_behavior/test_tracker.py`

**Specification (from PLAN.md §4.7):**
Rolling behavioral fingerprint per agent. Tracked dimensions:
- Message frequency and timing
- Output length distribution
- Tool usage distribution
- Content type ratios (code, URLs, structured data)
- Interaction pattern (unique targets contacted)

- `BehaviorTracker(config)` with rolling window (default 100 events)
- `record_event(event)` — add to rolling window
- `get_fingerprint(agent_id) -> BehaviorFingerprint` — current profile
- `BehaviorFingerprint`: per-dimension mean/std, fingerprint_hash, event_count

**Step 1: Write tests**

- `test_record_and_fingerprint` — add events, get profile
- `test_rolling_window` — old events drop off
- `test_fingerprint_hash_changes` — hash reflects profile state
- `test_multiple_agents` — separate profiles per agent_id

**Step 2: Implement tracker**

**Step 3: Run tests, commit**

```bash
git add aegis/behavior/tracker.py tests/test_behavior/test_tracker.py
git commit -m "feat(behavior): rolling behavioral fingerprint tracker"
```

---

## Task 21: Behavior — Drift Detection

**Files:**
- Create: `aegis/behavior/drift.py`
- Modify: `aegis/behavior/__init__.py`
- Create: `tests/test_behavior/test_drift.py`

**Specification (from PLAN.md §4.7):**
- Per-dimension z-score against rolling window
- Zero-variance baselines handled with ratio-based detection
- New tool usage flagged immediately
- `DriftDetector(config)` with threshold (default 2.5 sigma)
- `check_drift(fingerprint, event) -> DriftResult`
- `DriftResult`: max_sigma, per_dimension_scores, anomalous_dimensions, is_drifting, new_tools

**Step 1: Write tests**

- `test_no_drift_normal_behavior` — stable events → no drift
- `test_drift_detected_length_spike` — sudden output length change
- `test_new_tool_flagged` — using a tool never seen before
- `test_zero_variance_handling` — doesn't divide by zero
- `test_threshold_configurable`

**Step 2: Implement drift detector**

**Step 3: Run tests, commit**

```bash
git add aegis/behavior/ tests/test_behavior/
git commit -m "feat(behavior): statistical drift detection with z-score analysis"
```

---

## Task 22: Memory — Guard

**Files:**
- Create: `aegis/memory/guard.py`
- Create: `tests/test_memory/test_guard.py`

**Specification (from PLAN.md §4.5):**
- Schema-enforced categories: `fact`, `state`, `observation`, `history_summary`
- Blocked categories: `instruction`, `policy`, `directive`, `tool_config`
- `MemoryGuard(config, scanner=None)` — optionally uses scanner for content validation
- `validate_write(entry) -> WriteResult` — checks category + content
- `MemoryEntry`: key, value, category, provenance, ttl, timestamp
- `WriteResult`: allowed (bool), reason, sanitized_value (if modified)

**Step 1: Write tests**

- `test_allows_fact_category` — fact entries pass
- `test_blocks_instruction_category` — instruction entries rejected
- `test_scanner_validates_content` — if scanner present, content is scanned
- `test_unknown_category_blocked` — categories not in allowed list fail
- `test_passthrough_killswitch` — all writes allowed when killswitch active

**Step 2: Implement memory guard**

**Step 3: Run tests, commit**

```bash
git add aegis/memory/guard.py tests/test_memory/test_guard.py
git commit -m "feat(memory): schema-constrained write guard"
```

---

## Task 23: Memory — Taint Tracking & TTL

**Files:**
- Create: `aegis/memory/taint.py`
- Create: `aegis/memory/ttl.py`
- Modify: `aegis/memory/__init__.py`
- Create: `tests/test_memory/test_taint.py`
- Create: `tests/test_memory/test_ttl.py`

**Specification (from PLAN.md §4.5):**

Taint tracking:
- Every entry tagged with provenance source
- Tainted entries cannot be retrieved into trusted instruction channels
- `TaintTracker`: `tag(entry, provenance) -> TaintedEntry`, `is_tainted(entry) -> bool`, `get_provenance(entry) -> str`
- `filter_for_channel(entries, channel) -> list` — removes tainted entries from trusted channels

TTL enforcement:
- Default TTL 168 hours (7 days) for derived entries
- `TTLManager`: `check_expired(entries) -> tuple[valid, expired]`
- Diff-based anomaly detection: blocks additions of global overrides/tool directives not in prior state
- `check_diff_anomaly(old_state, new_state) -> list[Anomaly]`

**Step 1: Write tests for both taint and TTL**

**Step 2: Implement taint tracker and TTL manager**

**Step 3: Run tests, commit**

```bash
git add aegis/memory/ tests/test_memory/
git commit -m "feat(memory): taint tracking, TTL enforcement, diff anomaly detection"
```

---

## Task 24: Skills — Manifest & Static Analysis

**Files:**
- Create: `aegis/skills/manifest.py`
- Create: `aegis/skills/quarantine.py`
- Create: `tests/test_skills/test_manifest.py`
- Create: `tests/test_skills/test_quarantine.py`

**Specification (from PLAN.md §4.6):**

Skill manifest (`aegis.manifest.json`):
- Fields: name, version, publisher, hashes (sha256), signature, capabilities (network, filesystem, tools, read_write), secrets, budgets, sandbox
- `SkillManifest` dataclass, `load_manifest(path) -> SkillManifest`, `validate_manifest(manifest) -> ValidationResult`

Static analysis (quarantine):
- Python AST analysis for dangerous patterns (exec, eval, subprocess, os.system, import of dangerous modules)
- Shell pattern detection
- `analyze_code(code, language) -> AnalysisResult` with findings and risk score
- `AnalysisResult`: findings list, risk_score, safe (bool)

**Step 1: Write tests**

- `test_load_valid_manifest`
- `test_reject_invalid_manifest` — missing required fields
- `test_hash_verification` — content hash matches
- `test_detect_exec_in_code` — Python exec() flagged
- `test_detect_subprocess` — subprocess.run flagged
- `test_clean_code_passes` — safe code returns safe=True

**Step 2: Implement manifest + static analysis**

**Step 3: Run tests, commit**

```bash
git add aegis/skills/manifest.py aegis/skills/quarantine.py tests/test_skills/
git commit -m "feat(skills): manifest standard and static analysis quarantine"
```

---

## Task 25: Skills — Loader

**Files:**
- Create: `aegis/skills/loader.py`
- Modify: `aegis/skills/__init__.py`
- Create: `tests/test_skills/test_loader.py`

**Specification (from PLAN.md §4.6):**
Loader shim intercepts skill download/installation:
1. Verify manifest signature and content hash
2. Static analysis
3. Install into sandboxed environment
4. Inject Action Broker as only access to OS/network
5. Start in incubation mode (read-only)
6. Hash-based deduplication

- `SkillLoader(config, broker=None, scanner=None)`
- `load_skill(path, manifest) -> LoadResult`
- `LoadResult`: approved (bool), reason, incubation (bool), skill_hash
- Hash cache for previously approved/rejected skills

**Step 1: Write tests**

**Step 2: Implement loader**

**Step 3: Run tests, commit**

```bash
git add aegis/skills/ tests/test_skills/
git commit -m "feat(skills): loader shim with hash dedup and incubation mode"
```

---

## Task 26: Recovery — Quarantine, Rollback, Purge

**Files:**
- Create: `aegis/recovery/quarantine.py`
- Create: `aegis/recovery/rollback.py`
- Create: `aegis/recovery/purge.py`
- Modify: `aegis/recovery/__init__.py`
- Create: `tests/test_recovery/test_quarantine.py`
- Create: `tests/test_recovery/test_rollback.py`
- Create: `tests/test_recovery/test_purge.py`

**Specification (from PLAN.md §4.8):**

Quarantine management:
- `RecoveryQuarantine(config)` — coordinates with broker quarantine
- `enter(reason, read_only=True)` — activate quarantine
- `exit()` — deactivate (requires explicit call)
- `auto_quarantine(nk_verdict, drift_result)` — check if thresholds exceeded
- Config: `auto_quarantine=True`, `quarantine_on_hostile_nk=True`

Context rollback:
- `ContextRollback()` — manages snapshots
- `save_snapshot(context, snapshot_id)` — save known-good state
- `rollback(snapshot_id) -> context` — restore saved state
- `list_snapshots() -> list[SnapshotInfo]`

Memory purge:
- `MemoryPurge(memory_module=None)`
- `purge_tainted(window_hours=24)` — remove tainted entries within window
- `purge_by_provenance(provenance)` — remove all entries from source
- Returns list of purged entries

**Step 1: Write tests for all three components**

**Step 2: Implement recovery module**

**Step 3: Run tests, commit**

```bash
git add aegis/recovery/ tests/test_recovery/
git commit -m "feat(recovery): quarantine management, context rollback, memory purge"
```

---

## Task 27: Shield Orchestrator

**Files:**
- Create: `aegis/shield.py`
- Create: `tests/test_shield.py`

**Specification (from PLAN.md §3, §5.2, §7):**
Unified orchestrator that composes modules into a pipeline.

- `Shield(policy=None, modules=None, mode="observe")`
  - Loads config from policy path or auto-discovery
  - Instantiates requested modules
  - Wires module composition (scanner → identity → broker → behavior → recovery)
- `shield.wrap(client, tools=None)` — returns wrapped client with protection
- `shield.scan_input(text) -> ScanResult`
- `shield.evaluate_action(action_request) -> ActionResponse`
- `shield.sanitize_output(text) -> SanitizeResult`
- Graceful degradation when modules absent
- Mode: `observe` (log only) vs `enforce` (block/quarantine)
- Respects killswitch

Pipeline flow (PLAN.md §7):
1. Incoming content → Scanner (envelope + scan)
2. Scanner results → Identity (NK assess, trust eval)
3. Trust tier + NK verdict → Broker (policy enforcement)
4. Action outcome → Behavior Tracker (record, check drift)
5. Anomalies → Recovery (quarantine/reset/purge if triggered)

**Step 1: Write tests**

- `test_shield_with_all_modules` — all modules compose
- `test_shield_scanner_only` — works with just scanner
- `test_shield_broker_only` — works with just broker
- `test_observe_mode_logs_only` — threats detected but not blocked
- `test_enforce_mode_blocks` — threats actually blocked
- `test_killswitch_passthrough` — everything passes when killswitch active
- `test_graceful_degradation` — missing modules don't crash

**Step 2: Implement Shield**

**Step 3: Run tests, commit**

```bash
git add aegis/shield.py tests/test_shield.py
git commit -m "feat: Shield orchestrator composing all modules"
```

---

## Task 28: Provider Wrapper — Base

**Files:**
- Create: `aegis/providers/base.py`
- Create: `tests/test_providers/test_base.py`

**Purpose:** Abstract base for provider wrappers. Defines the interception protocol.

- `BaseWrapper(shield)` — holds reference to Shield
- Intercepts: `create()` / `generate()` calls → scan input, wrap envelope, scan output, sanitize
- If broker present: intercept tool calls → evaluate → allow/deny
- Returns wrapped client that preserves original API

**Step 1: Write tests with mock client**

**Step 2: Implement base wrapper**

**Step 3: Run tests, commit**

```bash
git add aegis/providers/base.py tests/test_providers/test_base.py
git commit -m "feat(providers): base wrapper with interception protocol"
```

---

## Task 29: Provider Wrappers — Anthropic, OpenAI, Generic

**Files:**
- Create: `aegis/providers/anthropic.py`
- Create: `aegis/providers/openai.py`
- Create: `aegis/providers/generic.py`
- Create: `tests/test_providers/test_anthropic.py`
- Create: `tests/test_providers/test_openai.py`

**Purpose:** Concrete wrappers for specific LLM providers.

- Anthropic: wraps `client.messages.create()`, intercepts tool_use blocks
- OpenAI: wraps `client.chat.completions.create()`, intercepts function_call/tool_calls
- Generic: wraps any client with `create`/`generate` method pattern
- Auto-detect provider from client class name
- All delegate to base wrapper interception protocol

**Step 1: Write tests with mocked SDK clients**

**Step 2: Implement provider wrappers**

**Step 3: Run tests, commit**

```bash
git add aegis/providers/ tests/test_providers/
git commit -m "feat(providers): Anthropic, OpenAI, and generic client wrappers"
```

---

## Task 30: Top-Level API

**Files:**
- Modify: `aegis/__init__.py`
- Create: `tests/test_api.py`

**Purpose:** Wire up the public API from `aegis` namespace.

```python
import aegis

# Surface 1: Quick wrap
client = aegis.wrap(my_client)

# Surface 2: Shield with modules
shield = aegis.Shield(policy="aegis.yaml", modules=["scanner", "broker"], mode="enforce")
client = shield.wrap(my_client, tools=my_tools)

# Direct access
from aegis.core import killswitch
from aegis.identity import attestation
```

Exports from `aegis/__init__.py`:
- `wrap(client, **kwargs)` — convenience function that creates a default Shield and wraps
- `Shield` — re-exported from `aegis.shield`
- `__version__`
- `killswitch` — re-exported module

**Step 1: Write tests for top-level API**

- `test_wrap_returns_wrapped_client`
- `test_shield_constructor`
- `test_version_accessible`
- `test_killswitch_accessible`

**Step 2: Implement top-level exports**

**Step 3: Run full test suite**

Run: `pytest tests/ -v --tb=short`

**Step 4: Commit**

```bash
git add aegis/__init__.py tests/test_api.py
git commit -m "feat: top-level API with wrap() and Shield exports"
```

---

## Task 31: Final Integration Test & Cleanup

**Files:**
- Create: `tests/test_integration.py`
- Modify: `aegis.yaml.example` (ensure it matches implementation)

**Purpose:** End-to-end integration test exercising the full pipeline.

**Test scenario:**
1. Create Shield with all modules
2. Wrap a mock client
3. Send clean message → passes through
4. Send message with prompt injection → detected, blocked in enforce mode
5. Send tool call → broker evaluates against manifests
6. Exceed budget → broker denies
7. Trigger quarantine → subsequent writes denied
8. Test killswitch disables everything

**Step 1: Write integration test**

**Step 2: Run full suite**

Run: `pytest tests/ -v --tb=short`

**Step 3: Commit**

```bash
git add tests/test_integration.py aegis.yaml.example
git commit -m "test: end-to-end integration test for full AEGIS pipeline"
```

---

## Summary

| Task | Module | Description |
|------|--------|-------------|
| 1 | — | Project scaffolding |
| 2 | core | Killswitch |
| 3 | core | Config auto-discovery |
| 4 | core | Telemetry |
| 5 | scanner | Threat signature database |
| 6 | scanner | Pattern matcher |
| 7 | scanner | Semantic analyzer |
| 8 | scanner | Prompt envelope |
| 9 | scanner | Outbound sanitizer |
| 10 | scanner | Module integration |
| 11 | broker | Action types |
| 12 | broker | Capability manifests |
| 13 | broker | Write budgets & rate limits |
| 14 | broker | Quarantine mode |
| 15 | broker | Policy engine |
| 16 | broker | Endpoint patchers |
| 17 | identity | Attestation |
| 18 | identity | Trust tiers |
| 19 | identity | NK cell analysis |
| 20 | behavior | Tracker |
| 21 | behavior | Drift detection |
| 22 | memory | Guard |
| 23 | memory | Taint tracking & TTL |
| 24 | skills | Manifest & static analysis |
| 25 | skills | Loader |
| 26 | recovery | Quarantine, rollback, purge |
| 27 | — | Shield orchestrator |
| 28 | providers | Base wrapper |
| 29 | providers | Anthropic, OpenAI, generic |
| 30 | — | Top-level API |
| 31 | — | Integration tests |

**Dependencies:** Tasks 1→2→3→4 are sequential (core foundation). After Task 4, Tasks 5-9 (scanner), 11-16 (broker), 17-19 (identity), 20-21 (behavior), 22-23 (memory), 24-25 (skills), 26 (recovery) can be parallelized. Tasks 27-31 depend on their respective modules being complete.
