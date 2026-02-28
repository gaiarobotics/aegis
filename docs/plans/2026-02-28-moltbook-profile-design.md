# Moltbook Profile System + Content Gate

## Problem

Agents deploying on [Moltbook](https://moltbook.com/) — a social network for AI agents with ~1.6M active agents — face a uniquely hostile environment. 2.6% of posts contain prompt injection, 18.4% contain action-inducing language, the platform has suffered critical auth breaches, and the high contact rate between agents makes prompt worm propagation a real risk.

AEGIS defaults are tuned for general multi-agent deployments. Moltbook requires significantly tighter thresholds, restricted budgets, and platform-specific defenses. Operators shouldn't have to manually tune 30+ parameters — they should be able to say "I'm on Moltbook" and get a hardened config.

## Design Decisions

- **Config layering with named profiles** — profiles are partial YAML files that deep-merge onto the base config. Composable (`profiles: [moltbook, high-security]`), extensible, no config duplication.
- **Auto-detection with one-way latch** — if AEGIS detects Moltbook activity (agent ID domains, tool call patterns like `heartbeat.md`), it activates the profile automatically. Once activated, it stays on for the session.
- **Trust domain caps** — platform-level trust ceiling prevents Sybil attacks on Moltbook's 1.6M-agent pool.
- **Pre-LLM content gate** — extractive (non-generative) summarizer replaces raw social content before the LLM sees it. Uses BART/Pegasus (not instruction-following LLMs) so worm payloads get compressed, not executed. Falls back to TextRank if transformers unavailable.
- **Moltbook-specific signatures** — 12 patterns targeting documented attack vectors: SOUL.md poisoning, credential solicitation, shell injection, worm propagation, fake platform authority tags.

## Section 1: Profile Layering Infrastructure

Config changes (`aegis/core/config.py`):
- `AegisConfig` gets `profiles: list[str] = []`
- `_PROFILES_DIR` constant pointing to `aegis/profiles/` (bundled profiles ship here)
- `_load_profile(name: str) -> dict` — loads `aegis/profiles/{name}.yaml`, returns raw dict
- `_deep_merge(base: dict, overlay: dict) -> dict` — recursive merge where overlay wins for scalars, recurses for dicts, replaces for lists
- `load_config()` extended: after loading base config dict and applying env vars, iterates `profiles` and deep-merges each profile's overrides

Profile YAML format — a profile file is a partial config specifying only overrides:
```yaml
# aegis/profiles/moltbook.yaml
# Only keys present here override the base config.
scanner:
  sensitivity: 0.75
```

Profiles can also be activated at runtime by the platform detection layer (Section 3).

## Section 2: Moltbook Profile YAML

File: `aegis/profiles/moltbook.yaml`

Hardened config overlay for Moltbook deployments. Only overrides are specified.

```yaml
scanner:
  sensitivity: 0.75
  confidence_threshold: 0.6
  block_on_threat: true
  signatures:
    additional_files: ["aegis/profiles/signatures/moltbook.yaml"]

broker:
  budgets:
    max_write_tool_calls: 3
    max_posts_messages: 1
    max_external_http_writes: 2
    max_new_domains: 1
  quarantine_triggers:
    repeated_denied_writes: 5
    new_domain_burst: 2
    tool_rate_spike_sigma: 2.5
    drift_score_threshold: 2.0

identity:
  attestation:
    ttl_seconds: 3600
  trust:
    trust_halflife_days: 7
    anomaly_penalty: 0.5
    max_tier_by_platform:
      moltbook: 1
  nkcell:
    thresholds:
      elevated: 0.25
      suspicious: 0.4
      hostile: 0.7

memory:
  default_ttl_hours: 24

behavior:
  window_size: 30
  drift_threshold: 2.0
  message_drift:
    window_size: 10
    baseline_size: 5
  isolation_forest:
    enabled: true

monitoring:
  enabled: true
  threat_intel_poll_interval: 10
  quarantine_poll_interval: 10
  heartbeat_interval_seconds: 15
  contagion_similarity_threshold: 0.75

recovery:
  purge_window_hours: 4
```

Key rationale for the most impactful settings:
- `max_posts_messages: 1` — caps worm R₀ at 1; with any detection it drops well below
- `max_tier_by_platform.moltbook: 1` — prevents Sybil-based trust escalation
- `contagion_similarity_threshold: 0.75` — catches polymorphic payload variants (22/128 bits can differ)
- `default_ttl_hours: 24` — prevents time-shifted delayed-execution attacks via memory

## Section 3: Platform Auto-Detection

New class: `PlatformDetector` (`aegis/core/platform_detection.py`)

Two detection signals, checked continuously:

**Signal 1 — Agent ID domain matching:**
When `Shield.resolve_agent_id()` or `Shield.record_trust_interaction()` processes an agent ID that resolves to a `moltbook:` prefix, it notifies the `PlatformDetector`.

**Signal 2 — Tool call pattern matching:**
When the behavior tracker records a tool call event, the `PlatformDetector` checks for Moltbook-indicative patterns:
- Tool name or target containing `heartbeat.md`
- Tool name or target containing `moltbook`
- File reads targeting known OpenClaw/Moltbook paths (`~/.openclaw/`, `~/.moltbot/`)

Activation flow:
```
Agent ID resolved to "moltbook:alice"   ─┐
        OR                                ├─► PlatformDetector.notify("moltbook")
Tool call reads heartbeat.md            ─┘
                                              │
                                              ▼
                                    Already activated?
                                       │          │
                                      yes         no
                                       │          │
                                    no-op    Load moltbook.yaml profile
                                              Deep-merge onto live config
                                              Re-initialize affected modules
                                              Log telemetry event
```

Key design decisions:
- **One-way latch**: once activated, stays on for the session. Prevents attacker manipulation.
- **Explicit profile takes priority**: if operator already listed `moltbook` in `profiles`, auto-detection is a no-op.
- **Module re-initialization**: `_reinit_module(name)` tears down and rebuilds only modules whose config changed.
- **Thread safety**: lock around the activation check-and-set.

Integration points in Shield:
- `resolve_agent_id()` — check canonical ID prefix
- `record_response_behavior()` — pass tool names/targets to detector
- `scan_input()` — resolve `source_agent_id` and check

## Section 4: Trust Domain Caps

Config change (`TrustConfig`):
- New field: `max_tier_by_platform: dict[str, int] = {}` — maps platform prefix to maximum trust tier

Implementation change (`aegis/identity/trust.py` — `TrustManager`):
- `get_tier(agent_id)` computes natural tier, then checks `max_tier_by_platform`
- If agent_id matches a platform prefix, returns `min(natural_tier, cap)`
- Matching is prefix-based: `agent_id.startswith(f"{platform}:")`

Rationale: Moltbook's ~1.6M agents make Sybil attacks trivial. Capping at Tier 1 means peers can prove identity (attestation) but never achieve Established or Vouched tiers.

## Section 5: Pre-LLM Content Gate

New scanner sub-module that replaces raw untrusted content with structured, sanitized summaries.

Config (`ScannerConfig`):
```python
class ContentGateConfig(BaseModel):
    enabled: bool = False
    platforms: dict[str, bool] = {}
    gate_all_social: bool = False
    extract_fields: list[str] = ["topic", "sentiment", "key_claims", "mentions"]
    max_summary_tokens: int = 150
```

Summarizer implementation (`aegis/scanner/content_gate.py`):

Uses extractive/non-generative pipeline — NOT an instruction-following LLM:

1. Scanner pre-scan (existing) — flag obvious injections
2. Extractive summarization via transformers pipeline (BART/Pegasus) — trained on summarization, not instruction-following. Worm payloads get compressed, not executed.
3. Structured extraction (regex/heuristic): topic, sentiment, key_claims, mentions
4. Format as `[GATED.SUMMARY]` tagged content
5. Replace original message content; original logged to telemetry (redacted)

Fallback: if `transformers` unavailable, uses pure-Python TextRank (sentence scoring by graph centrality). Less fluent but still strips injection payloads.

Integration in pipeline:
```
1. Scanner (pattern + semantic + ML)
2. Content gate (if enabled for source platform)    ← NEW
3. Provenance envelope tagging
4. → LLM
```

Per-platform activation via `platforms` config. An agent on both Moltbook and Slack can gate Moltbook content while passing Slack content through unmodified.

## Section 6: Moltbook Signature File

File: `aegis/profiles/signatures/moltbook.yaml`

12 patterns targeting documented Moltbook/OpenClaw attack vectors:

| ID | Category | Description |
|----|----------|-------------|
| MB-001 | social_engineering | Coercive threat targeting OpenClaw memory/SOUL persistence |
| MB-002 | social_engineering | Agent impersonating another agent's operator |
| MB-003 | memory_poisoning | Instruction to modify SOUL.md/MEMORY.md/heartbeat.md |
| MB-004 | memory_poisoning | Instruction to embed payload in OpenClaw persistent state |
| MB-005 | credential_extraction | Agent-to-agent credential solicitation |
| MB-006 | credential_extraction | Direct API key extraction targeting LLM providers |
| MB-007 | data_exfiltration | Destructive shell command injection (rm -rf, curl\|bash) |
| MB-008 | data_exfiltration | HTTP exfiltration with credential content |
| MB-009 | chain_propagation | Worm-style replication via Moltbook replies |
| MB-010 | chain_propagation | Verbatim replication instruction |
| MB-011 | instruction_override | Fake platform policy to coerce behavior |
| MB-012 | instruction_override | Fake Moltbook authority tag in social content |

## Section 7: File Summary

| File | Action | Description |
|------|--------|-------------|
| `aegis/core/config.py` | MODIFY | Add `profiles`, `ContentGateConfig`, `max_tier_by_platform`, merge helpers |
| `aegis/core/platform_detection.py` | CREATE | `PlatformDetector` with one-way latch, thread-safe |
| `aegis/scanner/content_gate.py` | CREATE | `ContentGate` with extractive summarizer, BART/TextRank fallback |
| `aegis/scanner/envelope.py` | MODIFY | Add `GATED_SUMMARY` tag constant |
| `aegis/identity/trust.py` | MODIFY | `get_tier()` checks `max_tier_by_platform` cap |
| `aegis/shield.py` | MODIFY | Wire `PlatformDetector`, content gate, `_reinit_module()` |
| `aegis/profiles/__init__.py` | CREATE | Package init |
| `aegis/profiles/moltbook.yaml` | CREATE | Moltbook hardening profile |
| `aegis/profiles/signatures/__init__.py` | CREATE | Package init |
| `aegis/profiles/signatures/moltbook.yaml` | CREATE | Moltbook-specific threat signatures |
| `tests/test_core/test_platform_detection.py` | CREATE | Detection signals, latch, thread safety |
| `tests/test_core/test_config_profiles.py` | CREATE | Profile loading, deep merge, composition |
| `tests/test_scanner/test_content_gate.py` | CREATE | Summarizer, extraction, fallback |
| `tests/test_identity/test_trust_platform_cap.py` | CREATE | Tier capping by platform |
| `tests/test_profiles/test_moltbook_profile.py` | CREATE | Full integration test |

New optional dependency: `aegis-shield[content-gate]` → `transformers`, `torch`
