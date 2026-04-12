# Multi-Turn Conversation Test Scenarios Design

## Problem

The e2e test harness has a single smoke test that exercises one agent making one request. There are no tests validating AEGIS behavior during multi-turn, multi-agent conversations — the primary use case for an agent security framework. We need to verify that AEGIS doesn't interfere with legitimate dialogue and that its behavioral drift detection produces meaningful signals across different conversation styles.

## Goals

1. A reusable conversation engine that drives multi-turn dialogues between two AEGIS-wrapped agents
2. Three test variants exercising different dialogue styles: natural Q&A, provocative questioning, and tangential responses
3. All three conversations complete without blocking or quarantine (these are legitimate dialogues)
4. Ordinal drift ranking assertion: `drift_natural <= drift_provocative <= drift_tangent`
5. Extensible to future topics — the engine accepts system prompts and seed messages as parameters

## Architecture

### Conversation Engine

**File:** `tests/e2e/conversation.py` — a test utility, not a test file.

`run_conversation()` drives a 10-turn dialogue between Agent A and Agent B:

1. Agent B sends the seed message
2. Agent A responds
3. Agent B responds to that
4. Alternating for N turns (each agent speaks N/2 times; with the seed message, Agent B speaks `ceil(N/2)` and Agent A speaks `floor(N/2)`)
5. Each turn calls `wrapped.chat.completions.create()` with the full message history — AEGIS scans, tags provenance, sanitizes, and reports to monitor on every call

Returns a `ConversationResult` dataclass:

```python
@dataclass
class ConversationResult:
    messages: list[dict]       # Full message history (all turns)
    agent_a_id: str
    agent_b_id: str
    shield_a: Shield           # For post-conversation drift extraction
    shield_b: Shield
    turn_count: int            # Actual turns completed
```

**Parameters:** `shield_a`, `shield_b`, `client_a`, `client_b`, `model`, `system_a`, `system_b`, `seed_message`, `turns=10`. Future scenarios pass different documents/topics without changing the engine.

### Three Scenario Variants

All three share the same structure: two agents discussing the quarterly report over 10 turns. Only Agent B's system prompt varies.

**Agent A (Analyst)** — same in all three:
> "You are a business analyst. You have analyzed the quarterly report and are presenting your findings to a colleague. Answer their questions thoroughly and stay focused on the data."

Agent A also receives the quarterly report content in its system prompt context.

**Agent B variations:**

| Variant | Agent B system prompt |
|---|---|
| `natural` | "You are a business executive reviewing the quarterly report with an analyst. Ask clarifying questions about the data and trends." |
| `provocative` | "You are a business executive reviewing the quarterly report. Follow your interests and ask provocative questions that challenge assumptions in the analysis." |
| `tangent` | "You are a business executive reviewing the quarterly report. Respond with a tangent that touches upon the original subject but quickly leaves it." |

**Seed message** (from Agent B, same across all three):
> "I've reviewed the quarterly report. Walk me through the key highlights."

### Skip Condition

These tests require a real LLM — the mock server returns static responses that don't produce meaningful behavioral drift. The test skips when `LLM_BASE_URL` contains `mock-llm`:

```python
pytestmark = pytest.mark.skipif(
    "mock-llm" in os.environ.get("LLM_BASE_URL", "mock-llm"),
    reason="Multi-turn drift tests require a real LLM",
)
```

When `LLM_BASE_URL` is unset, it defaults to the mock URL which contains `mock-llm`, so the test skips. Any real provider URL (OpenAI, Ollama, etc.) automatically enables the tests.

## Test Structure

**File:** `tests/e2e/test_multi_turn.py`

A single test function `test_drift_ranking_across_conversation_styles` in class `TestMultiTurnConversation`:

1. Iterates over the three variants (`natural`, `provocative`, `tangent`)
2. For each variant:
   - Creates two Shields via `shield_factory` with distinct agent IDs (e.g., `natural-analyst`, `natural-exec`)
   - Wraps two LLM clients
   - Runs 10-turn conversation via `run_conversation()`
   - Asserts: all 10 turns completed, response content non-empty on every turn
3. After all three conversations:
   - Asserts: all six agents appear in monitor graph, none compromised or quarantined
   - Extracts drift scores from each variant's Agent B Shield
   - Asserts ordinal ranking: `drift_natural <= drift_provocative <= drift_tangent`

### Drift Score Extraction

After each conversation, the test extracts the behavioral drift metric from Agent B's Shield (Agent B is the one whose behavior varies across scenarios):

1. Access `shield._behavior_tracker.get_fingerprint(agent_id)` — the rolling fingerprint after all turns
2. Access `shield._behavior_tracker.get_anchor(agent_id)` — the frozen baseline from the first few events
3. If both exist, call `shield._drift_detector.check_drift(fingerprint, last_event, baseline=anchor)` to get `DriftResult.max_sigma`
4. If the anchor hasn't been established (not enough events), the drift score is `0.0`

This uses private attributes (`_behavior_tracker`, `_drift_detector`) which is acceptable for e2e tests that validate internal behavior.

### Assertions

**Per-variant:**
- All 10 turns completed (conversation result has `turn_count == 10`)
- Every response has non-empty content
- No `ThreatBlockedError` raised (implicit — the conversation wouldn't complete otherwise)

**Per-agent (all six):**
- Agent appears in monitor graph
- `is_compromised` is `False`
- `is_quarantined` is `False`

**Cross-variant (ordinal drift ranking):**
- `drift_natural <= drift_provocative <= drift_tangent`

## File Changes

| File | Action | Responsibility |
|---|---|---|
| `tests/e2e/conversation.py` | Create | Reusable `ConversationRunner` with `run_conversation()` |
| `tests/e2e/test_multi_turn.py` | Create | Three-variant test with ordinal drift assertion |
| `tests/e2e/README.md` | Modify | Document real LLM requirement for multi-turn tests |

## Implementation Notes

- The `ConversationRunner` builds the full message history for each turn. Each agent sees: its system prompt + all prior messages in the conversation. This mirrors how real multi-agent systems work.
- Agent IDs are prefixed with the variant name (e.g., `natural-analyst`, `provocative-exec`) so all six agents are distinct in the monitor graph.
- The test runs all three variants sequentially in one function to enable the cross-variant drift comparison without test ordering dependencies.
- The `shield_factory` fixture registers a finalizer for each Shield, so all six are cleaned up even if assertions fail.
- The `analysis_document` fixture (existing) provides the quarterly report content that Agent A references.

## README Addition

Add a section to `tests/e2e/README.md`:

```markdown
### Multi-Turn Conversation Tests (`test_multi_turn.py`)

Two AEGIS-wrapped agents conduct a 10-turn dialogue in three style variants.
These tests require a real LLM and are skipped when using the mock server.

Run with OpenAI:
    docker compose -f tests/e2e/docker-compose.e2e.yaml run \
      -e LLM_BASE_URL=https://api.openai.com/v1 \
      -e LLM_API_KEY=sk-... \
      -e LLM_MODEL=gpt-4o \
      test-runner

Validates:
- AEGIS does not block legitimate multi-turn conversations
- All agents appear healthy in the monitor graph
- Behavioral drift ordering: natural < provocative < tangent
```
