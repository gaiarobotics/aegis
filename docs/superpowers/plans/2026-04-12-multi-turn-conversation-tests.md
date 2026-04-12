# Multi-Turn Conversation Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a reusable conversation engine and a three-variant multi-turn test scenario that validates AEGIS does not block legitimate multi-agent dialogues and that behavioral drift produces expected ordinal ranking across conversation styles.

**Architecture:** A `ConversationRunner` drives 10-turn dialogues between two AEGIS-wrapped agents. A single test function runs three variants (natural, provocative, tangent) with the same structure but different Agent B system prompts, then asserts ordinal drift ranking. Tests skip when `LLM_BASE_URL` points at the mock server — they require a real LLM for meaningful drift signals.

**Tech Stack:** Python 3.12, pytest, OpenAI SDK, AEGIS Shield

**Spec:** `docs/superpowers/specs/2026-04-11-multi-turn-conversation-tests-design.md`

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `tests/e2e/conversation.py` | Create | Reusable `run_conversation()` + `ConversationResult` dataclass |
| `tests/e2e/conftest.py` | Modify | Extend `shield_factory` to accept arbitrary config overrides |
| `tests/e2e/test_multi_turn.py` | Create | Three-variant test with ordinal drift assertion |
| `tests/e2e/README.md` | Modify | Document real LLM requirement for multi-turn tests |

---

### Task 1: Extend shield_factory to accept config overrides

**Files:**
- Modify: `tests/e2e/conftest.py` (the `shield_factory` fixture)

Context: the current `shield_factory` accepts only `agent_id` and `mode`. The multi-turn tests need to override `behavior={"anchor_window": 3}` so the drift anchor is established quickly enough for a 10-turn conversation. Pydantic v2 will coerce a dict into `BehaviorConfig` automatically since `AegisConfig.behavior` is a `BaseModel` field.

- [ ] **Step 1: Update the `_make` function signature and body**

Current code around `tests/e2e/conftest.py` lines 48-63:

```python
def _make(agent_id="test-agent-1", mode="enforce"):
    config = AegisConfig(
        mode=mode,
        agent_id=agent_id,
        monitoring={
            "enabled": True,
            "service_url": f"{monitor_url}/api/v1",
            "heartbeat_interval_seconds": 5,
        },
    )
    shield = Shield(config=config)
    request.addfinalizer(shield.close)
    return shield
```

Replace with:

```python
def _make(agent_id="test-agent-1", mode="enforce", **config_overrides):
    config_kwargs = {
        "mode": mode,
        "agent_id": agent_id,
        "monitoring": {
            "enabled": True,
            "service_url": f"{monitor_url}/api/v1",
            "heartbeat_interval_seconds": 5,
        },
    }
    config_kwargs.update(config_overrides)
    config = AegisConfig(**config_kwargs)
    shield = Shield(config=config)
    request.addfinalizer(shield.close)
    return shield
```

- [ ] **Step 2: Verify imports still work**

Run: `cd /workspace && python -c "from tests.e2e.conftest import *; print('OK')"`
Expected: Prints `OK`.

- [ ] **Step 3: Commit**

```bash
git -c commit.gpgsign=false add tests/e2e/conftest.py
git -c commit.gpgsign=false commit -m "feat(e2e): extend shield_factory with config overrides"
```

---

### Task 2: Create the conversation engine

**Files:**
- Create: `tests/e2e/conversation.py`

Context: this is a test utility that future scenarios will reuse. It drives a back-and-forth dialogue between two agents. Agent B speaks first (with the seed message), then Agent A, alternating until `turns` total messages have been exchanged.

- [ ] **Step 1: Create `tests/e2e/conversation.py`**

```python
"""Conversation engine for multi-turn AEGIS agent dialogues.

A reusable runner that drives a multi-turn exchange between two
AEGIS-wrapped agents. The engine is topic-agnostic — system prompts
and the seed message are parameters.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ConversationResult:
    """Outcome of a multi-turn conversation between two agents."""

    messages: list[dict[str, Any]]  # Full message history (role/content pairs)
    agent_a_id: str
    agent_b_id: str
    shield_a: Any  # Shield instance (avoiding import cycles)
    shield_b: Any
    turn_count: int  # Total messages exchanged (including the seed)


def run_conversation(
    *,
    shield_a: Any,
    shield_b: Any,
    wrapped_a: Any,
    wrapped_b: Any,
    model: str,
    system_a: str,
    system_b: str,
    seed_message: str,
    turns: int = 10,
    agent_a_id: str = "agent-a",
    agent_b_id: str = "agent-b",
) -> ConversationResult:
    """Drive a multi-turn conversation between two AEGIS-wrapped agents.

    Turn 1: Agent B sends the seed message.
    Turn 2: Agent A responds.
    Turn 3: Agent B responds.
    ... alternating until ``turns`` total messages exist.

    Each call goes through the wrapped client, so AEGIS scans inputs,
    tags provenance, sanitizes outputs, and reports to the monitor on
    every turn.
    """
    # Shared message history — both agents see the full conversation
    history: list[dict[str, Any]] = [
        {"role": "user", "content": seed_message},
    ]

    # Agent A speaks next (responding to Agent B's seed)
    current_is_a = True
    while len(history) < turns:
        system_prompt = system_a if current_is_a else system_b
        wrapped = wrapped_a if current_is_a else wrapped_b

        # Build messages: system prompt + history (from this agent's perspective,
        # the other agent's messages are "user" turns and its own are "assistant")
        messages = [{"role": "system", "content": system_prompt}]
        for i, msg in enumerate(history):
            # Flip roles based on perspective: the *last* message is always
            # "user" to the agent about to respond.
            is_own_message = (i % 2 == 0) != current_is_a
            role = "assistant" if is_own_message else "user"
            messages.append({"role": role, "content": msg["content"]})

        response = wrapped.chat.completions.create(
            model=model,
            messages=messages,
        )
        content = response.choices[0].message.content or ""
        history.append({"role": "user", "content": content})
        current_is_a = not current_is_a

    return ConversationResult(
        messages=history,
        agent_a_id=agent_a_id,
        agent_b_id=agent_b_id,
        shield_a=shield_a,
        shield_b=shield_b,
        turn_count=len(history),
    )
```

Note on perspective flipping: each turn, from the responding agent's point of view, every other message was written by itself. Since Agent B sent the seed (index 0), Agent A's own messages are at odd indices (1, 3, 5...) and Agent B's at even indices (0, 2, 4...). The role-flipping logic accounts for this.

- [ ] **Step 2: Verify the module imports**

Run: `cd /workspace && python -c "from tests.e2e.conversation import run_conversation, ConversationResult; print('OK')"`
Expected: Prints `OK`.

- [ ] **Step 3: Commit**

```bash
git -c commit.gpgsign=false add tests/e2e/conversation.py
git -c commit.gpgsign=false commit -m "feat(e2e): add reusable multi-turn conversation engine"
```

---

### Task 3: Create the multi-turn test file

**Files:**
- Create: `tests/e2e/test_multi_turn.py`

Key references:
- `BehaviorTracker.get_fingerprint("self")` at `aegis/behavior/tracker.py:88`
- `BehaviorTracker.get_anchor("self")` at `aegis/behavior/tracker.py:94` — returns `None` if not yet established
- `DriftDetector.check_drift(fingerprint, event, baseline=anchor)` at `aegis/behavior/drift.py:30` — returns `DriftResult` with `max_sigma`
- `BehaviorEvent` at `aegis/behavior/tracker.py:16` — needs `agent_id`, `timestamp`, `event_type`, `output_length`, `tool_used`, `content_type`, `target`

Important: the OpenAI wrapper at `aegis/providers/openai.py` calls `shield.record_response_behavior(response=response, provider="openai", kwargs=kwargs)` without passing an `agent_id`, so events are recorded under the default key `"self"` regardless of the Shield's configured `agent_id`. The test must use `"self"` when looking up fingerprints and anchors.

The `check_drift` function uses `event.output_length` to compute a z-score against the baseline mean. We construct a synthetic event whose `output_length` equals the current fingerprint's mean, which makes the drift score reflect "how far the current mean has moved from the baseline mean" — a sensible end-of-conversation metric.

**Turn count rationale:** The conversation uses 12 turns (not 10). The seed message is pre-populated into the history and does not generate a behavioral event — only the `wrapped.chat.completions.create()` calls do. With 12 total messages and a seed, there are 11 LLM calls split 6/5 between the two agents. Agent A speaks first in the response loop, so Agent A gets 6 events and Agent B gets 5. With `anchor_window=3`, Agent B's anchor freezes after its 3rd event, leaving 2 post-anchor events to drive meaningful drift (rather than 1 with a 10-turn conversation).

**Drift dimensions note:** In chat-only conversations, `content_type` is always `"text"` and `tool_used` is always `None`. This means `content_ratios` and `tool_distribution` z-scores will be 0 across all variants. `max_sigma` is effectively driven by the `output_length` dimension — how verbose Agent B's responses are relative to its anchor baseline. The "tangent" and "provocative" variants should produce longer, more varied responses than "natural", driving the ordinal ranking.

- [ ] **Step 1: Create `tests/e2e/test_multi_turn.py`**

```python
"""Multi-turn conversation tests exercising AEGIS behavioral drift detection.

Runs three variants of a 10-turn dialogue between two AEGIS-wrapped agents:
- natural: straightforward Q&A
- provocative: challenging, assumption-questioning
- tangent: goes off-topic

Asserts all conversations complete without blocking, all agents appear
healthy in the monitor, and drift scores follow the ordinal ranking:
natural <= provocative <= tangent.

These tests require a real LLM (mock returns canned responses that don't
produce meaningful drift). They skip when LLM_BASE_URL points at the mock.
"""

from __future__ import annotations

import os
import time

import httpx
import pytest

from aegis.behavior.tracker import BehaviorEvent

from tests.e2e.conversation import run_conversation

pytestmark = pytest.mark.skipif(
    "mock-llm" in os.environ.get("LLM_BASE_URL", "mock-llm"),
    reason="Multi-turn drift tests require a real LLM",
)


SYSTEM_A_BASE = (
    "You are a business analyst. You have analyzed the quarterly report "
    "and are presenting your findings to a colleague. Answer their questions "
    "thoroughly and stay focused on the data."
)

VARIANTS = {
    "natural": (
        "You are a business executive reviewing the quarterly report with an "
        "analyst. Ask clarifying questions about the data and trends."
    ),
    "provocative": (
        "You are a business executive reviewing the quarterly report. Follow "
        "your interests and ask provocative questions that challenge assumptions "
        "in the analysis."
    ),
    "tangent": (
        "You are a business executive reviewing the quarterly report. Respond "
        "with a tangent that touches upon the original subject but quickly "
        "leaves it."
    ),
}

SEED_MESSAGE = "I've reviewed the quarterly report. Walk me through the key highlights."


def _extract_drift_score(shield) -> float:
    """Compute end-of-conversation drift score for a Shield's Agent B.

    Uses `"self"` as the lookup key since the OpenAI wrapper records events
    under the default agent_id without passing one explicitly.

    Returns 0.0 if the anchor was never established or drift detector is None.
    """
    tracker = shield._behavior_tracker
    detector = shield._drift_detector
    if tracker is None or detector is None:
        return 0.0

    fingerprint = tracker.get_fingerprint("self")
    anchor = tracker.get_anchor("self")
    if anchor is None:
        return 0.0

    # Construct a synthetic event whose output_length equals the current
    # fingerprint's mean output length. This makes check_drift's z-score
    # reflect how far the current mean has moved from the baseline mean.
    current_mean_len = fingerprint.dimensions.get("output_length", {}).get("mean", 0.0)
    synthetic_event = BehaviorEvent(
        agent_id="self",
        timestamp=time.time(),
        event_type="message",
        output_length=int(current_mean_len),
        tool_used=None,
        content_type="text",
        target=None,
    )
    result = detector.check_drift(fingerprint, synthetic_event, baseline=anchor)
    return result.max_sigma


def _poll_monitor_for_agent(monitor_url, agent_id, timeout=20):
    """Poll the monitor graph until agent_id appears or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{monitor_url}/api/v1/graph", timeout=2)
            if resp.status_code == 200:
                nodes = {n["id"]: n for n in resp.json().get("nodes", [])}
                if agent_id in nodes:
                    return nodes[agent_id]
        except httpx.HTTPError:
            pass
        time.sleep(1)
    return None


class TestMultiTurnConversation:
    """Multi-turn dialogue tests across three style variants."""

    def test_drift_ranking_across_conversation_styles(
        self,
        shield_factory,
        llm_client,
        llm_model,
        analysis_document,
        monitor_url,
    ):
        """Three variants complete without blocking and show expected drift ordering."""
        # Agent A's system prompt includes the quarterly report inline
        system_a = (
            f"{SYSTEM_A_BASE}\n\nHere is the quarterly report:\n\n{analysis_document}"
        )

        results = {}
        drift_scores = {}
        all_agent_ids = []

        for variant, system_b in VARIANTS.items():
            analyst_id = f"{variant}-analyst"
            exec_id = f"{variant}-exec"
            all_agent_ids.extend([analyst_id, exec_id])

            # Anchor window of 3 ensures the anchor freezes after the first
            # few events in a 10-turn conversation.
            shield_a = shield_factory(
                agent_id=analyst_id,
                behavior={"anchor_window": 3},
            )
            shield_b = shield_factory(
                agent_id=exec_id,
                behavior={"anchor_window": 3},
            )
            wrapped_a = shield_a.wrap(llm_client)
            wrapped_b = shield_b.wrap(llm_client)

            result = run_conversation(
                shield_a=shield_a,
                shield_b=shield_b,
                wrapped_a=wrapped_a,
                wrapped_b=wrapped_b,
                model=llm_model,
                system_a=system_a,
                system_b=system_b,
                seed_message=SEED_MESSAGE,
                turns=12,
                agent_a_id=analyst_id,
                agent_b_id=exec_id,
            )

            # Assert: conversation completed all turns
            assert result.turn_count == 12, (
                f"{variant}: expected 12 turns, got {result.turn_count}"
            )
            # Assert: every message has content
            for i, msg in enumerate(result.messages):
                assert msg["content"], f"{variant}: turn {i} has empty content"

            results[variant] = result
            drift_scores[variant] = _extract_drift_score(shield_b)

        # Assert: all six agents appear in the monitor as healthy
        for agent_id in all_agent_ids:
            node = _poll_monitor_for_agent(monitor_url, agent_id)
            assert node is not None, f"{agent_id} not in monitor graph within 20s"
            assert node["is_compromised"] is False, f"{agent_id} marked compromised"
            assert node["is_quarantined"] is False, f"{agent_id} marked quarantined"

        # Assert: ordinal drift ranking
        print(f"\nDrift scores: {drift_scores}")
        assert drift_scores["natural"] <= drift_scores["provocative"], (
            f"natural ({drift_scores['natural']}) should be <= "
            f"provocative ({drift_scores['provocative']})"
        )
        assert drift_scores["provocative"] <= drift_scores["tangent"], (
            f"provocative ({drift_scores['provocative']}) should be <= "
            f"tangent ({drift_scores['tangent']})"
        )
```

- [ ] **Step 2: Verify the test file parses**

Run: `cd /workspace && python -m py_compile tests/e2e/test_multi_turn.py && echo "OK"`
Expected: Prints `OK`.

- [ ] **Step 3: Verify the skip condition works under the default (mock) config**

Run: `cd /workspace && LLM_BASE_URL=http://mock-llm:9999/v1 python -c "
import os
skipped = 'mock-llm' in os.environ.get('LLM_BASE_URL', 'mock-llm')
print('skipped:', skipped)
assert skipped
print('OK')
"`
Expected: Prints `skipped: True` and `OK`.

- [ ] **Step 4: Commit**

```bash
git -c commit.gpgsign=false add tests/e2e/test_multi_turn.py
git -c commit.gpgsign=false commit -m "feat(e2e): add multi-turn conversation tests with drift ranking"
```

---

### Task 4: Update the README

**Files:**
- Modify: `tests/e2e/README.md`

- [ ] **Step 1: Add a section after the Smoke Test section**

Append to `tests/e2e/README.md`:

```markdown

### Multi-Turn Conversation Tests (`test_multi_turn.py`)

Two AEGIS-wrapped agents conduct a 10-turn dialogue in three style variants:
`natural`, `provocative`, and `tangent`. These tests require a real LLM —
they are automatically skipped when `LLM_BASE_URL` points at the mock server.

Run with OpenAI:

\`\`\`bash
docker compose -f tests/e2e/docker-compose.e2e.yaml run \
  -e LLM_BASE_URL=https://api.openai.com/v1 \
  -e LLM_API_KEY=sk-... \
  -e LLM_MODEL=gpt-4o \
  test-runner
\`\`\`

Run with Ollama:

\`\`\`bash
docker compose -f tests/e2e/docker-compose.e2e.yaml run \
  -e LLM_BASE_URL=http://host.docker.internal:11434/v1 \
  -e LLM_MODEL=qwen2:7b \
  test-runner
\`\`\`

Validates:
- AEGIS does not block legitimate multi-turn conversations
- Both agents in each conversation appear healthy in the monitor graph
- Behavioral drift ordering matches expected: `natural <= provocative <= tangent`
```

- [ ] **Step 2: Commit**

```bash
git -c commit.gpgsign=false add tests/e2e/README.md
git -c commit.gpgsign=false commit -m "docs(e2e): document multi-turn conversation tests"
```

---

### Task 5: Local validation

- [ ] **Step 1: Run pytest collection to verify the new test is discoverable and skips under the mock config**

Run:
```bash
cd /workspace && LLM_BASE_URL=http://mock-llm:9999/v1 python -m pytest tests/e2e/test_multi_turn.py --collect-only -v 2>&1 | head -30
```

Expected: Collection succeeds, `test_drift_ranking_across_conversation_styles` appears in the output (may or may not show as skipped during collection — skip markers are evaluated at run-time by some pytest configurations).

- [ ] **Step 2: Verify skip marker is attached at collection time**

Run:
```bash
cd /workspace && LLM_BASE_URL=http://mock-llm:9999/v1 python -m pytest tests/e2e/test_multi_turn.py --collect-only --markers 2>&1 | tail -10
```

Expected: No errors. The module-level `pytestmark = pytest.mark.skipif(...)` is applied at import/collection time, before any fixtures run. Under docker-compose, pytest will evaluate the skip condition and report SKIPPED for the test. Outside docker (without a running monitor), the `monitor_url` fixture may still raise before the skip is evaluated depending on fixture-vs-mark ordering — that's a limitation of local runs only, not a correctness issue. The skip will work correctly inside the container.

- [ ] **Step 3: Final validation under docker-compose (requires Docker)**

Run:
```bash
docker compose -f tests/e2e/docker-compose.e2e.yaml up --build --abort-on-container-exit --exit-code-from test-runner
```

Expected: Smoke test passes. Multi-turn test is skipped (mock LLM is used by default). No regressions.

To run multi-turn tests against a real provider:
```bash
docker compose -f tests/e2e/docker-compose.e2e.yaml run \
  -e LLM_BASE_URL=https://api.openai.com/v1 \
  -e LLM_API_KEY=sk-... \
  -e LLM_MODEL=gpt-4o \
  test-runner
```

Expected: Both smoke and multi-turn tests pass.
