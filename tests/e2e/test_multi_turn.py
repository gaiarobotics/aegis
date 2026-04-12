"""Multi-turn conversation tests exercising AEGIS behavioral drift detection.

Runs three variants of a 12-turn dialogue between two AEGIS-wrapped agents:
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
            # few events in a 12-turn conversation.
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
