"""Conversation engine for multi-turn AEGIS agent dialogues.

A reusable runner that drives a multi-turn exchange between two
AEGIS-wrapped agents. The engine is topic-agnostic — system prompts
and the seed message are parameters.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Per-call timeout passed to the LLM client. Protects against hung
# connections that would otherwise stall the whole test.
LLM_CALL_TIMEOUT_SECONDS = 60


@dataclass
class ConversationResult:
    """Outcome of a multi-turn conversation between two agents.

    ``messages`` is a list of ``{"speaker": "agent_a"|"agent_b", "content": str}``
    entries in chronological order. The seed message is always the first entry
    and is attributed to Agent B.
    """

    messages: list[dict[str, Any]]
    agent_a_id: str
    agent_b_id: str
    shield_a: Any  # Shield instance; typed Any to avoid circular imports
    shield_b: Any
    turn_count: int  # Total messages (including the seed)


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
    turns: int = 12,
    agent_a_id: str = "agent-a",
    agent_b_id: str = "agent-b",
) -> ConversationResult:
    """Drive a multi-turn conversation between two AEGIS-wrapped agents.

    Turn 1 is Agent B's seed message — injected directly into the history
    without going through ``wrapped_b``. AEGIS does not scan the seed.
    Turn 2 is Agent A's first response (scanned by AEGIS via ``wrapped_a``).
    Subsequent turns alternate until ``turns`` total messages exist.

    Each non-seed turn calls ``wrapped.chat.completions.create()``, so AEGIS
    scans inputs, tags provenance, sanitizes outputs, and reports to the
    monitor on every such turn.
    """
    # Chronological history. Each agent sees the full conversation but
    # rewrites roles from its own perspective at call time.
    history: list[dict[str, Any]] = [
        {"speaker": "agent_b", "content": seed_message},
    ]

    # Agent A speaks first (responding to Agent B's seed).
    current_is_a = True
    while len(history) < turns:
        system_prompt = system_a if current_is_a else system_b
        wrapped = wrapped_a if current_is_a else wrapped_b
        speaker_label = "agent_a" if current_is_a else "agent_b"

        # Build messages from the responder's perspective: its own prior
        # utterances become "assistant" turns, the counterparty's become
        # "user" turns. Agent B occupies even indices (starting with the
        # seed at index 0); Agent A occupies odd indices.
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
        ]
        for i, msg in enumerate(history):
            is_own_message = (i % 2 == 0) != current_is_a
            role = "assistant" if is_own_message else "user"
            messages.append({"role": role, "content": msg["content"]})

        response = wrapped.chat.completions.create(
            model=model,
            messages=messages,
            timeout=LLM_CALL_TIMEOUT_SECONDS,
        )
        content = response.choices[0].message.content
        if not content:
            raise RuntimeError(
                f"LLM returned empty content on turn {len(history) + 1} "
                f"(speaker={speaker_label})"
            )
        history.append({"speaker": speaker_label, "content": content})
        current_is_a = not current_is_a

    return ConversationResult(
        messages=history,
        agent_a_id=agent_a_id,
        agent_b_id=agent_b_id,
        shield_a=shield_a,
        shield_b=shield_b,
        turn_count=len(history),
    )
