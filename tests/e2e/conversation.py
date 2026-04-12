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
    turns: int = 12,
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
