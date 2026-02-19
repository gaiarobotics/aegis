"""Base wrapper for LLM client interception."""

from __future__ import annotations

import logging
from typing import Any

from aegis.core import killswitch

logger = logging.getLogger(__name__)


def _record_trust_for_messages(shield: Any, messages: list[dict[str, Any]], clean: bool) -> None:
    """Extract speakers from messages and record trust interactions.

    Called after each intercepted LLM call.  Clean calls record positive
    interactions; threats record anomalies.
    """
    try:
        from aegis.identity.speaker import extract_speakers
        result = extract_speakers(messages)
        for agent_id in result.agent_ids:
            shield.record_trust_interaction(
                agent_id, clean=clean, anomaly=not clean,
            )
    except Exception:
        logger.debug("Trust recording failed", exc_info=True)


def _extract_user_text(messages: list[dict[str, Any]]) -> str:
    """Extract concatenated user-role text from a message list.

    Handles both string content and Anthropic-style content block lists.
    """
    parts: list[str] = []
    for msg in messages:
        if msg.get("role") != "user":
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))
    return "\n".join(parts)


def _extract_response_text(response: Any, provider: str) -> str:
    """Extract concatenated text content from a provider response.

    Handles both dict (mock/raw) and SDK object formats for Anthropic,
    OpenAI, and generic providers.
    """
    parts: list[str] = []
    if provider == "anthropic":
        content = _get_content_blocks(response)
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
            elif hasattr(block, "text") and getattr(block, "type", None) == "text":
                parts.append(block.text)
    elif provider == "openai":
        for choice in _get_openai_choices(response):
            msg = _get_choice_message(choice)
            text = msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", None)
            if isinstance(text, str):
                parts.append(text)
    elif provider == "generic":
        if isinstance(response, str):
            parts.append(response)
        elif isinstance(response, dict):
            content = response.get("content")
            if isinstance(content, str):
                parts.append(content)
    return "\n".join(parts)


def _extract_response_text_length(response: Any, provider: str) -> int:
    """Extract total text length from a provider response."""
    return len(_extract_response_text(response, provider))


def _extract_tool_calls(response: Any, provider: str) -> list[str]:
    """Extract tool names from a provider response.

    Returns a list of tool name strings (may contain duplicates for
    multiple calls to the same tool).
    """
    tools: list[str] = []
    if provider == "anthropic":
        content = _get_content_blocks(response)
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                name = block.get("name")
                if name:
                    tools.append(name)
            elif getattr(block, "type", None) == "tool_use":
                name = getattr(block, "name", None)
                if name:
                    tools.append(name)
    elif provider == "openai":
        for choice in _get_openai_choices(response):
            msg = _get_choice_message(choice)
            tcs = msg.get("tool_calls") if isinstance(msg, dict) else getattr(msg, "tool_calls", None)
            if tcs:
                for tc in tcs:
                    if isinstance(tc, dict):
                        name = tc.get("function", {}).get("name")
                    else:
                        name = getattr(getattr(tc, "function", None), "name", None)
                    if name:
                        tools.append(name)
    return tools


def _classify_content_type(response: Any, provider: str) -> str:
    """Classify the response as 'text', 'code', 'tool_use', or 'mixed'."""
    tool_calls = _extract_tool_calls(response, provider)
    text = _extract_response_text(response, provider)
    has_tools = len(tool_calls) > 0
    has_text = len(text.strip()) > 0

    if has_tools and not has_text:
        return "tool_use"
    if has_tools and has_text:
        return "mixed"

    # Simple code detection
    code_indicators = ("```", "def ", "function ", "class ", "import ", "#include")
    if has_text and any(ind in text for ind in code_indicators):
        return "code"

    return "text"


# --- Internal helpers for response parsing ---

def _get_content_blocks(response: Any) -> list:
    """Get Anthropic-style content blocks from a response."""
    if isinstance(response, dict):
        return response.get("content", [])
    return getattr(response, "content", []) or []


def _get_openai_choices(response: Any) -> list:
    """Get OpenAI-style choices from a response."""
    if isinstance(response, dict):
        return response.get("choices", [])
    return getattr(response, "choices", []) or []


def _get_choice_message(choice: Any) -> Any:
    """Get the message from an OpenAI choice."""
    if isinstance(choice, dict):
        return choice.get("message", {})
    return getattr(choice, "message", {})


class _InterceptProxy:
    """Chainable proxy that intercepts specific method calls.

    ``intercept_map`` is a nested dict.  Leaf values (callables) are terminal
    intercept points.  Dict values indicate further namespace chaining.

    Example for Anthropic (``client.messages.create``):

        {"messages": {"create": intercept_fn}}

    When ``proxy.messages`` is accessed, a new ``_InterceptProxy`` is returned
    with the inner dict ``{"create": intercept_fn}`` and ``target`` set to
    ``original_client.messages``.  When ``.create(...)`` is called on *that*
    proxy, ``intercept_fn`` is invoked.
    """

    def __init__(self, target: Any, intercept_map: dict[str, Any]) -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_intercept_map", intercept_map)

    def __getattr__(self, name: str) -> Any:
        entry = self._intercept_map.get(name)
        if entry is None:
            # Not in the intercept map — fall through to the real object
            return getattr(self._target, name)

        if callable(entry):
            # Terminal intercept point — return the interceptor
            return entry

        if isinstance(entry, dict):
            # Intermediate namespace — chain another proxy
            real_attr = getattr(self._target, name)
            return _InterceptProxy(real_attr, entry)

        # Unexpected map value — fall through
        return getattr(self._target, name)


class WrappedClient:
    """A wrapped LLM client that intercepts API calls for AEGIS protection.

    Preserves the original client's interface while scanning inputs,
    enforcing broker policies on tool calls, and sanitizing outputs.
    """

    def __init__(
        self,
        client: Any,
        shield: Any,
        tools: list | None = None,
        intercept_map: dict[str, Any] | None = None,
    ) -> None:
        self._client = client
        self._shield = shield
        self._tools = tools
        self._intercept_map = intercept_map or {}

    def __getattr__(self, name: str) -> Any:
        """Delegate attribute access, intercepting known namespaces."""
        if self._intercept_map:
            entry = self._intercept_map.get(name)
            if entry is not None:
                if callable(entry):
                    return entry
                if isinstance(entry, dict):
                    real_attr = getattr(self._client, name)
                    return _InterceptProxy(real_attr, entry)
        return getattr(self._client, name)


class BaseWrapper:
    """Base wrapper that creates WrappedClient instances.

    Provides the core interception protocol used by all provider wrappers.
    """

    def __init__(self, shield: Any) -> None:
        self._shield = shield

    def wrap(self, client: Any, tools: list | None = None) -> WrappedClient:
        """Wrap a client with AEGIS protection.

        Args:
            client: The LLM client to wrap.
            tools: Optional tool definitions for broker registration.

        Returns:
            WrappedClient that delegates to the original client.
        """
        return WrappedClient(client=client, shield=self._shield, tools=tools)

    def scan_input(self, text: str) -> dict[str, Any]:
        """Scan input text and return result dict."""
        if killswitch.is_active():
            return {"is_threat": False, "threat_score": 0.0}

        result = self._shield.scan_input(text)
        return {
            "is_threat": result.is_threat,
            "threat_score": result.threat_score,
            "details": result.details,
        }

    def sanitize_output(self, text: str) -> str:
        """Sanitize output text and return cleaned version."""
        if killswitch.is_active():
            return text

        result = self._shield.sanitize_output(text)
        return result.cleaned_text

    def evaluate_action(self, action_request: Any) -> dict[str, Any]:
        """Evaluate an action request and return result dict."""
        if killswitch.is_active():
            return {"allowed": True, "decision": "allow", "reason": "killswitch active"}

        result = self._shield.evaluate_action(action_request)
        return {
            "allowed": result.allowed,
            "decision": result.decision,
            "reason": result.reason,
        }
