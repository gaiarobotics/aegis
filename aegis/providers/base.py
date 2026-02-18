"""Base wrapper for LLM client interception."""

from __future__ import annotations

import logging
import warnings
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

    @property
    def original(self) -> Any:
        """Access the unwrapped original client.

        .. deprecated::
            Use the wrapped client directly instead.  Access to the
            unwrapped client bypasses all AEGIS protections.
        """
        warnings.warn(
            "WrappedClient.original is deprecated. "
            "Accessing the unwrapped client bypasses AEGIS protections.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._client

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
