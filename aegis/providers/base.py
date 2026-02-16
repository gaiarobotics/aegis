"""Base wrapper for LLM client interception."""

from __future__ import annotations

from typing import Any

from aegis.core import killswitch


class WrappedClient:
    """A wrapped LLM client that intercepts API calls for AEGIS protection.

    Preserves the original client's interface while scanning inputs,
    enforcing broker policies on tool calls, and sanitizing outputs.
    """

    def __init__(self, client: Any, shield: Any, tools: list | None = None) -> None:
        self._client = client
        self._shield = shield
        self._tools = tools

    @property
    def original(self) -> Any:
        """Access the unwrapped original client."""
        return self._client

    def __getattr__(self, name: str) -> Any:
        """Delegate attribute access to the wrapped client."""
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
