"""Anthropic client wrapper for AEGIS protection."""

from __future__ import annotations

from typing import Any

from aegis.providers.base import BaseWrapper, WrappedClient


class AnthropicWrapper(BaseWrapper):
    """Wraps an Anthropic client for AEGIS protection.

    Intercepts client.messages.create() calls to scan inputs
    and sanitize outputs.
    """

    def wrap(self, client: Any, tools: list | None = None) -> WrappedClient:
        """Wrap an Anthropic client."""
        return WrappedClient(client=client, shield=self._shield, tools=tools)


def detect_anthropic(client: Any) -> bool:
    """Check if client is an Anthropic client."""
    cls_name = type(client).__name__
    module = type(client).__module__ or ""
    return "Anthropic" in cls_name or module.startswith("anthropic")
