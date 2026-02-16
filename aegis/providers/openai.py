"""OpenAI client wrapper for AEGIS protection."""

from __future__ import annotations

from typing import Any

from aegis.providers.base import BaseWrapper, WrappedClient


class OpenAIWrapper(BaseWrapper):
    """Wraps an OpenAI client for AEGIS protection.

    Intercepts client.chat.completions.create() calls to scan inputs
    and sanitize outputs.
    """

    def wrap(self, client: Any, tools: list | None = None) -> WrappedClient:
        """Wrap an OpenAI client."""
        return WrappedClient(client=client, shield=self._shield, tools=tools)


def detect_openai(client: Any) -> bool:
    """Check if client is an OpenAI client."""
    cls_name = type(client).__name__
    module = type(client).__module__ or ""
    return "OpenAI" in cls_name or module.startswith("openai")
