"""Generic client wrapper for AEGIS protection."""

from __future__ import annotations

from typing import Any

from aegis.providers.base import BaseWrapper, WrappedClient


class GenericWrapper(BaseWrapper):
    """Wraps any client with a create() or generate() method.

    Provides AEGIS protection for clients that don't match
    known provider patterns (Anthropic, OpenAI).
    """

    def wrap(self, client: Any, tools: list | None = None) -> WrappedClient:
        """Wrap a generic LLM client."""
        return WrappedClient(client=client, shield=self._shield, tools=tools)


def detect_generic(client: Any) -> bool:
    """Check if client has create() or generate() methods."""
    return hasattr(client, "create") or hasattr(client, "generate")
