"""Anthropic client wrapper for AEGIS protection."""

from __future__ import annotations

import copy
import logging
from typing import Any

logger = logging.getLogger(__name__)

from aegis.providers.base import BaseWrapper, WrappedClient, _extract_user_text, _record_trust_for_messages


class AnthropicWrapper(BaseWrapper):
    """Wraps an Anthropic client for AEGIS protection.

    Intercepts ``client.messages.create()`` calls to scan inputs,
    tag provenance, and sanitize outputs.
    """

    def wrap(self, client: Any, tools: list | None = None) -> WrappedClient:
        """Wrap an Anthropic client with automatic interception."""
        shield = self._shield
        real_messages = client.messages

        def intercept_create(*args: Any, **kwargs: Any) -> Any:
            from aegis.shield import ThreatBlockedError

            shield.check_killswitch()

            messages = kwargs.get("messages", [])

            # 1. Scan user input
            user_text = _extract_user_text(messages)
            is_threat = False
            if user_text:
                scan = shield.scan_input(user_text)
                is_threat = scan.is_threat
                if is_threat and shield.mode == "enforce":
                    _record_trust_for_messages(shield, messages, clean=False)
                    raise ThreatBlockedError(scan)

            # 2. Tag provenance on messages
            if messages:
                kwargs["messages"] = shield.wrap_messages(messages)

            # 3. Call the real method
            response = real_messages.create(*args, **kwargs)

            # 4. Sanitize output content blocks
            response = _sanitize_anthropic_response(shield, response)

            # 4.5. Record response behavior and check drift
            try:
                shield.record_response_behavior(
                    response=response, provider="anthropic", kwargs=kwargs,
                )
            except Exception:
                logger.debug("Behavior recording failed", exc_info=True)

            # 5. Record trust interaction for discovered agents
            _record_trust_for_messages(shield, messages, clean=not is_threat)

            return response

        intercept_map = {"messages": {"create": intercept_create}}
        return WrappedClient(
            client=client, shield=shield, tools=tools, intercept_map=intercept_map,
        )


def _sanitize_anthropic_response(shield: Any, response: Any) -> Any:
    """Sanitize text blocks in an Anthropic response."""
    # Handle dict responses (common in mocks and raw API)
    if isinstance(response, dict):
        content = response.get("content")
        if isinstance(content, list):
            response = copy.copy(response)
            new_content = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    cleaned = shield.sanitize_output(block.get("text", ""))
                    block = {**block, "text": cleaned.cleaned_text}
                new_content.append(block)
            response["content"] = new_content
        return response

    # Handle object responses (Anthropic SDK message objects)
    if hasattr(response, "content") and isinstance(response.content, list):
        for block in response.content:
            if hasattr(block, "text"):
                cleaned = shield.sanitize_output(block.text)
                block.text = cleaned.cleaned_text
    return response


def detect_anthropic(client: Any) -> bool:
    """Check if client is an Anthropic client."""
    cls_name = type(client).__name__
    module = type(client).__module__ or ""
    return "Anthropic" in cls_name or module.startswith("anthropic")
