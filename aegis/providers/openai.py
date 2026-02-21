"""OpenAI client wrapper for AEGIS protection."""

from __future__ import annotations

import copy
import logging
from typing import Any

logger = logging.getLogger(__name__)

from aegis.providers.base import BaseWrapper, WrappedClient, _extract_user_text, _record_trust_for_messages


class OpenAIWrapper(BaseWrapper):
    """Wraps an OpenAI client for AEGIS protection.

    Intercepts ``client.chat.completions.create()`` calls to scan inputs
    and sanitize outputs.
    """

    def wrap(self, client: Any, tools: list | None = None) -> WrappedClient:
        """Wrap an OpenAI client with automatic interception."""
        shield = self._shield
        real_completions = client.chat.completions

        def intercept_create(*args: Any, **kwargs: Any) -> Any:
            from aegis.shield import ThreatBlockedError

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
            response = real_completions.create(*args, **kwargs)

            # 4. Sanitize output
            response = _sanitize_openai_response(shield, response)

            # 4.5. Record response behavior and check drift
            try:
                shield.record_response_behavior(
                    response=response, provider="openai", kwargs=kwargs,
                )
            except Exception:
                logger.debug("Behavior recording failed", exc_info=True)

            # 5. Record trust interaction for discovered agents
            _record_trust_for_messages(shield, messages, clean=not is_threat)

            return response

        intercept_map = {"chat": {"completions": {"create": intercept_create}}}
        return WrappedClient(
            client=client, shield=shield, tools=tools, intercept_map=intercept_map,
        )


def _sanitize_openai_response(shield: Any, response: Any) -> Any:
    """Sanitize content in an OpenAI response."""
    # Handle dict responses
    if isinstance(response, dict):
        choices = response.get("choices")
        if isinstance(choices, list):
            response = copy.copy(response)
            new_choices = []
            for choice in choices:
                if isinstance(choice, dict):
                    msg = choice.get("message", {})
                    if isinstance(msg, dict) and "content" in msg:
                        text = msg["content"]
                        if isinstance(text, str):
                            cleaned = shield.sanitize_output(text)
                            choice = copy.copy(choice)
                            choice["message"] = {**msg, "content": cleaned.cleaned_text}
                new_choices.append(choice)
            response["choices"] = new_choices
        return response

    # Handle object responses (OpenAI SDK objects)
    if hasattr(response, "choices"):
        for choice in response.choices:
            if hasattr(choice, "message") and hasattr(choice.message, "content"):
                text = choice.message.content
                if isinstance(text, str):
                    cleaned = shield.sanitize_output(text)
                    choice.message.content = cleaned.cleaned_text
    return response


def detect_openai(client: Any) -> bool:
    """Check if client is an OpenAI client."""
    cls_name = type(client).__name__
    module = type(client).__module__ or ""
    return "OpenAI" in cls_name or module.startswith("openai")
