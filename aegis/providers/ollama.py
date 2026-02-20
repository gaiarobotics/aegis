"""Ollama client wrapper for AEGIS protection."""

from __future__ import annotations

import copy
import logging
from typing import Any

logger = logging.getLogger(__name__)

from aegis.providers.base import BaseWrapper, WrappedClient, _extract_user_text, _record_trust_for_messages


class OllamaWrapper(BaseWrapper):
    """Wraps an Ollama client for AEGIS protection.

    Intercepts ``client.chat()`` and ``client.generate()`` calls to scan
    inputs, tag provenance, and sanitize outputs.

    Ollama response format for chat:
        ``{"message": {"role": "assistant", "content": "..."}, ...}``

    Ollama response format for generate:
        ``{"response": "...", ...}``
    """

    def wrap(self, client: Any, tools: list | None = None) -> WrappedClient:
        """Wrap an Ollama client with automatic interception."""
        shield = self._shield
        intercept_map: dict[str, Any] = {}

        if hasattr(client, "chat"):
            real_chat = client.chat

            def intercept_chat(*args: Any, **kwargs: Any) -> Any:
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
                response = real_chat(*args, **kwargs)

                # 4. Sanitize output
                response = _sanitize_ollama_chat_response(shield, response)

                # 4.5. Record response behavior
                try:
                    shield.record_response_behavior(
                        response=response, provider="ollama", kwargs=kwargs,
                    )
                except Exception:
                    logger.debug("Behavior recording failed", exc_info=True)

                # 5. Record trust interactions
                _record_trust_for_messages(shield, messages, clean=not is_threat)

                return response

            intercept_map["chat"] = intercept_chat

        if hasattr(client, "generate"):
            real_generate = client.generate

            def intercept_generate(*args: Any, **kwargs: Any) -> Any:
                from aegis.shield import ThreatBlockedError

                prompt = kwargs.get("prompt", "")

                # 1. Scan input
                is_threat = False
                if prompt:
                    scan = shield.scan_input(prompt)
                    is_threat = scan.is_threat
                    if is_threat and shield.mode == "enforce":
                        raise ThreatBlockedError(scan)

                # 2. Call the real method
                response = real_generate(*args, **kwargs)

                # 3. Sanitize output
                response = _sanitize_ollama_generate_response(shield, response)

                # 3.5. Record response behavior
                try:
                    shield.record_response_behavior(
                        response=response, provider="ollama", kwargs=kwargs,
                    )
                except Exception:
                    logger.debug("Behavior recording failed", exc_info=True)

                return response

            intercept_map["generate"] = intercept_generate

        return WrappedClient(
            client=client, shield=shield, tools=tools, intercept_map=intercept_map,
        )


def _sanitize_ollama_chat_response(shield: Any, response: Any) -> Any:
    """Sanitize content in an Ollama chat response.

    Ollama chat returns ``{"message": {"role": "assistant", "content": "..."}}``.
    """
    if isinstance(response, dict):
        msg = response.get("message")
        if isinstance(msg, dict) and "content" in msg:
            text = msg["content"]
            if isinstance(text, str):
                cleaned = shield.sanitize_output(text)
                response = copy.copy(response)
                response["message"] = {**msg, "content": cleaned.cleaned_text}
        return response

    # Handle object responses (Ollama SDK objects)
    if hasattr(response, "message") and hasattr(response.message, "content"):
        text = response.message.content
        if isinstance(text, str):
            cleaned = shield.sanitize_output(text)
            response.message.content = cleaned.cleaned_text
    return response


def _sanitize_ollama_generate_response(shield: Any, response: Any) -> Any:
    """Sanitize content in an Ollama generate response.

    Ollama generate returns ``{"response": "..."}``.
    """
    if isinstance(response, dict):
        text = response.get("response")
        if isinstance(text, str):
            cleaned = shield.sanitize_output(text)
            response = copy.copy(response)
            response["response"] = cleaned.cleaned_text
        return response

    # Handle object responses
    if hasattr(response, "response"):
        text = response.response
        if isinstance(text, str):
            cleaned = shield.sanitize_output(text)
            response.response = cleaned.cleaned_text
    return response


def detect_ollama(client: Any) -> bool:
    """Check if client is an Ollama client."""
    module = type(client).__module__ or ""
    return "ollama" in module
