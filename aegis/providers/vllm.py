"""vLLM client wrapper for AEGIS protection.

Covers vLLM's offline inference API (``vllm.LLM``).  When vLLM is used as an
OpenAI-compatible server, clients use the ``openai`` library and are handled
by ``OpenAIWrapper`` automatically.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

from aegis.providers.base import BaseWrapper, WrappedClient, _extract_user_text, _record_trust_for_messages


class VLLMWrapper(BaseWrapper):
    """Wraps a vLLM ``LLM`` instance for AEGIS protection.

    Intercepts ``llm.generate()`` and ``llm.chat()`` calls to scan inputs
    and sanitize outputs.

    vLLM generate returns a list of ``RequestOutput`` objects, each with an
    ``outputs`` list of ``CompletionOutput`` objects containing ``.text``.

    vLLM chat returns a list of ``ChatCompletionOutput`` objects.
    """

    def wrap(self, client: Any, tools: list | None = None) -> WrappedClient:
        """Wrap a vLLM LLM instance with automatic interception."""
        shield = self._shield
        intercept_map: dict[str, Any] = {}

        if hasattr(client, "generate"):
            real_generate = client.generate

            def intercept_generate(*args: Any, **kwargs: Any) -> Any:
                from aegis.shield import ThreatBlockedError

                # vLLM generate accepts prompts as first positional arg or keyword
                prompts = args[0] if args else kwargs.get("prompts")
                if prompts is None:
                    # Single prompt string
                    prompts = kwargs.get("prompt")

                # Scan all prompts
                is_threat = False
                if prompts:
                    texts = [prompts] if isinstance(prompts, str) else prompts
                    for text in texts:
                        if isinstance(text, str) and text:
                            scan = shield.scan_input(text)
                            if scan.is_threat:
                                is_threat = True
                                if shield.mode == "enforce":
                                    raise ThreatBlockedError(scan)

                # Call the real method
                results = real_generate(*args, **kwargs)

                # Sanitize outputs
                results = _sanitize_vllm_generate_response(shield, results)

                # Record response behavior
                try:
                    shield.record_response_behavior(
                        response=results, provider="vllm", kwargs=kwargs,
                    )
                except Exception:
                    logger.debug("Behavior recording failed", exc_info=True)

                return results

            intercept_map["generate"] = intercept_generate

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

                # 2. Tag provenance
                if messages:
                    kwargs["messages"] = shield.wrap_messages(messages)

                # 3. Call real method
                results = real_chat(*args, **kwargs)

                # 4. Sanitize outputs
                results = _sanitize_vllm_chat_response(shield, results)

                # 4.5. Record response behavior
                try:
                    shield.record_response_behavior(
                        response=results, provider="vllm", kwargs=kwargs,
                    )
                except Exception:
                    logger.debug("Behavior recording failed", exc_info=True)

                # 5. Record trust interactions
                _record_trust_for_messages(shield, messages, clean=not is_threat)

                return results

            intercept_map["chat"] = intercept_chat

        return WrappedClient(
            client=client, shield=shield, tools=tools, intercept_map=intercept_map,
        )


def _sanitize_vllm_generate_response(shield: Any, results: Any) -> Any:
    """Sanitize content in vLLM generate response.

    vLLM returns a list of ``RequestOutput``, each with ``.outputs`` list
    of ``CompletionOutput`` objects containing ``.text``.
    """
    if not isinstance(results, list):
        return results
    for request_output in results:
        outputs = getattr(request_output, "outputs", None)
        if outputs is None:
            continue
        for completion in outputs:
            text = getattr(completion, "text", None)
            if isinstance(text, str):
                cleaned = shield.sanitize_output(text)
                completion.text = cleaned.cleaned_text
    return results


def _sanitize_vllm_chat_response(shield: Any, results: Any) -> Any:
    """Sanitize content in vLLM chat response.

    vLLM chat returns a list of outputs. Each may have ``.outputs``
    with ``.text`` or a ``.message`` with ``.content``.
    """
    if not isinstance(results, list):
        return results
    for output in results:
        # Handle RequestOutput-style
        outputs = getattr(output, "outputs", None)
        if outputs:
            for completion in outputs:
                text = getattr(completion, "text", None)
                if isinstance(text, str):
                    cleaned = shield.sanitize_output(text)
                    completion.text = cleaned.cleaned_text
    return results


def detect_vllm(client: Any) -> bool:
    """Check if client is a vLLM LLM instance."""
    module = type(client).__module__ or ""
    return "vllm" in module
