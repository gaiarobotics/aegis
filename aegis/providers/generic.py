"""Generic client wrapper for AEGIS protection."""

from __future__ import annotations

from typing import Any

from aegis.providers.base import BaseWrapper, WrappedClient


class GenericWrapper(BaseWrapper):
    """Wraps any client with a ``create()`` or ``generate()`` method.

    Provides AEGIS protection for clients that don't match
    known provider patterns (Anthropic, OpenAI).
    """

    def wrap(self, client: Any, tools: list | None = None) -> WrappedClient:
        """Wrap a generic LLM client with automatic interception."""
        shield = self._shield
        intercept_map: dict[str, Any] = {}

        if hasattr(client, "create"):
            real_create = client.create

            def intercept_create(*args: Any, **kwargs: Any) -> Any:
                return _intercept_generic_call(
                    shield, real_create, args, kwargs,
                )

            intercept_map["create"] = intercept_create

        if hasattr(client, "generate"):
            real_generate = client.generate

            def intercept_generate(*args: Any, **kwargs: Any) -> Any:
                return _intercept_generic_call(
                    shield, real_generate, args, kwargs,
                )

            intercept_map["generate"] = intercept_generate

        return WrappedClient(
            client=client, shield=shield, tools=tools, intercept_map=intercept_map,
        )


def _intercept_generic_call(
    shield: Any,
    real_method: Any,
    args: tuple,
    kwargs: dict,
) -> Any:
    """Scan input, call real method, sanitize output, record trust."""
    from aegis.shield import ThreatBlockedError

    # Extract text from first positional arg or prompt kwarg
    text = ""
    if args:
        first = args[0]
        if isinstance(first, str):
            text = first
    if not text:
        text = str(kwargs.get("prompt", ""))

    # 1. Scan
    is_threat = False
    if text:
        scan = shield.scan_input(text)
        is_threat = scan.is_threat
        if is_threat and shield.mode == "enforce":
            # Try regex extraction on the raw text for trust recording
            _record_trust_for_text(shield, text, clean=False)
            raise ThreatBlockedError(scan)

    # 2. Call real method
    response = real_method(*args, **kwargs)

    # 3. Sanitize string responses
    if isinstance(response, str):
        cleaned = shield.sanitize_output(response)
        response = cleaned.cleaned_text

    # 4. Record trust from text-extracted speakers
    if text:
        _record_trust_for_text(shield, text, clean=not is_threat)

    return response


def _record_trust_for_text(shield: Any, text: str, clean: bool) -> None:
    """Extract speakers from raw text and record trust interactions."""
    try:
        from aegis.identity.speaker import _extract_regex
        speakers = _extract_regex(text)
        for speaker in speakers:
            shield.record_trust_interaction(
                speaker.agent_id, clean=clean, anomaly=not clean,
            )
    except Exception:
        pass


def detect_generic(client: Any) -> bool:
    """Check if client has create() or generate() methods."""
    return hasattr(client, "create") or hasattr(client, "generate")
