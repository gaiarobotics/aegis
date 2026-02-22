"""Request handlers for chat completions, messages, and streaming."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from aegis.shield import InferenceBlockedError, Shield, ThreatBlockedError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_user_text_openai(messages: list[dict]) -> str:
    """Extract concatenated user text from OpenAI-format messages."""
    parts: list[str] = []
    for msg in messages:
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
    return "\n".join(parts)


def _extract_user_text_anthropic(messages: list[dict]) -> str:
    """Extract concatenated user text from Anthropic-format messages."""
    parts: list[str] = []
    for msg in messages:
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
    return "\n".join(parts)


def _extract_response_text_openai(data: dict) -> str:
    """Extract assistant text from an OpenAI response dict."""
    parts: list[str] = []
    for choice in data.get("choices", []):
        msg = choice.get("message", {})
        if isinstance(msg, dict):
            text = msg.get("content", "")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(parts)


def _extract_response_text_anthropic(data: dict) -> str:
    """Extract assistant text from an Anthropic response dict."""
    parts: list[str] = []
    for block in data.get("content", []):
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(block.get("text", ""))
    return "\n".join(parts)


def _threat_error_response(score: float) -> dict:
    """Build an OpenAI-compatible error body for a blocked threat."""
    return {
        "error": {
            "message": f"AEGIS: threat detected (score={score:.2f})",
            "type": "aegis_threat_blocked",
            "code": "threat_detected",
        }
    }


def _forward_request(
    url: str,
    body: bytes,
    api_key: str,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict]:
    """Forward a JSON request to the upstream provider and return (status, parsed_json)."""
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    if extra_headers:
        headers.update(extra_headers)

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return exc.code, {"error": {"message": raw.decode(errors="replace"), "type": "upstream_error", "code": "upstream_error"}}
    except urllib.error.URLError as exc:
        return 502, {"error": {"message": f"Upstream connection failed: {exc.reason}", "type": "upstream_error", "code": "connection_failed"}}


def _forward_streaming_request(
    url: str,
    body: bytes,
    api_key: str,
) -> tuple[int, list[bytes], str]:
    """Forward a streaming request, accumulate all SSE chunks.

    Returns (status, list_of_raw_chunks, concatenated_text).
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    chunks: list[bytes] = []
    text_parts: list[str] = []

    try:
        with urllib.request.urlopen(req) as resp:
            status = resp.status
            for line in resp:
                chunks.append(line)
                # Parse SSE data lines for text content
                decoded = line.decode(errors="replace").strip()
                if decoded.startswith("data: ") and decoded != "data: [DONE]":
                    try:
                        chunk_data = json.loads(decoded[6:])
                        for choice in chunk_data.get("choices", []):
                            delta = choice.get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                text_parts.append(content)
                    except (json.JSONDecodeError, ValueError):
                        pass
            return status, chunks, "".join(text_parts)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, [raw], ""
    except urllib.error.URLError as exc:
        msg = f"Upstream connection failed: {exc.reason}"
        return 502, [msg.encode()], ""


# ---------------------------------------------------------------------------
# Main handlers
# ---------------------------------------------------------------------------


def handle_chat_completions(
    body: dict,
    shield: Shield,
    upstream_url: str,
    upstream_key: str,
) -> tuple[int, dict]:
    """Handle an OpenAI-format /v1/chat/completions request.

    Returns (http_status, response_dict).
    """
    # 0. Check remote killswitch
    shield.check_killswitch()

    messages = body.get("messages", [])
    is_streaming = body.get("stream", False)

    # 1. Extract user text and scan input
    user_text = _extract_user_text_openai(messages)
    if user_text:
        scan = shield.scan_input(user_text)
        if scan.is_threat and shield.mode == "enforce":
            return 400, _threat_error_response(scan.threat_score)

    # 2. Wrap messages with provenance tags
    body["messages"] = shield.wrap_messages(messages)

    # 3. Forward to upstream
    endpoint = upstream_url.rstrip("/") + "/chat/completions"
    encoded = json.dumps(body).encode()

    if is_streaming:
        return _handle_streaming_completions(endpoint, encoded, upstream_key, shield)

    status, response = _forward_request(endpoint, encoded, upstream_key)
    if status >= 400:
        return status, response

    # 4. Sanitize output
    response = _sanitize_openai_dict(shield, response)

    # 5. Record response behavior
    try:
        shield.record_response_behavior(response=response, provider="openai")
    except Exception:
        logger.debug("Behavior recording failed", exc_info=True)

    return status, response


def _handle_streaming_completions(
    endpoint: str,
    encoded_body: bytes,
    upstream_key: str,
    shield: Shield,
) -> tuple[int, dict]:
    """Handle a streaming chat completions request.

    Accumulates all chunks, scans the complete text, then returns the
    full response as a non-streaming response (accumulate-then-replay).
    """
    status, chunks, full_text = _forward_streaming_request(endpoint, encoded_body, upstream_key)

    if status >= 400:
        # Return error as-is
        try:
            error_data = json.loads(b"".join(chunks))
        except (json.JSONDecodeError, ValueError):
            error_data = {"error": {"message": "Upstream streaming error", "type": "upstream_error", "code": "streaming_error"}}
        return status, error_data

    # Sanitize the accumulated text
    sanitized = shield.sanitize_output(full_text)

    # Record behavior
    synth_response = {
        "choices": [{"message": {"role": "assistant", "content": sanitized.cleaned_text}}],
    }
    try:
        shield.record_response_behavior(response=synth_response, provider="openai")
    except Exception:
        logger.debug("Behavior recording failed", exc_info=True)

    return 200, synth_response


def handle_messages(
    body: dict,
    shield: Shield,
    upstream_url: str,
    upstream_key: str,
) -> tuple[int, dict]:
    """Handle an Anthropic-format /v1/messages request.

    Returns (http_status, response_dict).
    """
    # 0. Check remote killswitch
    shield.check_killswitch()

    messages = body.get("messages", [])

    # 1. Extract user text and scan input
    user_text = _extract_user_text_anthropic(messages)
    if user_text:
        scan = shield.scan_input(user_text)
        if scan.is_threat and shield.mode == "enforce":
            return 400, _threat_error_response(scan.threat_score)

    # 2. Wrap messages with provenance tags
    body["messages"] = shield.wrap_messages(messages)

    # 3. Forward to upstream
    endpoint = upstream_url.rstrip("/") + "/messages"
    api_key = upstream_key

    # Anthropic uses x-api-key header instead of Bearer token
    headers_extra = {}
    if api_key:
        headers_extra["x-api-key"] = api_key
        headers_extra["anthropic-version"] = "2023-06-01"

    encoded = json.dumps(body).encode()
    req = urllib.request.Request(
        endpoint,
        data=encoded,
        headers={"Content-Type": "application/json", **headers_extra},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            status = resp.status
            response = json.loads(raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return exc.code, {"error": {"message": raw.decode(errors="replace"), "type": "upstream_error", "code": "upstream_error"}}
    except urllib.error.URLError as exc:
        return 502, {"error": {"message": f"Upstream connection failed: {exc.reason}", "type": "upstream_error", "code": "connection_failed"}}

    # 4. Sanitize output
    response = _sanitize_anthropic_dict(shield, response)

    # 5. Record response behavior
    try:
        shield.record_response_behavior(response=response, provider="anthropic")
    except Exception:
        logger.debug("Behavior recording failed", exc_info=True)

    return status, response


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------


def _sanitize_openai_dict(shield: Shield, response: dict) -> dict:
    """Sanitize content in an OpenAI-format response dict."""
    for choice in response.get("choices", []):
        msg = choice.get("message", {})
        if isinstance(msg, dict) and "content" in msg:
            text = msg["content"]
            if isinstance(text, str):
                cleaned = shield.sanitize_output(text)
                msg["content"] = cleaned.cleaned_text
    return response


def _sanitize_anthropic_dict(shield: Shield, response: dict) -> dict:
    """Sanitize content in an Anthropic-format response dict."""
    content = response.get("content", [])
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text", "")
                if isinstance(text, str):
                    cleaned = shield.sanitize_output(text)
                    block["text"] = cleaned.cleaned_text
    return response
