"""Local JSONL telemetry with automatic redaction."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

# Patterns that should be redacted
_REDACT_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9\-]{10,}"),  # Anthropic API keys (with hyphens)
    re.compile(r"key-[A-Za-z0-9]{10,}"),
    re.compile(r"Bearer\s+[^\s]+"),  # Bearer tokens
    re.compile(r"\b[A-Za-z0-9+/]{64,}={0,2}\b"),  # long base64
]


def redact(text: str) -> str:
    """Replace API keys and long base64 strings with [REDACTED]."""
    for pattern in _REDACT_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def _redact_value(value: Any) -> Any:
    """Recursively redact string values in nested structures."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    return value


class TelemetryLogger:
    """Writes structured events to a local JSONL file."""

    def __init__(self, log_path: str = ".aegis/telemetry.jsonl"):
        self._log_path = Path(log_path)

    def log_event(self, event_type: str, **data: Any) -> None:
        """Log a telemetry event."""
        event = {
            "timestamp": time.time(),
            "event_type": event_type,
            "data": _redact_value(data),
        }

        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
