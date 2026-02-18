"""Action types for the AEGIS Broker module."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


@dataclass
class ActionRequest:
    """Represents a request to perform an action that the broker must evaluate."""

    id: str                     # UUID
    timestamp: float            # time.time()
    source_provenance: str      # "trusted.system", "social.content", etc.
    action_type: str            # "http_write", "fs_write", "tool_call", "post_message"
    read_write: str             # "read" or "write"
    target: str                 # Domain, path, tool name
    args: dict[str, Any]        # Structured arguments
    risk_hints: dict[str, Any]  # Optional metadata from scanner


class ActionDecision(str, Enum):
    """Possible decisions the broker can make about an action."""

    ALLOW = "allow"
    DENY = "deny"
    QUARANTINE = "quarantine"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class ActionResponse:
    """The broker's response to an action request."""

    request_id: str
    decision: ActionDecision
    reason: str
    policy_rule: str | None = None
