"""Speaker/agent classifier for automatic trust management.

Extracts agent identities from LLM message arrays using a tiered approach:

Tier 0 — Structured metadata (zero deps, ~100% on frameworks):
    Looks for ``name``, ``source``, ``agent``, ``sender`` fields that
    frameworks like AutoGen, CrewAI, LangGraph, Slack, and Discord
    always include in their message dicts.

Tier 1 — Regex patterns (stdlib ``re``, 90-95% on chat-formatted text):
    Matches ``@AgentName``, ``AgentName:`` prefixes, ``[Agent: Name]``
    brackets, and quoted-speech attribution patterns common in
    multi-agent conversations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SpeakerInfo:
    """Identified speaker from a message."""

    agent_id: str
    confidence: float  # 0.0–1.0
    tier: int  # 0 = metadata, 1 = regex
    source_field: str = ""  # which field/pattern matched


@dataclass
class ExtractionResult:
    """Result of speaker extraction across a message list."""

    speakers: list[SpeakerInfo] = field(default_factory=list)

    @property
    def agent_ids(self) -> list[str]:
        """Unique agent IDs ordered by first appearance."""
        seen: set[str] = set()
        ids: list[str] = []
        for s in self.speakers:
            if s.agent_id not in seen:
                seen.add(s.agent_id)
                ids.append(s.agent_id)
        return ids

    @property
    def primary_speaker(self) -> str | None:
        """Highest-confidence speaker, or None."""
        if not self.speakers:
            return None
        return max(self.speakers, key=lambda s: s.confidence).agent_id


# ---------------------------------------------------------------------------
# Tier 0: Structured metadata extraction
# ---------------------------------------------------------------------------

# Fields checked in priority order.  First non-empty string wins.
_METADATA_FIELDS = ("name", "source", "agent", "sender", "from", "author")


def _extract_metadata(msg: dict[str, Any]) -> SpeakerInfo | None:
    """Extract speaker from structured metadata fields."""
    for fld in _METADATA_FIELDS:
        val = msg.get(fld)
        if isinstance(val, str) and val.strip():
            return SpeakerInfo(
                agent_id=val.strip(),
                confidence=1.0,
                tier=0,
                source_field=fld,
            )
    return None


# ---------------------------------------------------------------------------
# Tier 1: Regex pattern extraction
# ---------------------------------------------------------------------------

# @AgentName — common in Slack, Discord, and multi-agent frameworks
_RE_AT_MENTION = re.compile(r"@(\w[\w\-\.]{0,63})")

# AgentName: message — classic chat transcript prefix
_RE_NAME_PREFIX = re.compile(r"^([A-Z][\w\-\.]{0,63}):\s", re.MULTILINE)

# [Agent: Name] or [From: Name] — bracket-delimited speaker tags
_RE_BRACKET_AGENT = re.compile(
    r"\[(?:Agent|From|Speaker|Sender):\s*([^\]]+)\]", re.IGNORECASE
)

# "..." said AgentName / AgentName said "..."
_RE_SAID_ATTRIBUTION = re.compile(
    r'(?:(?:^|\s)(\w[\w\-\.]{0,63})\s+(?:said|says|wrote|asked|replied|responded)'
    r'|(?:said|says|wrote|asked|replied|responded)\s+(\w[\w\-\.]{0,63}))',
    re.IGNORECASE,
)

# Ordered from highest to lowest confidence
_TIER1_PATTERNS: list[tuple[re.Pattern, float]] = [
    (_RE_BRACKET_AGENT, 0.9),
    (_RE_NAME_PREFIX, 0.85),
    (_RE_AT_MENTION, 0.8),
    (_RE_SAID_ATTRIBUTION, 0.7),
]


def _extract_regex(text: str) -> list[SpeakerInfo]:
    """Extract speakers using regex patterns (Tier 1)."""
    results: list[SpeakerInfo] = []
    seen: set[str] = set()

    for pattern, confidence in _TIER1_PATTERNS:
        for match in pattern.finditer(text):
            # Some patterns have multiple capture groups
            name = None
            for group in match.groups():
                if group and group.strip():
                    name = group.strip()
                    break
            if name and name not in seen:
                seen.add(name)
                results.append(SpeakerInfo(
                    agent_id=name,
                    confidence=confidence,
                    tier=1,
                    source_field=pattern.pattern[:30],
                ))

    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_speakers(messages: list[dict[str, Any]]) -> ExtractionResult:
    """Extract agent identities from a list of message dicts.

    Processes each message through Tier 0 (metadata) first, then falls
    back to Tier 1 (regex) on the text content for any messages where
    metadata yielded nothing.

    Args:
        messages: List of message dicts (any provider format).

    Returns:
        ExtractionResult with all discovered speakers.
    """
    result = ExtractionResult()

    for msg in messages:
        # Tier 0: structured metadata
        meta_speaker = _extract_metadata(msg)
        if meta_speaker is not None:
            result.speakers.append(meta_speaker)
            continue

        # Tier 1: regex on text content
        content = msg.get("content", "")
        if isinstance(content, str) and content:
            regex_speakers = _extract_regex(content)
            result.speakers.extend(regex_speakers)
        elif isinstance(content, list):
            # Anthropic-style content block list
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = block.get("text", "")
                    if text:
                        regex_speakers = _extract_regex(text)
                        result.speakers.extend(regex_speakers)

    return result
