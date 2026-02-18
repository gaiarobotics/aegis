"""Tests for AEGIS speaker/agent classifier."""

import pytest

from aegis.identity.speaker import (
    ExtractionResult,
    SpeakerInfo,
    _extract_metadata,
    _extract_regex,
    extract_speakers,
)


class TestTier0Metadata:
    """Tier 0: Structured metadata extraction."""

    def test_name_field(self):
        msg = {"role": "user", "name": "Alice", "content": "Hello"}
        info = _extract_metadata(msg)
        assert info is not None
        assert info.agent_id == "Alice"
        assert info.confidence == 1.0
        assert info.tier == 0
        assert info.source_field == "name"

    def test_source_field(self):
        """AutoGen uses 'source' for agent identity."""
        msg = {"role": "user", "source": "ResearchBot", "content": "data"}
        info = _extract_metadata(msg)
        assert info.agent_id == "ResearchBot"
        assert info.source_field == "source"

    def test_agent_field(self):
        """CrewAI uses 'agent' for agent identity."""
        msg = {"role": "assistant", "agent": "AnalystAgent", "content": "ok"}
        info = _extract_metadata(msg)
        assert info.agent_id == "AnalystAgent"
        assert info.source_field == "agent"

    def test_sender_field(self):
        """Slack/Discord-style 'sender'."""
        msg = {"role": "user", "sender": "bot-42", "content": "hi"}
        info = _extract_metadata(msg)
        assert info.agent_id == "bot-42"

    def test_from_field(self):
        msg = {"role": "user", "from": "external-service", "content": "data"}
        info = _extract_metadata(msg)
        assert info.agent_id == "external-service"

    def test_author_field(self):
        msg = {"role": "user", "author": "CodeReviewer", "content": "looks good"}
        info = _extract_metadata(msg)
        assert info.agent_id == "CodeReviewer"

    def test_priority_order(self):
        """'name' takes priority over 'source'."""
        msg = {"role": "user", "name": "Alice", "source": "Bob", "content": "hi"}
        info = _extract_metadata(msg)
        assert info.agent_id == "Alice"

    def test_empty_name_skipped(self):
        """Empty strings are skipped."""
        msg = {"role": "user", "name": "", "source": "FallbackBot", "content": "hi"}
        info = _extract_metadata(msg)
        assert info.agent_id == "FallbackBot"

    def test_whitespace_only_skipped(self):
        msg = {"role": "user", "name": "   ", "source": "Real", "content": "hi"}
        info = _extract_metadata(msg)
        assert info.agent_id == "Real"

    def test_no_metadata_returns_none(self):
        msg = {"role": "user", "content": "Hello"}
        assert _extract_metadata(msg) is None

    def test_non_string_metadata_skipped(self):
        msg = {"role": "user", "name": 42, "content": "Hello"}
        assert _extract_metadata(msg) is None


class TestTier1Regex:
    """Tier 1: Regex pattern extraction."""

    def test_at_mention(self):
        speakers = _extract_regex("Hey @AliceBot, can you help?")
        assert any(s.agent_id == "AliceBot" for s in speakers)

    def test_name_prefix(self):
        speakers = _extract_regex("AgentSmith: I have located the target.")
        assert any(s.agent_id == "AgentSmith" for s in speakers)

    def test_bracket_agent(self):
        speakers = _extract_regex("[Agent: ReviewBot] The code looks good.")
        assert any(s.agent_id == "ReviewBot" for s in speakers)

    def test_bracket_from(self):
        speakers = _extract_regex("[From: Coordinator] Please proceed.")
        assert any(s.agent_id == "Coordinator" for s in speakers)

    def test_bracket_speaker(self):
        speakers = _extract_regex("[Speaker: Narrator] Once upon a time...")
        assert any(s.agent_id == "Narrator" for s in speakers)

    def test_said_attribution(self):
        speakers = _extract_regex('Manager said "we should proceed"')
        assert any(s.agent_id == "Manager" for s in speakers)

    def test_multiple_speakers(self):
        text = "Alice: Hello\nBob: Hi there\n@Charlie are you here?"
        speakers = _extract_regex(text)
        ids = {s.agent_id for s in speakers}
        assert "Alice" in ids
        assert "Bob" in ids
        assert "Charlie" in ids

    def test_dedup(self):
        """Same speaker mentioned twice returns single entry."""
        text = "Alice: Hello\nAlice: Again"
        speakers = _extract_regex(text)
        alice_count = sum(1 for s in speakers if s.agent_id == "Alice")
        assert alice_count == 1

    def test_no_matches(self):
        speakers = _extract_regex("This is plain text with no agent markers.")
        assert speakers == []

    def test_confidence_ordering(self):
        """Bracket patterns should have higher confidence than @mentions."""
        text = "[Agent: HighConf] Also @LowConf is here"
        speakers = _extract_regex(text)
        high = next(s for s in speakers if s.agent_id == "HighConf")
        low = next(s for s in speakers if s.agent_id == "LowConf")
        assert high.confidence > low.confidence


class TestExtractSpeakers:
    """Integration: extract_speakers() across message lists."""

    def test_metadata_takes_priority(self):
        """Tier 0 metadata short-circuits Tier 1 for that message."""
        messages = [
            {"role": "user", "name": "Alice", "content": "Bob: this text mentions Bob"},
        ]
        result = extract_speakers(messages)
        # Alice from metadata, Bob should not appear since metadata matched
        assert result.primary_speaker == "Alice"
        assert "Bob" not in result.agent_ids

    def test_fallback_to_regex(self):
        """Messages without metadata fall through to Tier 1."""
        messages = [
            {"role": "user", "content": "[Agent: Coordinator] Please help."},
        ]
        result = extract_speakers(messages)
        assert "Coordinator" in result.agent_ids

    def test_mixed_messages(self):
        """Mix of metadata and regex extraction."""
        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "name": "Alice", "content": "Hello"},
            {"role": "user", "content": "@Bob are you there?"},
        ]
        result = extract_speakers(messages)
        assert "Alice" in result.agent_ids
        assert "Bob" in result.agent_ids

    def test_anthropic_content_blocks(self):
        """Handles Anthropic-style content block lists."""
        messages = [
            {"role": "user", "content": [
                {"type": "text", "text": "Alice: Can you help?"},
                {"type": "image", "source": {}},
            ]},
        ]
        result = extract_speakers(messages)
        assert "Alice" in result.agent_ids

    def test_empty_messages(self):
        result = extract_speakers([])
        assert result.agent_ids == []
        assert result.primary_speaker is None

    def test_agent_ids_unique_ordered(self):
        messages = [
            {"role": "user", "name": "Alice", "content": "hi"},
            {"role": "user", "name": "Bob", "content": "hi"},
            {"role": "user", "name": "Alice", "content": "again"},
        ]
        result = extract_speakers(messages)
        assert result.agent_ids == ["Alice", "Bob"]


class TestExtractionResult:
    def test_primary_speaker_highest_confidence(self):
        result = ExtractionResult(speakers=[
            SpeakerInfo("low", 0.5, 1),
            SpeakerInfo("high", 1.0, 0),
        ])
        assert result.primary_speaker == "high"

    def test_primary_speaker_none_when_empty(self):
        result = ExtractionResult()
        assert result.primary_speaker is None
