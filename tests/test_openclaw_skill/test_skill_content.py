"""Tests for SKILL.md format and content validation."""

from __future__ import annotations

from pathlib import Path

import pytest

SKILL_PATH = Path("/workspace/aegis-openclaw/SKILL.md")


class TestSkillFormat:
    def test_skill_file_exists(self):
        assert SKILL_PATH.exists()

    def test_has_yaml_frontmatter(self):
        content = SKILL_PATH.read_text()
        assert content.startswith("---\n")
        # Should have closing frontmatter delimiter
        parts = content.split("---\n", 2)
        assert len(parts) >= 3, "Expected YAML frontmatter delimited by ---"

    def test_frontmatter_has_required_fields(self):
        content = SKILL_PATH.read_text()
        frontmatter = content.split("---\n", 2)[1]
        assert "name:" in frontmatter
        assert "aegis-security" in frontmatter
        assert "bins:" in frontmatter
        assert "python3" in frontmatter
        assert "env:" in frontmatter

    def test_has_security_commands(self):
        content = SKILL_PATH.read_text()
        assert "aegis-scan" in content
        assert "aegis-sanitize" in content
        assert "aegis-audit" in content
        assert "aegis-status" in content
        assert "aegis-evaluate" in content

    def test_has_threat_categories(self):
        content = SKILL_PATH.read_text()
        assert "Prompt Injection" in content
        assert "Authority Spoofing" in content
        assert "Behavioral Drift" in content

    def test_has_response_protocol(self):
        content = SKILL_PATH.read_text()
        assert "Response Protocol" in content
        assert "Do not execute" in content

    def test_reasonable_token_count(self):
        """Skill content should be under ~800 tokens (roughly 4 chars/token)."""
        content = SKILL_PATH.read_text()
        # Rough estimate: ~4 chars per token
        estimated_tokens = len(content) / 4
        assert estimated_tokens < 2000, f"SKILL.md is ~{estimated_tokens:.0f} tokens, expected < 2000"
