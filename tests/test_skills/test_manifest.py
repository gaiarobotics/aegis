"""Tests for skill manifest loading and validation."""

import json
import tempfile
from pathlib import Path

from aegis.skills.manifest import (
    SkillManifest,
    ValidationResult,
    load_manifest,
    validate_manifest,
)


class TestLoadValidManifest:
    def test_load_valid_manifest(self, tmp_path):
        """Load a well-formed manifest JSON and verify all fields."""
        manifest_data = {
            "name": "example-skill",
            "version": "1.0.0",
            "publisher": "acme-corp",
            "hashes": {
                "main.py": "abc123def456",
                "utils.py": "789ghi012jkl",
            },
            "signature": "sig-xyz-123",
            "capabilities": {
                "network": True,
                "filesystem": False,
                "tools": ["read_file", "search"],
                "read_write": "read",
            },
            "secrets": ["API_KEY"],
            "budgets": {"max_calls": 100},
            "sandbox": True,
        }
        manifest_file = tmp_path / "manifest.json"
        manifest_file.write_text(json.dumps(manifest_data))

        result = load_manifest(str(manifest_file))

        assert isinstance(result, SkillManifest)
        assert result.name == "example-skill"
        assert result.version == "1.0.0"
        assert result.publisher == "acme-corp"
        assert result.hashes == {"main.py": "abc123def456", "utils.py": "789ghi012jkl"}
        assert result.signature == "sig-xyz-123"
        assert result.capabilities["network"] is True
        assert result.capabilities["filesystem"] is False
        assert result.capabilities["tools"] == ["read_file", "search"]
        assert result.capabilities["read_write"] == "read"
        assert result.secrets == ["API_KEY"]
        assert result.budgets == {"max_calls": 100}
        assert result.sandbox is True


class TestRejectInvalidManifest:
    def test_reject_missing_name(self):
        """Manifest with empty name should fail validation."""
        manifest = SkillManifest(
            name="",
            version="1.0.0",
            publisher="acme",
            hashes={},
            signature=None,
            capabilities={
                "network": False,
                "filesystem": False,
                "tools": [],
                "read_write": "read",
            },
            secrets=[],
            budgets=None,
            sandbox=True,
        )
        result = validate_manifest(manifest)
        assert isinstance(result, ValidationResult)
        assert result.valid is False
        assert any("name" in e.lower() for e in result.errors)

    def test_reject_missing_version(self):
        """Manifest with empty version should fail validation."""
        manifest = SkillManifest(
            name="my-skill",
            version="",
            publisher="acme",
            hashes={},
            signature=None,
            capabilities={
                "network": False,
                "filesystem": False,
                "tools": [],
                "read_write": "read",
            },
            secrets=[],
            budgets=None,
            sandbox=True,
        )
        result = validate_manifest(manifest)
        assert result.valid is False
        assert any("version" in e.lower() for e in result.errors)

    def test_valid_manifest_passes(self):
        """A fully valid manifest should pass validation."""
        manifest = SkillManifest(
            name="my-skill",
            version="1.0.0",
            publisher="acme",
            hashes={"main.py": "abc123"},
            signature="sig-abc",
            capabilities={
                "network": False,
                "filesystem": False,
                "tools": [],
                "read_write": "read",
            },
            secrets=[],
            budgets=None,
            sandbox=True,
        )
        result = validate_manifest(manifest)
        assert result.valid is True
        assert result.errors == []


class TestHashVerification:
    def test_hash_verification(self, tmp_path):
        """Loaded manifest preserves file hashes for verification."""
        hashes = {
            "main.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "lib.py": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        }
        manifest_data = {
            "name": "hash-skill",
            "version": "2.0.0",
            "publisher": "test-pub",
            "hashes": hashes,
            "signature": None,
            "capabilities": {
                "network": False,
                "filesystem": False,
                "tools": [],
                "read_write": "read",
            },
            "secrets": [],
            "budgets": None,
            "sandbox": False,
        }
        manifest_file = tmp_path / "manifest.json"
        manifest_file.write_text(json.dumps(manifest_data))

        result = load_manifest(str(manifest_file))
        assert result.hashes == hashes
        assert result.hashes["main.py"] == hashes["main.py"]
        assert result.hashes["lib.py"] == hashes["lib.py"]
