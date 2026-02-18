"""Tests for broker capability manifests."""

import pytest

from aegis.broker.actions import ActionRequest
from aegis.broker.manifests import ManifestRegistry, ToolManifest


class TestToolManifest:
    def test_construction(self):
        m = ToolManifest(
            name="web_search",
            allowed_actions=["http_write"],
            allowed_domains=["google.com"],
            allowed_paths=[],
            read_write="read",
        )
        assert m.name == "web_search"
        assert m.allowed_actions == ["http_write"]
        assert m.allowed_domains == ["google.com"]
        assert m.allowed_paths == []
        assert m.read_write == "read"
        assert m.schema is None

    def test_construction_with_schema(self):
        schema = {"type": "object", "properties": {"query": {"type": "string"}}}
        m = ToolManifest(
            name="search",
            allowed_actions=["tool_call"],
            allowed_domains=[],
            allowed_paths=[],
            read_write="read",
            schema=schema,
        )
        assert m.schema == schema

    def test_both_read_write(self):
        m = ToolManifest(
            name="file_manager",
            allowed_actions=["fs_write"],
            allowed_domains=[],
            allowed_paths=["/tmp"],
            read_write="both",
        )
        assert m.read_write == "both"


class TestManifestRegistry:
    def test_register_and_get(self):
        registry = ManifestRegistry()
        m = ToolManifest(
            name="web_search",
            allowed_actions=["http_write"],
            allowed_domains=["google.com"],
            allowed_paths=[],
            read_write="read",
        )
        registry.register(m)
        assert registry.get("web_search") is m

    def test_get_unknown_returns_none(self):
        registry = ManifestRegistry()
        assert registry.get("nonexistent") is None

    def test_register_duplicate_raises(self):
        registry = ManifestRegistry()
        m1 = ToolManifest(
            name="tool_a",
            allowed_actions=["tool_call"],
            allowed_domains=[],
            allowed_paths=[],
            read_write="read",
        )
        m2 = ToolManifest(
            name="tool_a",
            allowed_actions=["tool_call", "http_write"],
            allowed_domains=["example.com"],
            allowed_paths=[],
            read_write="both",
        )
        registry.register(m1)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(m2)
        # Original manifest unchanged
        assert registry.get("tool_a") is m1

    def test_register_overwrite_flag(self):
        registry = ManifestRegistry()
        m1 = ToolManifest(
            name="tool_a",
            allowed_actions=["tool_call"],
            allowed_domains=[],
            allowed_paths=[],
            read_write="read",
        )
        m2 = ToolManifest(
            name="tool_a",
            allowed_actions=["tool_call", "http_write"],
            allowed_domains=["example.com"],
            allowed_paths=[],
            read_write="both",
        )
        registry.register(m1)
        registry.register(m2, overwrite=True)
        assert registry.get("tool_a") is m2

    def test_check_action_allowed(self):
        registry = ManifestRegistry()
        m = ToolManifest(
            name="web_search",
            allowed_actions=["http_write"],
            allowed_domains=["google.com"],
            allowed_paths=[],
            read_write="both",
        )
        req = ActionRequest(
            id="1",
            timestamp=1000.0,
            source_provenance="trusted.system",
            action_type="http_write",
            read_write="write",
            target="google.com",
            args={},
            risk_hints={},
        )
        assert registry.check_action(req, m) is True

    def test_check_action_denied_wrong_action_type(self):
        registry = ManifestRegistry()
        m = ToolManifest(
            name="web_search",
            allowed_actions=["http_write"],
            allowed_domains=["google.com"],
            allowed_paths=[],
            read_write="both",
        )
        req = ActionRequest(
            id="1",
            timestamp=1000.0,
            source_provenance="trusted.system",
            action_type="fs_write",
            read_write="write",
            target="google.com",
            args={},
            risk_hints={},
        )
        assert registry.check_action(req, m) is False

    def test_check_action_denied_wrong_domain(self):
        registry = ManifestRegistry()
        m = ToolManifest(
            name="web_search",
            allowed_actions=["http_write"],
            allowed_domains=["google.com"],
            allowed_paths=[],
            read_write="both",
        )
        req = ActionRequest(
            id="1",
            timestamp=1000.0,
            source_provenance="trusted.system",
            action_type="http_write",
            read_write="write",
            target="evil.com",
            args={},
            risk_hints={},
        )
        assert registry.check_action(req, m) is False

    def test_check_action_denied_write_not_declared(self):
        """Default deny for write if manifest only declares read."""
        registry = ManifestRegistry()
        m = ToolManifest(
            name="reader",
            allowed_actions=["http_write"],
            allowed_domains=["google.com"],
            allowed_paths=[],
            read_write="read",
        )
        req = ActionRequest(
            id="1",
            timestamp=1000.0,
            source_provenance="trusted.system",
            action_type="http_write",
            read_write="write",
            target="google.com",
            args={},
            risk_hints={},
        )
        assert registry.check_action(req, m) is False

    def test_check_action_read_allowed_on_read_manifest(self):
        registry = ManifestRegistry()
        m = ToolManifest(
            name="reader",
            allowed_actions=["http_write"],
            allowed_domains=["google.com"],
            allowed_paths=[],
            read_write="read",
        )
        req = ActionRequest(
            id="1",
            timestamp=1000.0,
            source_provenance="trusted.system",
            action_type="http_write",
            read_write="read",
            target="google.com",
            args={},
            risk_hints={},
        )
        assert registry.check_action(req, m) is True

    def test_check_action_path_matching(self):
        registry = ManifestRegistry()
        m = ToolManifest(
            name="file_tool",
            allowed_actions=["fs_write"],
            allowed_domains=[],
            allowed_paths=["/tmp", "/var/data"],
            read_write="both",
        )
        req = ActionRequest(
            id="1",
            timestamp=1000.0,
            source_provenance="trusted.system",
            action_type="fs_write",
            read_write="write",
            target="/tmp/output.txt",
            args={},
            risk_hints={},
        )
        assert registry.check_action(req, m) is True

    def test_check_action_path_denied(self):
        registry = ManifestRegistry()
        m = ToolManifest(
            name="file_tool",
            allowed_actions=["fs_write"],
            allowed_domains=[],
            allowed_paths=["/tmp"],
            read_write="both",
        )
        req = ActionRequest(
            id="1",
            timestamp=1000.0,
            source_provenance="trusted.system",
            action_type="fs_write",
            read_write="write",
            target="/etc/passwd",
            args={},
            risk_hints={},
        )
        assert registry.check_action(req, m) is False

    def test_check_action_no_domains_or_paths_allows_any_target(self):
        """If both domains and paths are empty, target is not checked."""
        registry = ManifestRegistry()
        m = ToolManifest(
            name="generic_tool",
            allowed_actions=["tool_call"],
            allowed_domains=[],
            allowed_paths=[],
            read_write="both",
        )
        req = ActionRequest(
            id="1",
            timestamp=1000.0,
            source_provenance="trusted.system",
            action_type="tool_call",
            read_write="write",
            target="anything",
            args={},
            risk_hints={},
        )
        assert registry.check_action(req, m) is True

    def test_path_prefix_does_not_match_evil_sibling(self):
        """'/data/uploads' must not match '/data/uploads-evil'."""
        registry = ManifestRegistry()
        m = ToolManifest(
            name="file_tool",
            allowed_actions=["fs_write"],
            allowed_domains=[],
            allowed_paths=["/data/uploads"],
            read_write="both",
        )
        evil_req = ActionRequest(
            id="1",
            timestamp=1000.0,
            source_provenance="trusted.system",
            action_type="fs_write",
            read_write="write",
            target="/data/uploads-evil/payload.txt",
            args={},
            risk_hints={},
        )
        assert registry.check_action(evil_req, m) is False

    def test_path_exact_match_allowed(self):
        """Exact path match (target == allowed path) should be allowed."""
        registry = ManifestRegistry()
        m = ToolManifest(
            name="file_tool",
            allowed_actions=["fs_write"],
            allowed_domains=[],
            allowed_paths=["/data/uploads"],
            read_write="both",
        )
        req = ActionRequest(
            id="1",
            timestamp=1000.0,
            source_provenance="trusted.system",
            action_type="fs_write",
            read_write="write",
            target="/data/uploads",
            args={},
            risk_hints={},
        )
        assert registry.check_action(req, m) is True

    def test_path_normpath_trailing_slash(self):
        """Paths with trailing slashes should be normalised correctly."""
        registry = ManifestRegistry()
        m = ToolManifest(
            name="file_tool",
            allowed_actions=["fs_write"],
            allowed_domains=[],
            allowed_paths=["/data/uploads/"],
            read_write="both",
        )
        req = ActionRequest(
            id="1",
            timestamp=1000.0,
            source_provenance="trusted.system",
            action_type="fs_write",
            read_write="write",
            target="/data/uploads/file.txt",
            args={},
            risk_hints={},
        )
        assert registry.check_action(req, m) is True

    def test_domain_check_parses_url(self):
        """Domain check should extract hostname from a full URL target."""
        registry = ManifestRegistry()
        m = ToolManifest(
            name="web_tool",
            allowed_actions=["http_write"],
            allowed_domains=["google.com"],
            allowed_paths=[],
            read_write="both",
        )
        req = ActionRequest(
            id="1",
            timestamp=1000.0,
            source_provenance="trusted.system",
            action_type="http_write",
            read_write="write",
            target="https://google.com/api/v1/data",
            args={},
            risk_hints={},
        )
        assert registry.check_action(req, m) is True

    def test_domain_check_url_subdomain(self):
        """Subdomain of allowed domain in a URL should be accepted."""
        registry = ManifestRegistry()
        m = ToolManifest(
            name="web_tool",
            allowed_actions=["http_write"],
            allowed_domains=["google.com"],
            allowed_paths=[],
            read_write="both",
        )
        req = ActionRequest(
            id="1",
            timestamp=1000.0,
            source_provenance="trusted.system",
            action_type="http_write",
            read_write="write",
            target="https://api.google.com/endpoint",
            args={},
            risk_hints={},
        )
        assert registry.check_action(req, m) is True

    def test_domain_check_url_wrong_domain_denied(self):
        """URL with wrong domain should be denied."""
        registry = ManifestRegistry()
        m = ToolManifest(
            name="web_tool",
            allowed_actions=["http_write"],
            allowed_domains=["google.com"],
            allowed_paths=[],
            read_write="both",
        )
        req = ActionRequest(
            id="1",
            timestamp=1000.0,
            source_provenance="trusted.system",
            action_type="http_write",
            read_write="write",
            target="https://evil.com/google.com",
            args={},
            risk_hints={},
        )
        assert registry.check_action(req, m) is False
