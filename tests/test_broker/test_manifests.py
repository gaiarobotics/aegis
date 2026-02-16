"""Tests for broker capability manifests."""

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

    def test_register_overwrites(self):
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
        registry.register(m2)
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
