"""Tests for AEGIS Anthropic provider wrapper."""

from aegis.providers.anthropic import AnthropicWrapper, detect_anthropic
from aegis.providers.base import WrappedClient
from aegis.shield import Shield


class MockAnthropicClient:
    """Mock Anthropic client."""

    class messages:
        @staticmethod
        def create(**kwargs):
            return {"content": [{"type": "text", "text": "Response"}]}


class MockOtherClient:
    """Mock non-Anthropic client."""
    pass


class TestAnthropicWrapper:
    def test_wrap_returns_wrapped_client(self):
        shield = Shield(modules=["scanner"])
        wrapper = AnthropicWrapper(shield=shield)
        client = MockAnthropicClient()
        wrapped = wrapper.wrap(client)
        assert isinstance(wrapped, WrappedClient)
        assert wrapped.original is client

    def test_wrapped_client_has_messages(self):
        shield = Shield(modules=["scanner"])
        wrapper = AnthropicWrapper(shield=shield)
        client = MockAnthropicClient()
        wrapped = wrapper.wrap(client)
        # Should delegate to original client's messages
        assert hasattr(wrapped, "messages")


class TestDetectAnthropic:
    def test_detect_anthropic_by_name(self):
        # Class with "Anthropic" in name
        class Anthropic:
            pass
        assert detect_anthropic(Anthropic()) is True

    def test_detect_non_anthropic(self):
        assert detect_anthropic(MockOtherClient()) is False
