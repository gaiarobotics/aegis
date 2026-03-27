"""Tests for async Anthropic provider wrapper."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from aegis.providers.anthropic import AnthropicWrapper
from aegis.shield import Shield


class _FakeAsyncMessages:
    """Mock async messages resource."""

    def __init__(self):
        self.create = AsyncMock(return_value={
            "content": [{"type": "text", "text": "Hello!"}],
            "role": "assistant",
        })


class _FakeAsyncAnthropic:
    """Mock AsyncAnthropic client."""

    __name__ = "AsyncAnthropic"
    __module__ = "anthropic"

    def __init__(self):
        self.messages = _FakeAsyncMessages()


class _FakeMessages:
    """Mock sync messages resource."""

    def __init__(self):
        self.create = MagicMock(return_value={
            "content": [{"type": "text", "text": "Hello!"}],
            "role": "assistant",
        })


class _FakeAnthropic:
    """Mock sync Anthropic client."""

    __name__ = "Anthropic"
    __module__ = "anthropic"

    def __init__(self):
        self.messages = _FakeMessages()


class TestAsyncAnthropicDetection:
    def test_sync_client_uses_sync_intercept(self):
        """Sync Anthropic client gets sync intercept_create."""
        shield = Shield()
        wrapper = AnthropicWrapper(shield=shield)
        client = _FakeAnthropic()
        wrapped = wrapper.wrap(client)
        # The intercept should be a regular function, not a coroutine
        import asyncio
        messages_proxy = getattr(wrapped, "messages")
        create_fn = getattr(messages_proxy, "create")
        assert not asyncio.iscoroutinefunction(create_fn)
        shield.close()

    def test_async_client_uses_async_intercept(self):
        """AsyncAnthropic client gets async intercept_create."""
        shield = Shield()
        wrapper = AnthropicWrapper(shield=shield)
        client = _FakeAsyncAnthropic()
        wrapped = wrapper.wrap(client)
        import asyncio
        messages_proxy = getattr(wrapped, "messages")
        create_fn = getattr(messages_proxy, "create")
        assert asyncio.iscoroutinefunction(create_fn)
        shield.close()


@pytest.mark.asyncio
class TestAsyncAnthropicIntercept:
    async def test_async_intercept_calls_scan_and_returns(self):
        """Async intercept scans input and returns response."""
        shield = Shield()
        wrapper = AnthropicWrapper(shield=shield)
        client = _FakeAsyncAnthropic()
        wrapped = wrapper.wrap(client)

        messages_proxy = getattr(wrapped, "messages")
        create_fn = getattr(messages_proxy, "create")

        response = await create_fn(
            model="claude-3-haiku",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert response is not None
        # The mock should have been called
        assert client.messages.create.called
        shield.close()

    async def test_async_intercept_wraps_messages(self):
        """Async intercept wraps messages with provenance."""
        shield = Shield()
        wrapper = AnthropicWrapper(shield=shield)
        client = _FakeAsyncAnthropic()
        wrapped = wrapper.wrap(client)

        messages_proxy = getattr(wrapped, "messages")
        create_fn = getattr(messages_proxy, "create")

        await create_fn(
            model="claude-3-haiku",
            messages=[{"role": "user", "content": "Test message"}],
        )
        # Verify create was called with wrapped messages
        call_kwargs = client.messages.create.call_args[1]
        assert "messages" in call_kwargs
        shield.close()
