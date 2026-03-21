"""Tests for async OpenAI provider wrapper."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from aegis.providers.openai import OpenAIWrapper
from aegis.shield import Shield


class _FakeAsyncCompletions:
    """Mock async completions resource."""

    def __init__(self):
        self.create = AsyncMock(return_value={
            "choices": [{"message": {"role": "assistant", "content": "Hi!"}}],
        })


class _FakeAsyncChat:
    """Mock async chat namespace."""

    def __init__(self):
        self.completions = _FakeAsyncCompletions()


class _FakeAsyncOpenAI:
    """Mock AsyncOpenAI client."""

    __name__ = "AsyncOpenAI"
    __module__ = "openai"

    def __init__(self):
        self.chat = _FakeAsyncChat()


class _FakeCompletions:
    """Mock sync completions resource."""

    def __init__(self):
        self.create = MagicMock(return_value={
            "choices": [{"message": {"role": "assistant", "content": "Hi!"}}],
        })


class _FakeChat:
    def __init__(self):
        self.completions = _FakeCompletions()


class _FakeOpenAI:
    """Mock sync OpenAI client."""

    __name__ = "OpenAI"
    __module__ = "openai"

    def __init__(self):
        self.chat = _FakeChat()


class TestAsyncOpenAIDetection:
    def test_sync_client_uses_sync_intercept(self):
        """Sync OpenAI client gets sync intercept_create."""
        shield = Shield()
        wrapper = OpenAIWrapper(shield=shield)
        client = _FakeOpenAI()
        wrapped = wrapper.wrap(client)
        import asyncio
        chat_proxy = getattr(wrapped, "chat")
        completions_proxy = getattr(chat_proxy, "completions")
        create_fn = getattr(completions_proxy, "create")
        assert not asyncio.iscoroutinefunction(create_fn)
        shield.close()

    def test_async_client_uses_async_intercept(self):
        """AsyncOpenAI client gets async intercept_create."""
        shield = Shield()
        wrapper = OpenAIWrapper(shield=shield)
        client = _FakeAsyncOpenAI()
        wrapped = wrapper.wrap(client)
        import asyncio
        chat_proxy = getattr(wrapped, "chat")
        completions_proxy = getattr(chat_proxy, "completions")
        create_fn = getattr(completions_proxy, "create")
        assert asyncio.iscoroutinefunction(create_fn)
        shield.close()


@pytest.mark.asyncio
class TestAsyncOpenAIIntercept:
    async def test_async_intercept_calls_scan_and_returns(self):
        """Async intercept scans input and returns response."""
        shield = Shield()
        wrapper = OpenAIWrapper(shield=shield)
        client = _FakeAsyncOpenAI()
        wrapped = wrapper.wrap(client)

        chat_proxy = getattr(wrapped, "chat")
        completions_proxy = getattr(chat_proxy, "completions")
        create_fn = getattr(completions_proxy, "create")

        response = await create_fn(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert response is not None
        assert client.chat.completions.create.called
        shield.close()

    async def test_async_intercept_wraps_messages(self):
        """Async intercept wraps messages with provenance."""
        shield = Shield()
        wrapper = OpenAIWrapper(shield=shield)
        client = _FakeAsyncOpenAI()
        wrapped = wrapper.wrap(client)

        chat_proxy = getattr(wrapped, "chat")
        completions_proxy = getattr(chat_proxy, "completions")
        create_fn = getattr(completions_proxy, "create")

        await create_fn(
            model="gpt-4",
            messages=[{"role": "user", "content": "Test message"}],
        )
        call_kwargs = client.chat.completions.create.call_args[1]
        assert "messages" in call_kwargs
        shield.close()
