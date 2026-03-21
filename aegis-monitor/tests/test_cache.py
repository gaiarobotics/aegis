"""Tests for the response cache."""

import pytest

from monitor.cache import InMemoryCache


@pytest.mark.asyncio
class TestInMemoryCache:
    async def test_get_returns_none_on_miss(self):
        cache = InMemoryCache()
        assert await cache.get("nonexistent") is None

    async def test_set_then_get(self):
        cache = InMemoryCache()
        await cache.set("key", b'{"data": 1}')
        result = await cache.get("key")
        assert result == b'{"data": 1}'

    async def test_invalidate_clears_key(self):
        cache = InMemoryCache()
        await cache.set("key", b"data")
        await cache.invalidate("key")
        assert await cache.get("key") is None

    async def test_invalidate_nonexistent_key_is_noop(self):
        cache = InMemoryCache()
        await cache.invalidate("nonexistent")  # should not raise

    async def test_invalidate_all(self):
        cache = InMemoryCache()
        await cache.set("a", b"1")
        await cache.set("b", b"2")
        await cache.invalidate_all()
        assert await cache.get("a") is None
        assert await cache.get("b") is None

    async def test_set_overwrites_previous(self):
        cache = InMemoryCache()
        await cache.set("key", b"old")
        await cache.set("key", b"new")
        assert await cache.get("key") == b"new"

    async def test_invalidate_then_set_works(self):
        cache = InMemoryCache()
        await cache.set("key", b"v1")
        await cache.invalidate("key")
        await cache.set("key", b"v2")
        assert await cache.get("key") == b"v2"
