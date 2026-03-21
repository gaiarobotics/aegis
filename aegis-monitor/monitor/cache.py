"""Response cache for AEGIS monitor.

Stores pre-serialized JSON bytes keyed by string.  Invalidation is
explicit and mutation-driven (no TTL).

The ``CacheBackend`` protocol uses async methods so a Redis backend
(``redis.asyncio``) can be dropped in without wrapping call sites.
The ``InMemoryCache`` implementation awaits trivially.
"""

from __future__ import annotations

from typing import Protocol


class CacheBackend(Protocol):
    """Async cache interface — swap InMemoryCache for RedisCache later."""

    async def get(self, key: str) -> bytes | None: ...
    async def set(self, key: str, data: bytes) -> None: ...
    async def invalidate(self, key: str) -> None: ...
    async def invalidate_all(self) -> None: ...


class InMemoryCache:
    """In-process cache storing pre-serialized response bytes."""

    def __init__(self) -> None:
        self._data: dict[str, bytes] = {}

    async def get(self, key: str) -> bytes | None:
        return self._data.get(key)

    async def set(self, key: str, data: bytes) -> None:
        self._data[key] = data

    async def invalidate(self, key: str) -> None:
        self._data.pop(key, None)

    async def invalidate_all(self) -> None:
        self._data.clear()
