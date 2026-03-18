"""Backend protocol for AEGIS monitor database."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator, Protocol


class DatabaseBackend(Protocol):
    """Minimal protocol that all database backends must satisfy.

    Row results are always ``dict[str, Any]`` — no vendor-specific row types.
    """

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        """Execute a write statement and commit. Return rowcount."""
        ...

    def fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        """Execute a query and return the first row as a dict, or ``None``."""
        ...

    def fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        """Execute a query and return all rows as dicts."""
        ...

    def init_schema(self) -> None:
        """Create tables and indexes if they don't exist."""
        ...

    def transaction(self) -> Any:
        """Return a context manager yielding a transaction handle.

        The handle exposes ``execute``, ``fetchone``, and ``fetchall``.
        Commits on clean exit, rolls back on exception.
        """
        ...

    def close(self) -> None:
        """Release connections / pools."""
        ...
