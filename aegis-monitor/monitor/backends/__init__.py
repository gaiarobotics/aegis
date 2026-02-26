"""Database backend selection for AEGIS monitor."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from monitor.backends._base import DatabaseBackend


def create_backend(url: str) -> "DatabaseBackend":
    """Create the appropriate backend from a database URL.

    - File paths or ``:memory:`` → SQLite
    - ``postgresql://...`` or ``postgres://...`` → Postgres
    """
    if url.startswith(("postgresql://", "postgres://")):
        from monitor.backends._postgres import PostgresBackend

        backend = PostgresBackend(url)
    else:
        from monitor.backends._sqlite import SqliteBackend

        backend = SqliteBackend(url)

    backend.init_schema()
    return backend
