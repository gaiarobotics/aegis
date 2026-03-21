"""Async wrappers for the synchronous Database layer.

Uses ``asyncio.to_thread()`` to run blocking DB calls in the default
thread pool, keeping the FastAPI event loop unblocked.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, TypeVar

from monitor.db import Database

T = TypeVar("T")


async def run_db(fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run a synchronous Database method in a thread."""
    return await asyncio.to_thread(fn, *args, **kwargs)


async def run_in_transaction(db: Database, fn: Callable[..., T]) -> T:
    """Run *fn(tx)* inside a database transaction in a thread.

    ``fn`` receives a transaction handle with ``execute``, ``fetchone``,
    and ``fetchall`` methods.  The transaction commits on clean return
    and rolls back on exception.
    """

    def _run() -> T:
        with db.transaction() as tx:
            return fn(tx)

    return await asyncio.to_thread(_run)
