"""Shared HTTP connection pool — httpx-backed with urllib fallback.

Provides ``HttpPool`` for connection-pooled sync and async HTTP, and
``HttpResponse`` as a uniform response wrapper.  All AEGIS components
that make outbound HTTP calls should share a single ``HttpPool`` instance
to amortise connection setup at scale.

When *httpx* is unavailable, sync methods fall back to ``urllib.request``
(no pooling but functional).  Async methods require *httpx* and raise
``RuntimeError`` if it is missing.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)


class HttpResponse:
    """Uniform HTTP response wrapper."""

    __slots__ = ("status_code", "body", "headers")

    def __init__(self, status_code: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self.body = body
        self.headers: dict[str, str] = headers or {}

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.body)


class HttpPool:
    """Connection-pooling HTTP client with sync and async interfaces.

    Args:
        max_connections: Maximum total connections in the pool.
        max_keepalive_connections: Maximum idle keep-alive connections.
        timeout: Default request timeout in seconds.
    """

    def __init__(
        self,
        max_connections: int = 20,
        max_keepalive_connections: int = 10,
        timeout: float = 10.0,
    ) -> None:
        self._max_connections = max_connections
        self._max_keepalive = max_keepalive_connections
        self._timeout = timeout

        self._sync_client: Any = None
        self._async_client: Any = None
        self._sync_lock = threading.Lock()
        self._async_lock = threading.Lock()
        self._has_httpx: bool | None = None

    # ------------------------------------------------------------------
    # httpx availability
    # ------------------------------------------------------------------

    def _check_httpx(self) -> bool:
        if self._has_httpx is None:
            try:
                import httpx  # noqa: F401
                self._has_httpx = True
            except ImportError:
                self._has_httpx = False
        return self._has_httpx

    # ------------------------------------------------------------------
    # Lazy init
    # ------------------------------------------------------------------

    def _get_sync_client(self) -> Any:
        if self._sync_client is None:
            with self._sync_lock:
                if self._sync_client is None:
                    import httpx
                    self._sync_client = httpx.Client(
                        limits=httpx.Limits(
                            max_connections=self._max_connections,
                            max_keepalive_connections=self._max_keepalive,
                        ),
                        timeout=self._timeout,
                    )
        return self._sync_client

    def _get_async_client(self) -> Any:
        if self._async_client is None:
            with self._async_lock:
                if self._async_client is None:
                    import httpx
                    self._async_client = httpx.AsyncClient(
                        limits=httpx.Limits(
                            max_connections=self._max_connections,
                            max_keepalive_connections=self._max_keepalive,
                        ),
                        timeout=self._timeout,
                    )
        return self._async_client

    # ------------------------------------------------------------------
    # Sync methods
    # ------------------------------------------------------------------

    def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        """Synchronous GET request."""
        if self._check_httpx():
            client = self._get_sync_client()
            r = client.get(url, headers=headers, timeout=timeout)
            return HttpResponse(
                status_code=r.status_code,
                body=r.content,
                headers=dict(r.headers),
            )
        return self._urllib_get(url, headers, timeout)

    def post(
        self,
        url: str,
        body: bytes | None = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        """Synchronous POST request."""
        if self._check_httpx():
            client = self._get_sync_client()
            r = client.post(url, content=body, json=json_body, headers=headers, timeout=timeout)
            return HttpResponse(
                status_code=r.status_code,
                body=r.content,
                headers=dict(r.headers),
            )
        return self._urllib_post(url, body, json_body, headers, timeout)

    # ------------------------------------------------------------------
    # Async methods
    # ------------------------------------------------------------------

    async def aget(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        """Asynchronous GET request.  Requires httpx."""
        if not self._check_httpx():
            raise RuntimeError("httpx is required for async HTTP operations")
        client = self._get_async_client()
        r = await client.get(url, headers=headers, timeout=timeout)
        return HttpResponse(
            status_code=r.status_code,
            body=r.content,
            headers=dict(r.headers),
        )

    async def apost(
        self,
        url: str,
        body: bytes | None = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        """Asynchronous POST request.  Requires httpx."""
        if not self._check_httpx():
            raise RuntimeError("httpx is required for async HTTP operations")
        client = self._get_async_client()
        r = await client.post(url, content=body, json=json_body, headers=headers, timeout=timeout)
        return HttpResponse(
            status_code=r.status_code,
            body=r.content,
            headers=dict(r.headers),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the synchronous client and release resources."""
        with self._sync_lock:
            client = self._sync_client
            self._sync_client = None
        if client is not None:
            try:
                client.close()
            except Exception:
                logger.debug("Error closing sync HTTP client", exc_info=True)

    async def aclose(self) -> None:
        """Close the asynchronous client and release resources."""
        with self._async_lock:
            client = self._async_client
            self._async_client = None
        if client is not None:
            try:
                await client.aclose()
            except Exception:
                logger.debug("Error closing async HTTP client", exc_info=True)

    # ------------------------------------------------------------------
    # urllib fallbacks (no pooling)
    # ------------------------------------------------------------------

    def _urllib_get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        import urllib.error
        import urllib.request

        req = urllib.request.Request(url, method="GET", headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout or self._timeout) as resp:
                return HttpResponse(
                    status_code=resp.status,
                    body=resp.read(),
                    headers=dict(resp.headers),
                )
        except urllib.error.HTTPError as exc:
            return HttpResponse(
                status_code=exc.code,
                body=exc.read(),
                headers=dict(exc.headers) if exc.headers else {},
            )

    def _urllib_post(
        self,
        url: str,
        body: bytes | None = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> HttpResponse:
        import urllib.error
        import urllib.request

        hdrs = dict(headers or {})
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        else:
            data = body

        req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout or self._timeout) as resp:
                return HttpResponse(
                    status_code=resp.status,
                    body=resp.read(),
                    headers=dict(resp.headers),
                )
        except urllib.error.HTTPError as exc:
            return HttpResponse(
                status_code=exc.code,
                body=exc.read(),
                headers=dict(exc.headers) if exc.headers else {},
            )
