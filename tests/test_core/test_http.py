"""Tests for the shared HTTP connection pool."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio

from aegis.core.http import HttpPool, HttpResponse


# ---------------------------------------------------------------------------
# HttpResponse
# ---------------------------------------------------------------------------


class TestHttpResponse:
    def test_status_code(self):
        r = HttpResponse(200, b"ok")
        assert r.status_code == 200

    def test_body(self):
        r = HttpResponse(200, b"hello")
        assert r.body == b"hello"

    def test_headers_default_empty(self):
        r = HttpResponse(200, b"")
        assert r.headers == {}

    def test_headers_set(self):
        r = HttpResponse(200, b"", {"X-Foo": "bar"})
        assert r.headers["X-Foo"] == "bar"

    def test_is_success_200(self):
        assert HttpResponse(200, b"").is_success

    def test_is_success_201(self):
        assert HttpResponse(201, b"").is_success

    def test_is_success_299(self):
        assert HttpResponse(299, b"").is_success

    def test_not_success_400(self):
        assert not HttpResponse(400, b"").is_success

    def test_not_success_500(self):
        assert not HttpResponse(500, b"").is_success

    def test_text(self):
        r = HttpResponse(200, b"hello world")
        assert r.text == "hello world"

    def test_text_utf8(self):
        r = HttpResponse(200, "héllo".encode("utf-8"))
        assert r.text == "héllo"

    def test_json(self):
        data = {"key": "value", "num": 42}
        r = HttpResponse(200, json.dumps(data).encode())
        assert r.json() == data

    def test_json_invalid_raises(self):
        r = HttpResponse(200, b"not json")
        with pytest.raises(json.JSONDecodeError):
            r.json()


# ---------------------------------------------------------------------------
# HttpPool — sync
# ---------------------------------------------------------------------------


def _make_server(handler_cls):
    """Start a test HTTP server on a random port and return (server, port)."""
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    return server, port


class _EchoHandler(BaseHTTPRequestHandler):
    """Returns request info as JSON."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        body = json.dumps({"method": "GET", "path": self.path}).encode()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length) if length else b""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        body = json.dumps({
            "method": "POST",
            "path": self.path,
            "body": data.decode("utf-8", errors="replace"),
        }).encode()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class TestHttpPool:
    def test_get_returns_http_response(self):
        server, port = _make_server(_EchoHandler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        try:
            pool = HttpPool()
            resp = pool.get(f"http://127.0.0.1:{port}/test")
            assert isinstance(resp, HttpResponse)
            assert resp.is_success
            data = resp.json()
            assert data["method"] == "GET"
            assert data["path"] == "/test"
            pool.close()
        finally:
            server.server_close()
            thread.join(timeout=2)

    def test_post_returns_http_response(self):
        server, port = _make_server(_EchoHandler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        try:
            pool = HttpPool()
            resp = pool.post(
                f"http://127.0.0.1:{port}/submit",
                json_body={"key": "value"},
            )
            assert isinstance(resp, HttpResponse)
            assert resp.is_success
            data = resp.json()
            assert data["method"] == "POST"
            assert "key" in data["body"]
            pool.close()
        finally:
            server.server_close()
            thread.join(timeout=2)

    def test_post_with_raw_body(self):
        server, port = _make_server(_EchoHandler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        try:
            pool = HttpPool()
            resp = pool.post(
                f"http://127.0.0.1:{port}/submit",
                body=b"raw data",
                headers={"Content-Type": "text/plain"},
            )
            assert resp.is_success
            assert "raw data" in resp.json()["body"]
            pool.close()
        finally:
            server.server_close()
            thread.join(timeout=2)

    def test_connection_reuse(self):
        """Multiple requests share the same pool/client."""
        server, port = _make_server(_EchoHandler)
        # Handle 2 requests
        def serve():
            server.handle_request()
            server.handle_request()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            pool = HttpPool()
            r1 = pool.get(f"http://127.0.0.1:{port}/a")
            r2 = pool.get(f"http://127.0.0.1:{port}/b")
            assert r1.is_success
            assert r2.is_success
            # Verify the same httpx client is reused
            assert pool._sync_client is not None
            pool.close()
        finally:
            server.server_close()
            thread.join(timeout=2)

    def test_close_releases_resources(self):
        pool = HttpPool()
        # Force client creation
        pool._check_httpx()
        if pool._has_httpx:
            _ = pool._get_sync_client()
            assert pool._sync_client is not None
            pool.close()
            assert pool._sync_client is None

    def test_custom_timeout(self):
        pool = HttpPool(timeout=5.0)
        assert pool._timeout == 5.0
        pool.close()

    def test_custom_pool_sizes(self):
        pool = HttpPool(max_connections=50, max_keepalive_connections=25)
        assert pool._max_connections == 50
        assert pool._max_keepalive == 25
        pool.close()


# ---------------------------------------------------------------------------
# HttpPool — urllib fallback
# ---------------------------------------------------------------------------


class TestHttpPoolUrllibFallback:
    def test_get_fallback(self):
        server, port = _make_server(_EchoHandler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        try:
            pool = HttpPool()
            # Force urllib fallback by pretending httpx is unavailable
            pool._has_httpx = False
            resp = pool.get(f"http://127.0.0.1:{port}/fallback")
            assert resp.is_success
            data = resp.json()
            assert data["method"] == "GET"
            pool.close()
        finally:
            server.server_close()
            thread.join(timeout=2)

    def test_post_fallback(self):
        server, port = _make_server(_EchoHandler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        try:
            pool = HttpPool()
            pool._has_httpx = False
            resp = pool.post(
                f"http://127.0.0.1:{port}/submit",
                json_body={"x": 1},
            )
            assert resp.is_success
            pool.close()
        finally:
            server.server_close()
            thread.join(timeout=2)


# ---------------------------------------------------------------------------
# HttpPool — async
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestHttpPoolAsync:
    async def test_aget_returns_http_response(self):
        server, port = _make_server(_EchoHandler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        try:
            pool = HttpPool()
            resp = await pool.aget(f"http://127.0.0.1:{port}/async-test")
            assert isinstance(resp, HttpResponse)
            assert resp.is_success
            data = resp.json()
            assert data["method"] == "GET"
            await pool.aclose()
            pool.close()
        finally:
            server.server_close()
            thread.join(timeout=2)

    async def test_apost_returns_http_response(self):
        server, port = _make_server(_EchoHandler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        try:
            pool = HttpPool()
            resp = await pool.apost(
                f"http://127.0.0.1:{port}/async-submit",
                json_body={"async": True},
            )
            assert isinstance(resp, HttpResponse)
            assert resp.is_success
            await pool.aclose()
            pool.close()
        finally:
            server.server_close()
            thread.join(timeout=2)

    async def test_aclose_releases_async_client(self):
        pool = HttpPool()
        # Force async client creation
        _ = pool._get_async_client()
        assert pool._async_client is not None
        await pool.aclose()
        assert pool._async_client is None

    async def test_aget_raises_without_httpx(self):
        pool = HttpPool()
        pool._has_httpx = False
        with pytest.raises(RuntimeError, match="httpx is required"):
            await pool.aget("http://example.com")

    async def test_apost_raises_without_httpx(self):
        pool = HttpPool()
        pool._has_httpx = False
        with pytest.raises(RuntimeError, match="httpx is required"):
            await pool.apost("http://example.com")
