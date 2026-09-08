"""ThreadingHTTPServer with AegisRequestHandler for the AEGIS proxy."""

from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from aegis.shield import Shield
from aegis_proxy.config import ProxyConfig

logger = logging.getLogger(__name__)


class AegisRequestHandler(BaseHTTPRequestHandler):
    """Route requests through AEGIS scanning before forwarding upstream."""

    # Set by the server at startup
    shield: Shield
    proxy_config: ProxyConfig

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.proxy_config.request_timeout_seconds)

    def do_POST(self) -> None:
        """Handle POST requests for /v1/chat/completions and /v1/messages."""
        if not self._authenticate_client():
            return

        semaphore = self.server.request_semaphore  # type: ignore[attr-defined]
        if not semaphore.acquire(blocking=False):
            self._send_json(
                503, {"error": {"message": "Proxy is at capacity", "code": "capacity_exceeded"}}
            )
            return

        try:
            self._handle_post()
        finally:
            semaphore.release()

    def _handle_post(self) -> None:
        """Handle an authenticated POST while holding a concurrency slot."""
        from aegis_proxy.handlers import handle_chat_completions, handle_messages

        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            self._send_json(
                400,
                {"error": {"message": "Invalid Content-Length", "code": "invalid_content_length"}},
            )
            return
        if content_length < 0:
            self._send_json(
                400,
                {"error": {"message": "Invalid Content-Length", "code": "invalid_content_length"}},
            )
            return
        if content_length > self.proxy_config.max_body_bytes:
            self._send_json(
                413, {"error": {"message": "Request body too large", "code": "body_too_large"}}
            )
            return
        try:
            raw_body = self.rfile.read(content_length) if content_length else b""
        except TimeoutError:
            self._send_json(
                408, {"error": {"message": "Request body timed out", "code": "request_timeout"}}
            )
            return

        try:
            body = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError:
            self._send_json(
                400,
                {
                    "error": {
                        "message": "Invalid JSON",
                        "type": "invalid_request_error",
                        "code": "invalid_json",
                    }
                },
            )
            return

        # Resolve upstream key: prefer Authorization header from client, fallback to config
        auth_header = self.headers.get("Authorization", "")
        upstream_key = ""
        if auth_header.startswith("Bearer "):
            upstream_key = auth_header[7:]
        upstream_key = upstream_key or self.proxy_config.upstream_key

        upstream_url = self.proxy_config.upstream_url

        if self.path == "/v1/chat/completions":
            status, response = handle_chat_completions(
                body=body,
                shield=self.shield,
                upstream_url=upstream_url,
                upstream_key=upstream_key,
            )
            self._send_json(status, response)
        elif self.path == "/v1/messages":
            status, response = handle_messages(
                body=body,
                shield=self.shield,
                upstream_url=upstream_url,
                upstream_key=upstream_key,
            )
            self._send_json(status, response)
        else:
            self._send_json(
                404,
                {
                    "error": {
                        "message": f"Unknown path: {self.path}",
                        "type": "invalid_request_error",
                        "code": "unknown_path",
                    }
                },
            )

    def _authenticate_client(self) -> bool:
        """Authenticate with a proxy-specific key, never the upstream key."""
        if not self.proxy_config.client_keys:
            return True
        supplied = self.headers.get("X-Aegis-Proxy-Key", "")
        if not supplied or not any(
            hmac.compare_digest(supplied, key) for key in self.proxy_config.client_keys
        ):
            self._send_json(
                401,
                {"error": {"message": "Invalid proxy client key", "code": "invalid_proxy_key"}},
            )
            return False
        return True

    def do_GET(self) -> None:
        """Handle GET requests for /health."""
        if not self._authenticate_client():
            return
        if self.path == "/health":
            self._send_json(
                200,
                {
                    "status": "ok",
                    "aegis_mode": self.shield.mode,
                    "upstream_url": self.proxy_config.upstream_url or "(not configured)",
                },
            )
        else:
            self._send_json(
                404,
                {
                    "error": {
                        "message": f"Unknown path: {self.path}",
                        "type": "invalid_request_error",
                        "code": "unknown_path",
                    }
                },
            )

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        """Write a JSON response."""
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        """Route access logs through the logging module."""
        logger.info(fmt, *args)


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def create_server(config: ProxyConfig, shield: Shield) -> ThreadingHTTPServer:
    """Create a configured ThreadingHTTPServer."""
    if not _is_loopback_host(config.host) and not config.client_keys:
        raise ValueError("Non-loopback proxy binding requires AEGIS_PROXY_CLIENT_KEYS")
    if config.max_body_bytes <= 0 or config.max_concurrent_requests <= 0:
        raise ValueError("Proxy resource limits must be positive")
    handler = type(
        "BoundHandler",
        (AegisRequestHandler,),
        {"shield": shield, "proxy_config": config},
    )
    server = _BoundedThreadingHTTPServer((config.host, config.port), handler)
    server.request_semaphore = threading.BoundedSemaphore(config.max_concurrent_requests)  # type: ignore[attr-defined]
    return server
