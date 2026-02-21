"""ThreadingHTTPServer with AegisRequestHandler for the AEGIS proxy."""

from __future__ import annotations

import json
import logging
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

    def do_POST(self) -> None:
        """Handle POST requests for /v1/chat/completions and /v1/messages."""
        from aegis_proxy.handlers import handle_chat_completions, handle_messages

        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length) if content_length else b""

        try:
            body = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError:
            self._send_json(400, {"error": {"message": "Invalid JSON", "type": "invalid_request_error", "code": "invalid_json"}})
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
            self._send_json(404, {"error": {"message": f"Unknown path: {self.path}", "type": "invalid_request_error", "code": "unknown_path"}})

    def do_GET(self) -> None:
        """Handle GET requests for /health."""
        if self.path == "/health":
            self._send_json(200, {
                "status": "ok",
                "aegis_mode": self.shield.mode,
                "upstream_url": self.proxy_config.upstream_url or "(not configured)",
            })
        else:
            self._send_json(404, {"error": {"message": f"Unknown path: {self.path}", "type": "invalid_request_error", "code": "unknown_path"}})

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


def create_server(config: ProxyConfig, shield: Shield) -> ThreadingHTTPServer:
    """Create a configured ThreadingHTTPServer."""
    handler = type(
        "BoundHandler",
        (AegisRequestHandler,),
        {"shield": shield, "proxy_config": config},
    )
    server = ThreadingHTTPServer((config.host, config.port), handler)
    return server
