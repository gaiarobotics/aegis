"""Tests for the AEGIS proxy server startup, routing, and health check."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from aegis.shield import Shield
from aegis_proxy.config import ProxyConfig
from aegis_proxy.server import AegisRequestHandler, create_server


@pytest.fixture()
def proxy_server():
    """Start a proxy server on a random port and yield (server, base_url)."""
    config = ProxyConfig(port=0, host="127.0.0.1", upstream_url="", upstream_key="")
    shield = Shield(mode="enforce")
    server = create_server(config, shield)
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Give the server a moment to bind
    time.sleep(0.1)
    yield server, base_url
    server.shutdown()


class TestHealthCheck:
    def test_health_returns_200(self, proxy_server):
        _, base_url = proxy_server
        req = urllib.request.Request(f"{base_url}/health")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read())
            assert data["status"] == "ok"
            assert "aegis_mode" in data

    def test_health_shows_mode(self, proxy_server):
        _, base_url = proxy_server
        req = urllib.request.Request(f"{base_url}/health")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            assert data["aegis_mode"] == "enforce"


class TestRouting:
    def test_unknown_get_returns_404(self, proxy_server):
        _, base_url = proxy_server
        req = urllib.request.Request(f"{base_url}/v1/unknown")
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)
        assert exc_info.value.code == 404

    def test_unknown_post_returns_404(self, proxy_server):
        _, base_url = proxy_server
        body = json.dumps({"test": True}).encode()
        req = urllib.request.Request(
            f"{base_url}/v1/unknown",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)
        assert exc_info.value.code == 404

    def test_invalid_json_returns_400(self, proxy_server):
        _, base_url = proxy_server
        req = urllib.request.Request(
            f"{base_url}/v1/chat/completions",
            data=b"not json {{{",
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)
        assert exc_info.value.code == 400


class TestServerCreation:
    def test_create_server_binds_shield(self):
        config = ProxyConfig(port=0, host="127.0.0.1")
        shield = Shield(mode="observe")
        server = create_server(config, shield)
        # Handler class should have shield attribute
        handler_cls = server.RequestHandlerClass
        assert handler_cls.shield is shield
        assert handler_cls.proxy_config is config
        server.server_close()


class TestConfig:
    def test_default_config(self):
        cfg = ProxyConfig()
        assert cfg.port == 8419
        assert cfg.aegis_mode == "enforce"

    def test_from_env_with_overrides(self):
        cfg = ProxyConfig.from_env(port=9999, mode="observe")
        assert cfg.port == 9999
        assert cfg.aegis_mode == "observe"

    def test_from_env_with_env_vars(self, monkeypatch):
        monkeypatch.setenv("AEGIS_PROXY_PORT", "7777")
        monkeypatch.setenv("AEGIS_PROXY_UPSTREAM_URL", "http://example.com/v1")
        monkeypatch.setenv("AEGIS_MODE", "observe")
        cfg = ProxyConfig.from_env()
        assert cfg.port == 7777
        assert cfg.upstream_url == "http://example.com/v1"
        assert cfg.aegis_mode == "observe"
