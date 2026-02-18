"""Tests for the monitoring client."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock, patch

from aegis.monitoring.client import MonitoringClient
from aegis.identity.attestation import generate_keypair


def _disabled_config():
    return {"enabled": False, "service_url": "http://localhost:1", "api_key": ""}


def _enabled_config(port=0):
    return {
        "enabled": True,
        "service_url": f"http://127.0.0.1:{port}/api/v1",
        "api_key": "test-key",
        "heartbeat_interval_seconds": 60,
        "retry_max_attempts": 1,
        "retry_backoff_seconds": 0,
        "timeout_seconds": 2,
        "queue_max_size": 10,
    }


class TestDisabledClient:
    def test_noop_when_disabled(self):
        client = MonitoringClient(_disabled_config(), agent_id="a1")
        assert not client.enabled
        # These should all be no-ops (no exceptions)
        client.send_compromise_report("a2")
        client.send_trust_report("a2")
        client.send_threat_event(0.5, True)
        client.send_heartbeat()
        client.start()
        client.stop()


class TestClientSigning:
    def test_reports_are_signed(self):
        kp = generate_keypair("hmac-sha256")
        client = MonitoringClient(
            _enabled_config(port=1),
            agent_id="a1",
            operator_id="op1",
            keypair=kp,
        )
        # Patch _post to capture the payload
        payloads = []
        client._post = lambda endpoint, payload: (payloads.append(payload), True)[-1]

        client.send_compromise_report("a2")
        assert len(payloads) == 1
        assert payloads[0]["signature"] != ""
        assert payloads[0]["agent_id"] == "a1"


class TestClientQueue:
    def test_queue_on_failure(self):
        client = MonitoringClient(
            _enabled_config(port=1),
            agent_id="a1",
        )
        # Force _post to fail
        client._post = lambda endpoint, payload: False

        client.send_compromise_report("a2")
        assert len(client._queue) == 1

    def test_queue_max_size(self):
        cfg = _enabled_config(port=1)
        cfg["queue_max_size"] = 3
        client = MonitoringClient(cfg, agent_id="a1")
        client._post = lambda endpoint, payload: False

        for i in range(5):
            client.send_compromise_report(f"a{i}")
        assert len(client._queue) == 3

    def test_flush_retries_queued(self):
        client = MonitoringClient(
            _enabled_config(port=1),
            agent_id="a1",
        )
        # Fail first, succeed on flush
        client._post = lambda endpoint, payload: False
        client.send_compromise_report("a2")
        assert len(client._queue) == 1

        sent = []
        client._post = lambda endpoint, payload: (sent.append(payload), True)[-1]
        client._flush_queue()
        assert len(client._queue) == 0
        assert len(sent) == 1


class TestClientAuthHeader:
    def test_auth_header_sent(self):
        """Verify the Authorization: Bearer header is included."""
        received_headers = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received_headers.update(dict(self.headers))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok": true}')

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()

        try:
            client = MonitoringClient(
                _enabled_config(port=port),
                agent_id="a1",
            )
            client.send_compromise_report("a2")
        finally:
            server.server_close()
            thread.join(timeout=2)

        assert received_headers.get("Authorization") == "Bearer test-key"


class TestClientGracefulDegradation:
    def test_no_exception_on_network_error(self):
        """Client should silently handle connection failures."""
        cfg = _enabled_config(port=1)  # port 1 won't be listening
        cfg["retry_max_attempts"] = 1
        cfg["timeout_seconds"] = 1
        client = MonitoringClient(cfg, agent_id="a1")
        # Should not raise
        client.send_compromise_report("a2")
        client.send_trust_report("a2")
        client.send_threat_event(0.5, True)
        client.send_heartbeat()

    def test_start_stop_lifecycle(self):
        """Start and stop should work without errors."""
        cfg = _enabled_config(port=1)
        cfg["heartbeat_interval_seconds"] = 0.1
        client = MonitoringClient(cfg, agent_id="a1")
        client._post = lambda endpoint, payload: True
        client.start()
        assert client._heartbeat_thread is not None
        assert client._heartbeat_thread.is_alive()
        client.stop()
        assert client._heartbeat_thread is None


class TestClientQueueLock:
    def test_has_queue_lock(self):
        """MonitoringClient should have a _queue_lock attribute."""
        client = MonitoringClient(_enabled_config(port=1), agent_id="a1")
        assert hasattr(client, "_queue_lock")
        assert isinstance(client._queue_lock, type(threading.Lock()))

    def test_concurrent_send_and_flush(self):
        """Concurrent sends and flushes should not corrupt the queue."""
        cfg = _enabled_config(port=1)
        cfg["queue_max_size"] = 100
        client = MonitoringClient(cfg, agent_id="a1")

        # Track calls to prevent actual HTTP requests
        call_count = {"send": 0, "flush": 0}

        # _post always fails so items get queued
        client._post = lambda endpoint, payload: False

        errors = []
        barrier = threading.Barrier(10)

        def send_worker():
            try:
                barrier.wait(timeout=5)
                for _ in range(10):
                    client.send_compromise_report("a2")
            except Exception as e:
                errors.append(e)

        def flush_worker():
            try:
                barrier.wait(timeout=5)
                for _ in range(10):
                    client._flush_queue()
            except Exception as e:
                errors.append(e)

        threads = []
        for _ in range(5):
            threads.append(threading.Thread(target=send_worker))
        for _ in range(5):
            threads.append(threading.Thread(target=flush_worker))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert not errors
        # Queue should not have raised any exceptions; all items should be intact
        assert len(client._queue) <= 100


class TestServiceUrlValidation:
    def test_invalid_scheme_rejected(self):
        """'ftp://evil.com' raises ValueError."""
        import pytest

        cfg = {"enabled": True, "service_url": "ftp://evil.com", "api_key": ""}
        with pytest.raises(ValueError, match="Invalid service URL scheme"):
            MonitoringClient(cfg, agent_id="a1")

    def test_no_hostname_rejected(self):
        """'http://' raises ValueError."""
        import pytest

        cfg = {"enabled": True, "service_url": "http://", "api_key": ""}
        with pytest.raises(ValueError, match="Service URL must have a valid hostname"):
            MonitoringClient(cfg, agent_id="a1")

    def test_valid_http_accepted(self):
        """'http://example.com' is accepted."""
        cfg = {"enabled": True, "service_url": "http://example.com", "api_key": ""}
        client = MonitoringClient(cfg, agent_id="a1")
        assert client._service_url == "http://example.com"

    def test_empty_url_accepted(self):
        """Empty string is accepted (disabled monitoring)."""
        cfg = {"enabled": False, "service_url": "", "api_key": ""}
        client = MonitoringClient(cfg, agent_id="a1")
        assert client._service_url == ""
