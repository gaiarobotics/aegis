"""Tests for the remote quarantine client."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from aegis.core.remote_quarantine import RemoteQuarantine


# ---------------------------------------------------------------------------
# Helpers — lightweight HTTP server for integration tests
# ---------------------------------------------------------------------------

class _MockHandler(BaseHTTPRequestHandler):
    """Configurable mock quarantine endpoint."""

    response_body: dict = {"quarantined": False, "reason": "", "severity": ""}
    response_code: int = 200
    fail: bool = False
    last_headers: dict = {}

    def do_GET(self):
        _MockHandler.last_headers = dict(self.headers)
        if self.fail:
            self.send_error(500, "Simulated failure")
            return
        self.send_response(self.response_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(self.response_body).encode())

    def log_message(self, format, *args):
        pass  # Suppress server logs during tests


def _run_server(server: HTTPServer):
    server.serve_forever()


@pytest.fixture()
def mock_monitor():
    """Start a local HTTP server that acts as a quarantine status endpoint."""
    _MockHandler.response_body = {"quarantined": False, "reason": "", "severity": ""}
    _MockHandler.response_code = 200
    _MockHandler.fail = False
    _MockHandler.last_headers = {}

    server = HTTPServer(("127.0.0.1", 0), _MockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=_run_server, args=(server,), daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}/api/v1"
    yield url, _MockHandler
    server.shutdown()


# ---------------------------------------------------------------------------
# Unit tests — no network
# ---------------------------------------------------------------------------


class TestNotQuarantinedByDefault:
    def test_fresh_instance_not_quarantined(self):
        rq = RemoteQuarantine(
            service_url="http://localhost:9999/api/v1",
            api_key="test-key",
            agent_id="agent-1",
            operator_id="op-1",
        )
        assert rq.is_quarantined() is False
        assert rq.reason == ""
        assert rq.severity == ""


# ---------------------------------------------------------------------------
# Integration tests — with mock HTTP server
# ---------------------------------------------------------------------------


class TestPollSetsQuarantined:
    def test_poll_quarantined_true(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {
            "quarantined": True,
            "reason": "Contagion alert: score=0.950",
            "severity": "high",
        }

        rq = RemoteQuarantine(
            service_url=url,
            api_key="test-key",
            agent_id="agent-1",
            operator_id="op-1",
            poll_interval=1,
        )
        rq.start()
        time.sleep(0.5)
        assert rq.is_quarantined() is True
        assert "Contagion" in rq.reason
        assert rq.severity == "high"
        rq.stop()


class TestPollClearsQuarantined:
    def test_quarantine_lifted(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {
            "quarantined": True,
            "reason": "contagion",
            "severity": "high",
        }

        rq = RemoteQuarantine(
            service_url=url,
            api_key="test-key",
            agent_id="agent-1",
            operator_id="op-1",
            poll_interval=1,
        )
        rq.start()
        time.sleep(0.5)
        assert rq.is_quarantined() is True

        # Lift quarantine
        handler.response_body = {"quarantined": False, "reason": "", "severity": ""}
        time.sleep(1.5)
        assert rq.is_quarantined() is False
        rq.stop()


class TestNetworkFailurePreservesState:
    def test_failure_keeps_quarantined(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {
            "quarantined": True,
            "reason": "contagion",
            "severity": "high",
        }

        rq = RemoteQuarantine(
            service_url=url,
            api_key="test-key",
            agent_id="agent-1",
            operator_id="op-1",
            poll_interval=1,
        )
        rq.start()
        time.sleep(0.5)
        assert rq.is_quarantined() is True

        # Simulate network failure
        handler.fail = True
        time.sleep(1.5)
        # Should still be quarantined (fail-last)
        assert rq.is_quarantined() is True
        rq.stop()

    def test_failure_keeps_not_quarantined(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {"quarantined": False, "reason": "", "severity": ""}

        rq = RemoteQuarantine(
            service_url=url,
            api_key="test-key",
            agent_id="agent-1",
            operator_id="op-1",
            poll_interval=1,
        )
        rq.start()
        time.sleep(0.5)
        assert rq.is_quarantined() is False

        handler.fail = True
        time.sleep(1.5)
        assert rq.is_quarantined() is False
        rq.stop()


class TestThreadStartsAndStops:
    def test_lifecycle(self, mock_monitor):
        url, handler = mock_monitor

        rq = RemoteQuarantine(
            service_url=url,
            api_key="test-key",
            agent_id="agent-1",
            operator_id="op-1",
            poll_interval=1,
        )
        rq.start()
        assert rq._thread is not None
        assert rq._thread.is_alive()
        rq.stop()
        assert rq._thread is None

    def test_double_start_is_noop(self, mock_monitor):
        url, handler = mock_monitor

        rq = RemoteQuarantine(
            service_url=url,
            api_key="test-key",
            agent_id="agent-1",
            operator_id="op-1",
            poll_interval=1,
        )
        rq.start()
        thread1 = rq._thread
        rq.start()
        assert rq._thread is thread1
        rq.stop()


class TestApiKeySent:
    def test_authorization_header(self, mock_monitor):
        url, handler = mock_monitor

        rq = RemoteQuarantine(
            service_url=url,
            api_key="my-secret-key",
            agent_id="agent-1",
            operator_id="op-1",
            poll_interval=1,
        )
        rq.start()
        time.sleep(0.5)
        rq.stop()

        assert handler.last_headers.get("Authorization") == "Bearer my-secret-key"
