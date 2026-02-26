"""Tests for the remote threat intelligence client."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from aegis.core.remote_threat_intel import RemoteThreatIntel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _MockHandler(BaseHTTPRequestHandler):
    response_body: dict = {
        "compromised_agents": [],
        "compromised_hashes": [],
        "quarantined_agents": [],
        "generated_at": 0,
    }
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
        pass


def _run_server(server: HTTPServer):
    server.serve_forever()


@pytest.fixture()
def mock_monitor():
    _MockHandler.response_body = {
        "compromised_agents": [],
        "compromised_hashes": [],
        "quarantined_agents": [],
        "generated_at": 0,
    }
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


class TestDefaultState:
    def test_empty_caches(self):
        ti = RemoteThreatIntel(
            service_url="http://localhost:9999/api/v1",
            api_key="k",
            poll_interval=60,
        )
        assert ti.is_agent_compromised("any") is False
        assert ti.is_agent_quarantined("any") is False
        suspicious, score = ti.check_hash("a" * 32)
        assert suspicious is False
        assert score == 0.0


# ---------------------------------------------------------------------------
# Integration tests — with mock HTTP server
# ---------------------------------------------------------------------------


class TestPollPopulatesCache:
    def test_compromised_agents(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {
            "compromised_agents": ["bad-1", "bad-2"],
            "compromised_hashes": [],
            "quarantined_agents": [],
            "generated_at": 0,
        }
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        time.sleep(0.5)
        assert ti.is_agent_compromised("bad-1") is True
        assert ti.is_agent_compromised("bad-2") is True
        assert ti.is_agent_compromised("good-1") is False
        ti.stop()

    def test_quarantined_agents(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {
            "compromised_agents": [],
            "compromised_hashes": [],
            "quarantined_agents": ["q-1"],
            "generated_at": 0,
        }
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        time.sleep(0.5)
        assert ti.is_agent_quarantined("q-1") is True
        assert ti.is_agent_quarantined("other") is False
        ti.stop()

    def test_compromised_hashes(self, mock_monitor):
        url, handler = mock_monitor
        comp_hash = "abcdef01" * 4
        handler.response_body = {
            "compromised_agents": [],
            "compromised_hashes": [comp_hash],
            "quarantined_agents": [],
            "generated_at": 0,
        }
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        time.sleep(0.5)
        # Identical hash -> score 1.0, suspicious
        suspicious, score = ti.check_hash(comp_hash)
        assert suspicious is True
        assert score == 1.0
        # Very different hash -> not suspicious
        suspicious2, score2 = ti.check_hash("0" * 32)
        assert score2 < 0.85
        ti.stop()


class TestCheckHashThreshold:
    def test_custom_threshold(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {
            "compromised_agents": [],
            "compromised_hashes": ["00000000000000000000000000000000"],
            "quarantined_agents": [],
            "generated_at": 0,
        }
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        time.sleep(0.5)
        # 1 bit different -> similarity ~0.992, above any reasonable threshold
        suspicious, score = ti.check_hash(
            "00000000000000000000000000000001", threshold=0.99,
        )
        assert suspicious is True
        ti.stop()

    def test_empty_hash_not_suspicious(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {
            "compromised_agents": [],
            "compromised_hashes": ["a" * 32],
            "quarantined_agents": [],
            "generated_at": 0,
        }
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        time.sleep(0.5)
        suspicious, score = ti.check_hash("")
        assert suspicious is False
        assert score == 0.0
        ti.stop()


class TestNetworkFailurePreservesCache:
    def test_cache_preserved_on_failure(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {
            "compromised_agents": ["bad-1"],
            "compromised_hashes": [],
            "quarantined_agents": [],
            "generated_at": 0,
        }
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        time.sleep(0.5)
        assert ti.is_agent_compromised("bad-1") is True

        # Network fails
        handler.fail = True
        time.sleep(1.5)
        # Cache preserved
        assert ti.is_agent_compromised("bad-1") is True
        ti.stop()


class TestThreadLifecycle:
    def test_start_and_stop(self, mock_monitor):
        url, handler = mock_monitor
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        assert ti._thread is not None
        assert ti._thread.is_alive()
        ti.stop()
        assert ti._thread is None

    def test_double_start_noop(self, mock_monitor):
        url, handler = mock_monitor
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        t1 = ti._thread
        ti.start()
        assert ti._thread is t1
        ti.stop()


class TestApiKeySent:
    def test_authorization_header(self, mock_monitor):
        url, handler = mock_monitor
        ti = RemoteThreatIntel(service_url=url, api_key="secret", poll_interval=1)
        ti.start()
        time.sleep(0.5)
        ti.stop()
        assert handler.last_headers.get("Authorization") == "Bearer secret"
