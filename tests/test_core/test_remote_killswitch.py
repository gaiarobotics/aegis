"""Tests for the remote killswitch client."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest

from aegis.core.config import KillswitchConfig
from aegis.core.remote_killswitch import RemoteKillswitch, _AEGIS_CENTRAL_URL


# ---------------------------------------------------------------------------
# Helpers — lightweight HTTP server for integration tests
# ---------------------------------------------------------------------------

class _MockHandler(BaseHTTPRequestHandler):
    """Configurable mock monitor endpoint."""

    # Class-level response config (set by tests)
    response_body: dict = {"blocked": False, "reason": "", "scope": ""}
    response_code: int = 200
    fail: bool = False

    def do_GET(self, *args, **kwargs):
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
    """Start a local HTTP server that acts as a killswitch monitor."""
    # Reset handler state
    _MockHandler.response_body = {"blocked": False, "reason": "", "scope": ""}
    _MockHandler.response_code = 200
    _MockHandler.fail = False

    server = HTTPServer(("127.0.0.1", 0), _MockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=_run_server, args=(server,), daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}/status"
    yield url, _MockHandler
    server.shutdown()


# ---------------------------------------------------------------------------
# Unit tests — no network
# ---------------------------------------------------------------------------


class TestKillswitchConfig:
    def test_default_config_empty_monitors(self):
        cfg = KillswitchConfig()
        assert cfg.monitors == []
        assert cfg.ttl_seconds == 60

    def test_custom_monitors(self):
        cfg = KillswitchConfig(
            monitors=["https://example.com/status", "aegis-central"],
            ttl_seconds=30,
        )
        assert len(cfg.monitors) == 2
        assert cfg.ttl_seconds == 30


class TestAliasExpansion:
    def test_aegis_central_expanded(self):
        cfg = KillswitchConfig(monitors=["aegis-central"])
        ks = RemoteKillswitch(config=cfg)
        assert _AEGIS_CENTRAL_URL in ks._monitor_states

    def test_plain_url_kept(self):
        cfg = KillswitchConfig(monitors=["https://example.com/status"])
        ks = RemoteKillswitch(config=cfg)
        assert "https://example.com/status" in ks._monitor_states

    def test_mixed_monitors(self):
        cfg = KillswitchConfig(
            monitors=["aegis-central", "https://other.com/ks"],
        )
        ks = RemoteKillswitch(config=cfg)
        assert len(ks._monitor_states) == 2
        assert _AEGIS_CENTRAL_URL in ks._monitor_states
        assert "https://other.com/ks" in ks._monitor_states


class TestIsBlockedNoPolling:
    def test_default_not_blocked(self):
        cfg = KillswitchConfig(monitors=["https://example.com/status"])
        ks = RemoteKillswitch(config=cfg)
        assert ks.is_blocked() is False
        assert ks.block_reason == ""

    def test_empty_monitors_not_blocked(self):
        cfg = KillswitchConfig(monitors=[])
        ks = RemoteKillswitch(config=cfg)
        assert ks.is_blocked() is False


class TestStartStop:
    def test_start_and_stop(self, mock_monitor):
        url, handler = mock_monitor
        cfg = KillswitchConfig(monitors=[url], ttl_seconds=1)
        ks = RemoteKillswitch(config=cfg)
        ks.start()
        assert ks._thread is not None
        assert ks._thread.is_alive()
        ks.stop()
        assert ks._thread is None

    def test_double_start_is_noop(self, mock_monitor):
        url, handler = mock_monitor
        cfg = KillswitchConfig(monitors=[url], ttl_seconds=1)
        ks = RemoteKillswitch(config=cfg)
        ks.start()
        thread1 = ks._thread
        ks.start()
        assert ks._thread is thread1
        ks.stop()


# ---------------------------------------------------------------------------
# Integration tests — with mock HTTP server
# ---------------------------------------------------------------------------


class TestPolling:
    def test_not_blocked_when_monitor_says_no(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {"blocked": False, "reason": "", "scope": ""}

        cfg = KillswitchConfig(monitors=[url], ttl_seconds=1)
        ks = RemoteKillswitch(config=cfg)
        ks.start()
        time.sleep(0.5)  # Wait for initial poll
        assert ks.is_blocked() is False
        ks.stop()

    def test_blocked_when_monitor_says_yes(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {
            "blocked": True,
            "reason": "Emergency shutdown",
            "scope": "swarm",
        }

        cfg = KillswitchConfig(monitors=[url], ttl_seconds=1)
        ks = RemoteKillswitch(config=cfg)
        ks.start()
        time.sleep(0.5)
        assert ks.is_blocked() is True
        assert ks.block_reason == "Emergency shutdown"
        ks.stop()

    def test_block_then_unblock(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {"blocked": True, "reason": "block", "scope": "swarm"}

        cfg = KillswitchConfig(monitors=[url], ttl_seconds=1)
        ks = RemoteKillswitch(config=cfg)
        ks.start()
        time.sleep(0.5)
        assert ks.is_blocked() is True

        # Unblock
        handler.response_body = {"blocked": False, "reason": "", "scope": ""}
        time.sleep(1.5)  # Wait for next poll
        assert ks.is_blocked() is False
        ks.stop()

    def test_network_failure_preserves_last_known(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {"blocked": True, "reason": "block", "scope": "swarm"}

        cfg = KillswitchConfig(monitors=[url], ttl_seconds=1)
        ks = RemoteKillswitch(config=cfg)
        ks.start()
        time.sleep(0.5)
        assert ks.is_blocked() is True

        # Simulate network failure
        handler.fail = True
        time.sleep(1.5)
        # Should still be blocked (last-known)
        assert ks.is_blocked() is True
        ks.stop()

    def test_network_failure_from_unblocked_stays_unblocked(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {"blocked": False, "reason": "", "scope": ""}

        cfg = KillswitchConfig(monitors=[url], ttl_seconds=1)
        ks = RemoteKillswitch(config=cfg)
        ks.start()
        time.sleep(0.5)
        assert ks.is_blocked() is False

        handler.fail = True
        time.sleep(1.5)
        # Should still be unblocked (last-known)
        assert ks.is_blocked() is False
        ks.stop()

    def test_query_params_sent(self, mock_monitor):
        url, handler = mock_monitor
        received_paths = []

        class _CapturingHandler(_MockHandler):
            def do_GET(self):
                received_paths.append(self.path)
                super().do_GET()

        # Need to manually create a server with the capturing handler
        server = HTTPServer(("127.0.0.1", 0), _CapturingHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=_run_server, args=(server,), daemon=True)
        thread.start()
        capture_url = f"http://127.0.0.1:{port}/status"

        cfg = KillswitchConfig(monitors=[capture_url], ttl_seconds=1)
        ks = RemoteKillswitch(config=cfg, agent_id="my-agent", operator_id="my-org")
        ks.start()
        time.sleep(0.5)
        ks.stop()
        server.shutdown()

        assert len(received_paths) >= 1
        assert "agent_id=my-agent" in received_paths[0]
        assert "operator_id=my-org" in received_paths[0]


class TestMultipleMonitors:
    def test_any_blocked_means_blocked(self):
        """If any monitor has blocked=True in its state, is_blocked() returns True."""
        cfg = KillswitchConfig(
            monitors=["https://m1.example.com", "https://m2.example.com"],
        )
        ks = RemoteKillswitch(config=cfg)

        # Manually set states (simulating poll results)
        states = list(ks._monitor_states.values())
        states[0].blocked = False
        states[1].blocked = True
        states[1].reason = "blocked by m2"

        assert ks.is_blocked() is True
        assert ks.block_reason == "blocked by m2"

    def test_none_blocked_means_not_blocked(self):
        cfg = KillswitchConfig(
            monitors=["https://m1.example.com", "https://m2.example.com"],
        )
        ks = RemoteKillswitch(config=cfg)
        assert ks.is_blocked() is False


class TestShieldIntegration:
    def test_shield_with_no_killswitch(self):
        """Shield with empty monitors should not create killswitch."""
        from aegis.core.config import AegisConfig
        from aegis.shield import Shield

        config = AegisConfig(
            modules={"scanner": False, "broker": False, "identity": False,
                      "memory": False, "behavior": False, "skills": False,
                      "recovery": False, "integrity": False},
        )
        shield = Shield(config=config)
        assert shield._killswitch is None
        assert shield.is_blocked is False
        # check_killswitch should be a no-op
        shield.check_killswitch()

    def test_shield_check_killswitch_raises(self):
        """check_killswitch should raise InferenceBlockedError when blocked."""
        from aegis.core.config import AegisConfig
        from aegis.shield import InferenceBlockedError, Shield

        config = AegisConfig(
            modules={"scanner": False, "broker": False, "identity": False,
                      "memory": False, "behavior": False, "skills": False,
                      "recovery": False, "integrity": False},
        )
        shield = Shield(config=config)

        # Simulate a killswitch that is blocked
        from unittest.mock import MagicMock
        mock_ks = MagicMock()
        mock_ks.is_blocked.return_value = True
        mock_ks.block_reason = "test block"
        shield._killswitch = mock_ks

        assert shield.is_blocked is True
        with pytest.raises(InferenceBlockedError, match="test block"):
            shield.check_killswitch()
