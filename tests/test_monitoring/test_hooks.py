"""Tests for monitoring hooks in trust.py and shield.py."""

from unittest.mock import MagicMock, patch

from aegis.core.config import AegisConfig
from aegis.identity.trust import TrustManager


class TestTrustCallback:
    def test_compromise_callback_fires(self):
        tm = TrustManager()
        called_with = []
        tm.set_compromise_callback(lambda agent_id: called_with.append(agent_id))

        tm.report_compromise("agent-x")
        assert called_with == ["agent-x"]

    def test_callback_exception_does_not_propagate(self):
        tm = TrustManager()
        tm.set_compromise_callback(lambda agent_id: 1 / 0)

        # Should not raise
        tm.report_compromise("agent-x")
        assert "agent-x" in tm._compromised

    def test_no_callback_by_default(self):
        tm = TrustManager()
        assert tm._compromise_callback is None
        # Should not raise
        tm.report_compromise("agent-y")


class TestShieldMonitoring:
    def test_monitoring_disabled_by_default(self):
        """Shield should not create a monitoring client when disabled."""
        from aegis.shield import Shield

        shield = Shield(config=AegisConfig())
        assert shield._monitoring_client is None

    def test_monitoring_enabled(self):
        """Shield should create a monitoring client when enabled."""
        from aegis.shield import Shield

        cfg = AegisConfig()
        cfg.monitoring["enabled"] = True
        cfg.monitoring["service_url"] = "http://localhost:9999/api/v1"
        cfg.agent_id = "test-agent"
        cfg.operator_id = "test-op"

        shield = Shield(config=cfg)
        assert shield._monitoring_client is not None
        assert shield._monitoring_client.enabled
        # Clean up
        shield._monitoring_client.stop()

    def test_shield_sends_threat_event(self):
        """scan_input should send a threat event when a threat is detected."""
        from aegis.shield import Shield

        cfg = AegisConfig()
        cfg.monitoring["enabled"] = True
        cfg.monitoring["service_url"] = "http://localhost:9999/api/v1"
        cfg.agent_id = "test-agent"
        cfg.modules["scanner"] = False
        cfg.modules["identity"] = False
        cfg.modules["behavior"] = False
        cfg.modules["recovery"] = False

        shield = Shield(config=cfg)
        assert shield._monitoring_client is not None

        sent_events = []
        shield._monitoring_client.send_threat_event = lambda **kw: sent_events.append(kw)
        shield._monitoring_client.send_compromise_report = lambda **kw: None

        # Simulate a threat result by patching _scanner
        mock_scanner = MagicMock()
        mock_result = MagicMock()
        mock_result.threat_score = 0.9
        mock_result.is_threat = True
        mock_result.matches = ["m1", "m2"]
        mock_scanner.scan_input.return_value = mock_result
        shield._scanner = mock_scanner

        result = shield.scan_input("test input")
        assert result.is_threat
        assert len(sent_events) == 1
        assert sent_events[0]["is_threat"] is True

        shield._monitoring_client.stop()

    def test_compromise_callback_wired(self):
        """TrustManager compromise callback should be wired to monitoring client."""
        from aegis.shield import Shield

        cfg = AegisConfig()
        cfg.monitoring["enabled"] = True
        cfg.monitoring["service_url"] = "http://localhost:9999/api/v1"
        cfg.agent_id = "test-agent"

        shield = Shield(config=cfg)

        if shield._trust_manager is not None and shield._monitoring_client is not None:
            assert shield._trust_manager._compromise_callback is not None

            sent = []
            shield._monitoring_client.send_compromise_report = lambda **kw: sent.append(kw)
            shield._trust_manager.report_compromise("compromised-agent")
            assert len(sent) == 1
            assert sent[0]["compromised_agent_id"] == "compromised-agent"

        if shield._monitoring_client:
            shield._monitoring_client.stop()
