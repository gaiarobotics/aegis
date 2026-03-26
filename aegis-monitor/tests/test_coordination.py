"""Tests for Clio-inspired cross-agent coordination detection."""

import time

import pytest

from monitor.coordination import (
    CoordinationConfig,
    CoordinationDetector,
    _hamming_hex,
)


class TestHammingHex:
    def test_identical(self):
        assert _hamming_hex("abcd1234", "abcd1234") == 0

    def test_different(self):
        dist = _hamming_hex("00000000", "ffffffff")
        assert dist == 32  # 32 bits different for 8 hex chars

    def test_invalid(self):
        assert _hamming_hex("not_hex", "also_bad") is None

    def test_single_bit(self):
        # 0x0 vs 0x1 = 1 bit
        assert _hamming_hex("0", "1") == 1


class TestCoordinationDetector:
    def test_no_alerts_with_few_agents(self):
        det = CoordinationDetector(
            config=CoordinationConfig(min_agents=3),
        )
        det.record_heartbeat("a1", drift_score=0.8)
        det.record_heartbeat("a2", drift_score=0.9)
        alerts = det.detect_coordination()
        assert len(alerts) == 0

    def test_synchronized_drift(self):
        det = CoordinationDetector(
            config=CoordinationConfig(
                min_agents=3,
                drift_window_seconds=60.0,
                drift_threshold=0.5,
            ),
        )
        # Record 4 agents all drifting
        for i in range(4):
            det.record_heartbeat(f"agent-{i}", drift_score=0.7)

        alerts = det.detect_coordination()
        drift_alerts = [a for a in alerts if a.alert_type == "synchronized_drift"]
        assert len(drift_alerts) == 1
        assert len(drift_alerts[0].agent_ids) == 4
        assert drift_alerts[0].confidence > 0

    def test_no_drift_below_threshold(self):
        det = CoordinationDetector(
            config=CoordinationConfig(
                min_agents=2,
                drift_threshold=0.5,
            ),
        )
        det.record_heartbeat("a1", drift_score=0.3)
        det.record_heartbeat("a2", drift_score=0.4)
        alerts = det.detect_coordination()
        drift_alerts = [a for a in alerts if a.alert_type == "synchronized_drift"]
        assert len(drift_alerts) == 0

    def test_content_convergence(self):
        det = CoordinationDetector(
            config=CoordinationConfig(
                min_agents=3,
                convergence_hamming_threshold=16,
            ),
        )
        # Same content hash
        for i in range(4):
            det.record_heartbeat(f"agent-{i}", content_hash="abcdef1234567890")

        alerts = det.detect_coordination()
        conv_alerts = [a for a in alerts if a.alert_type == "content_convergence"]
        assert len(conv_alerts) == 1
        assert len(conv_alerts[0].agent_ids) == 4

    def test_no_convergence_different_hashes(self):
        det = CoordinationDetector(
            config=CoordinationConfig(
                min_agents=3,
                convergence_hamming_threshold=4,
            ),
        )
        # Very different content hashes
        det.record_heartbeat("a1", content_hash="00000000")
        det.record_heartbeat("a2", content_hash="ffffffff")
        det.record_heartbeat("a3", content_hash="12345678")

        alerts = det.detect_coordination()
        conv_alerts = [a for a in alerts if a.alert_type == "content_convergence"]
        assert len(conv_alerts) == 0

    def test_behavioral_mimicry(self):
        det = CoordinationDetector(
            config=CoordinationConfig(min_agents=3),
        )
        # Same fingerprint hash
        for i in range(5):
            det.record_heartbeat(f"agent-{i}", fingerprint_hash="deadbeef12345678")

        alerts = det.detect_coordination()
        mimicry_alerts = [a for a in alerts if a.alert_type == "behavioral_mimicry"]
        assert len(mimicry_alerts) == 1
        assert len(mimicry_alerts[0].agent_ids) == 5

    def test_get_recent_alerts(self):
        det = CoordinationDetector(
            config=CoordinationConfig(min_agents=2, drift_threshold=0.3),
        )
        det.record_heartbeat("a1", drift_score=0.5)
        det.record_heartbeat("a2", drift_score=0.6)
        det.detect_coordination()

        recent = det.get_recent_alerts(max_age_seconds=60)
        assert len(recent) >= 1
        assert "alert_type" in recent[0]
        assert "confidence" in recent[0]

    def test_alert_to_dict(self):
        det = CoordinationDetector(
            config=CoordinationConfig(min_agents=2, drift_threshold=0.3),
        )
        det.record_heartbeat("a1", drift_score=0.5)
        det.record_heartbeat("a2", drift_score=0.6)
        alerts = det.detect_coordination()
        if alerts:
            d = alerts[0].to_dict()
            assert isinstance(d, dict)
            assert "agent_ids" in d
            assert "timestamp" in d

    def test_empty_heartbeats(self):
        det = CoordinationDetector()
        alerts = det.detect_coordination()
        assert alerts == []
