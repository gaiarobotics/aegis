"""Tests for AEGIS dendritic alert — signing, verification, and danger signals."""

import os

from aegis.dendritic.alert import (
    DangerSignal,
    DendriticAlert,
    build_alert,
    sign_alert,
    verify_alert,
)


class TestDangerSignalEnum:
    def test_stop_and_alert_human_value(self):
        assert DangerSignal.STOP_AND_ALERT_HUMAN.value == "stop_and_alert_human"

    def test_elevated_scrutiny_value(self):
        assert DangerSignal.ELEVATED_SCRUTINY.value == "elevated_scrutiny"

    def test_quarantine_recommended_value(self):
        assert DangerSignal.QUARANTINE_RECOMMENDED.value == "quarantine_recommended"


class TestAlertSigning:
    def _make_key(self):
        return os.urandom(32)

    def test_sign_and_verify_hmac(self):
        key = self._make_key()
        alert = build_alert(
            cleaned_fragment="safe content here",
            danger_signal=DangerSignal.STOP_AND_ALERT_HUMAN,
            source_agent_id="agent-x",
            sentinel_id="sentinel-1",
            threat_score=0.85,
            original_content_hash="abc123",
            modifications=[],
            signing_key=key,
        )
        assert alert.signature != b""
        assert verify_alert(alert, key, "hmac-sha256")

    def test_verify_rejects_wrong_key(self):
        key = self._make_key()
        wrong_key = self._make_key()
        alert = build_alert(
            cleaned_fragment="content",
            danger_signal=DangerSignal.ELEVATED_SCRUTINY,
            source_agent_id="agent-y",
            sentinel_id="sentinel-2",
            threat_score=0.5,
            original_content_hash="def456",
            modifications=[],
            signing_key=key,
        )
        assert not verify_alert(alert, wrong_key, "hmac-sha256")

    def test_verify_rejects_tampered_fragment(self):
        key = self._make_key()
        alert = build_alert(
            cleaned_fragment="original",
            danger_signal=DangerSignal.QUARANTINE_RECOMMENDED,
            source_agent_id="agent-z",
            sentinel_id="sentinel-3",
            threat_score=0.6,
            original_content_hash="ghi789",
            modifications=[],
            signing_key=key,
        )
        # Tamper with the fragment
        alert.cleaned_fragment = "tampered content"
        assert not verify_alert(alert, key, "hmac-sha256")

    def test_verify_rejects_tampered_danger_signal(self):
        key = self._make_key()
        alert = build_alert(
            cleaned_fragment="content",
            danger_signal=DangerSignal.ELEVATED_SCRUTINY,
            source_agent_id="agent-a",
            sentinel_id="sentinel-4",
            threat_score=0.4,
            original_content_hash="jkl012",
            modifications=[],
            signing_key=key,
        )
        # Tamper with danger signal
        alert.danger_signal = DangerSignal.STOP_AND_ALERT_HUMAN
        assert not verify_alert(alert, key, "hmac-sha256")


class TestAlertSerialization:
    def test_to_dict(self):
        key = os.urandom(32)
        alert = build_alert(
            cleaned_fragment="test",
            danger_signal=DangerSignal.STOP_AND_ALERT_HUMAN,
            source_agent_id="agent-1",
            sentinel_id="sentinel-1",
            threat_score=0.9,
            original_content_hash="hash123",
            modifications=[{"type": "sanitizer", "description": "stripped marker"}],
            signing_key=key,
        )
        d = alert.to_dict()
        assert d["danger_signal"] == "stop_and_alert_human"
        assert d["source_agent_id"] == "agent-1"
        assert d["sentinel_id"] == "sentinel-1"
        assert isinstance(d["signature"], str)  # hex-encoded
        assert len(d["modifications"]) == 1


class TestBuildAlert:
    def test_build_alert_populates_all_fields(self):
        key = os.urandom(32)
        alert = build_alert(
            cleaned_fragment="clean",
            danger_signal=DangerSignal.STOP_AND_ALERT_HUMAN,
            source_agent_id="src",
            sentinel_id="sent",
            threat_score=0.75,
            original_content_hash="hash",
            modifications=[],
            signing_key=key,
        )
        assert alert.cleaned_fragment == "clean"
        assert alert.danger_signal == DangerSignal.STOP_AND_ALERT_HUMAN
        assert alert.source_agent_id == "src"
        assert alert.sentinel_id == "sent"
        assert alert.threat_score == 0.75
        assert alert.original_content_hash == "hash"
        assert alert.timestamp > 0
        assert alert.signature != b""
