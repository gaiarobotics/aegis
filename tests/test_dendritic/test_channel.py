"""Tests for AEGIS dendritic alert channel — typed, schema-enforced transmission."""

import os

from aegis.dendritic.alert import DangerSignal, build_alert
from aegis.dendritic.channel import AlertChannel


class TestAlertChannelSchemaEnforcement:
    def test_rejects_non_dendritic_alert(self):
        channel = AlertChannel()
        result = channel.send("not an alert")
        assert result is False
        assert channel.rejected_count == 1
        assert channel.sent_count == 0

    def test_rejects_dict_instead_of_alert(self):
        channel = AlertChannel()
        result = channel.send({"danger_signal": "stop_and_alert_human"})
        assert result is False
        assert channel.rejected_count == 1

    def test_accepts_valid_dendritic_alert(self):
        key = os.urandom(32)
        alert = build_alert(
            cleaned_fragment="clean content",
            danger_signal=DangerSignal.STOP_AND_ALERT_HUMAN,
            source_agent_id="agent-1",
            sentinel_id="sentinel-1",
            threat_score=0.85,
            original_content_hash="hash123",
            modifications=[],
            signing_key=key,
        )
        # Channel without signature verification (no public key)
        channel = AlertChannel()
        result = channel.send(alert)
        assert result is True
        assert channel.sent_count == 1
        assert channel.rejected_count == 0


class TestAlertChannelSignatureVerification:
    def test_rejects_invalid_signature(self):
        key = os.urandom(32)
        wrong_key = os.urandom(32)
        alert = build_alert(
            cleaned_fragment="content",
            danger_signal=DangerSignal.ELEVATED_SCRUTINY,
            source_agent_id="agent-2",
            sentinel_id="sentinel-2",
            threat_score=0.5,
            original_content_hash="hash456",
            modifications=[],
            signing_key=key,
        )
        # Channel with wrong verification key
        channel = AlertChannel(sentinel_public_key=wrong_key)
        result = channel.send(alert)
        assert result is False
        assert channel.rejected_count == 1

    def test_accepts_valid_signature(self):
        key = os.urandom(32)
        alert = build_alert(
            cleaned_fragment="content",
            danger_signal=DangerSignal.QUARANTINE_RECOMMENDED,
            source_agent_id="agent-3",
            sentinel_id="sentinel-3",
            threat_score=0.6,
            original_content_hash="hash789",
            modifications=[],
            signing_key=key,
        )
        # HMAC uses same key for signing and verification
        channel = AlertChannel(sentinel_public_key=key)
        result = channel.send(alert)
        assert result is True
        assert channel.sent_count == 1


class TestAlertChannelReceive:
    def test_receive_verifies_signature(self):
        key = os.urandom(32)
        alert = build_alert(
            cleaned_fragment="content",
            danger_signal=DangerSignal.STOP_AND_ALERT_HUMAN,
            source_agent_id="agent-4",
            sentinel_id="sentinel-4",
            threat_score=0.9,
            original_content_hash="hash012",
            modifications=[],
            signing_key=key,
        )
        channel = AlertChannel()
        assert channel.receive(alert, key, "hmac-sha256") is True

    def test_receive_rejects_wrong_key(self):
        key = os.urandom(32)
        wrong_key = os.urandom(32)
        alert = build_alert(
            cleaned_fragment="content",
            danger_signal=DangerSignal.STOP_AND_ALERT_HUMAN,
            source_agent_id="agent-5",
            sentinel_id="sentinel-5",
            threat_score=0.9,
            original_content_hash="hash345",
            modifications=[],
            signing_key=key,
        )
        channel = AlertChannel()
        assert channel.receive(alert, wrong_key, "hmac-sha256") is False

    def test_receive_rejects_non_alert(self):
        channel = AlertChannel()
        assert channel.receive("not an alert", b"key", "hmac-sha256") is False
