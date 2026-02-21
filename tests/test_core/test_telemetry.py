import json
import os
from pathlib import Path

from aegis.core.telemetry import TelemetryLogger, redact


class TestRedaction:
    def test_redacts_api_keys_sk(self):
        text = "key is sk-abc123456789012345678901234567890"
        result = redact(text)
        assert "sk-abc" not in result
        assert "[REDACTED]" in result

    def test_redacts_api_keys_key(self):
        text = "token: key-xyz9876543210abcdef"
        result = redact(text)
        assert "key-xyz" not in result
        assert "[REDACTED]" in result

    def test_redacts_long_base64(self):
        b64 = "A" * 64
        text = f"secret: {b64}"
        result = redact(text)
        assert b64 not in result
        assert "[REDACTED]" in result

    def test_clean_text_unchanged(self):
        text = "hello world normal text"
        assert redact(text) == text


class TestTelemetryLogger:
    def test_log_event_writes_jsonl(self, tmp_path):
        log_path = tmp_path / ".aegis" / "telemetry.jsonl"
        logger = TelemetryLogger(log_path=str(log_path))
        logger.log_event("threat_detection", threat="injection", score=0.9)
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 1
        event = json.loads(lines[0])
        assert event["event_type"] == "threat_detection"
        assert event["data"]["threat"] == "injection"

    def test_event_structure(self, tmp_path):
        log_path = tmp_path / ".aegis" / "telemetry.jsonl"
        logger = TelemetryLogger(log_path=str(log_path))
        logger.log_event("action_decision", action="allow")
        event = json.loads(log_path.read_text().strip())
        assert "timestamp" in event
        assert "event_type" in event
        assert "data" in event

    def test_creates_directory(self, tmp_path):
        log_path = tmp_path / "nested" / "deep" / "telemetry.jsonl"
        logger = TelemetryLogger(log_path=str(log_path))
        logger.log_event("test", msg="hello")
        assert log_path.exists()

    def test_redaction_in_event(self, tmp_path):
        log_path = tmp_path / ".aegis" / "telemetry.jsonl"
        logger = TelemetryLogger(log_path=str(log_path))
        logger.log_event("test", api_key="sk-secret123456789012345678")
        event = json.loads(log_path.read_text().strip())
        assert "sk-secret" not in json.dumps(event)
        assert "[REDACTED]" in json.dumps(event)

    def test_multiple_events_appended(self, tmp_path):
        log_path = tmp_path / ".aegis" / "telemetry.jsonl"
        logger = TelemetryLogger(log_path=str(log_path))
        logger.log_event("event1", a=1)
        logger.log_event("event2", b=2)
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 2



class TestNestedRedaction:
    def test_redact_nested_dict(self, tmp_path):
        log_path = tmp_path / ".aegis" / "telemetry.jsonl"
        logger = TelemetryLogger(log_path=str(log_path))
        logger.log_event(
            "test",
            outer={"inner": {"secret": "sk-nested1234567890abcdef"}},
        )
        event = json.loads(log_path.read_text().strip())
        dumped = json.dumps(event)
        assert "sk-nested" not in dumped
        assert "[REDACTED]" in dumped

    def test_redact_list_values(self, tmp_path):
        log_path = tmp_path / ".aegis" / "telemetry.jsonl"
        logger = TelemetryLogger(log_path=str(log_path))
        logger.log_event(
            "test",
            keys=["clean", "sk-listsecret1234567890abcdef", "also clean"],
        )
        event = json.loads(log_path.read_text().strip())
        dumped = json.dumps(event)
        assert "sk-listsecret" not in dumped
        assert "[REDACTED]" in dumped
        assert "clean" in dumped

    def test_redact_mixed_nested(self, tmp_path):
        log_path = tmp_path / ".aegis" / "telemetry.jsonl"
        logger = TelemetryLogger(log_path=str(log_path))
        logger.log_event(
            "test",
            data={
                "items": [
                    {"token": "key-abcdef1234567890xyz"},
                    {"token": "safe-value"},
                ],
            },
        )
        event = json.loads(log_path.read_text().strip())
        dumped = json.dumps(event)
        assert "key-abcdef" not in dumped
        assert "safe-value" in dumped

    def test_redact_non_string_values_unchanged(self, tmp_path):
        log_path = tmp_path / ".aegis" / "telemetry.jsonl"
        logger = TelemetryLogger(log_path=str(log_path))
        logger.log_event("test", count=42, enabled=True, ratio=0.5)
        event = json.loads(log_path.read_text().strip())
        assert event["data"]["count"] == 42
        assert event["data"]["enabled"] is True
        assert event["data"]["ratio"] == 0.5


class TestExpandedRedaction:
    def test_anthropic_key_redacted(self):
        """Keys like 'sk-ant-api03-abcdefghij' are redacted."""
        text = "my key is sk-ant-api03-abcdefghij"
        result = redact(text)
        assert "sk-ant-api03" not in result
        assert "[REDACTED]" in result

    def test_bearer_token_redacted(self):
        """'Bearer abc123xyz' is redacted."""
        text = "Authorization: Bearer abc123xyz"
        result = redact(text)
        assert "abc123xyz" not in result
        assert "[REDACTED]" in result
