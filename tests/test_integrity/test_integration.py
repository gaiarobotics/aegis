"""Integration tests for model integrity with Shield and providers."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.config import AegisConfig, IntegrityConfig
from aegis.integrity.monitor import (
    IntegrityMonitor,
    ModelFileRecord,
    ModelTamperedError,
    RegisteredModel,
    StatSnapshot,
)
from aegis.shield import Shield


# ---------------------------------------------------------------------------
# Shield integration tests
# ---------------------------------------------------------------------------


class TestShieldIntegrity:
    def test_shield_init_with_integrity(self):
        """Shield initializes integrity module when enabled."""
        shield = Shield()
        assert shield.integrity_monitor is not None
        assert isinstance(shield.integrity_monitor, IntegrityMonitor)
        shield.integrity_monitor.stop()

    def test_shield_integrity_disabled(self):
        """Shield works without integrity module."""
        config = AegisConfig()
        config.modules["integrity"] = False
        shield = Shield(config=config)
        assert shield.integrity_monitor is None

    def test_enforce_raises_on_tamper(self, tmp_path):
        """In enforce mode, tampered files raise ModelTamperedError."""
        model_file = tmp_path / "model.bin"
        model_file.write_bytes(b"original")

        shield = Shield(mode="enforce")
        monitor = shield.integrity_monitor
        assert monitor is not None
        try:
            # Manually register with a stale stat
            record = ModelFileRecord(
                path=str(model_file),
                stat=StatSnapshot.from_path(str(model_file)),
            )
            monitor._models["test-model"] = RegisteredModel(
                model_name="test-model", provider="test", files=[record],
            )

            # Tamper with the file
            time.sleep(0.01)
            model_file.write_bytes(b"tampered!")

            with pytest.raises(ModelTamperedError) as exc_info:
                shield.check_model_integrity("test-model", provider="test")
            assert "test-model" in str(exc_info.value)
        finally:
            monitor.stop()

    def test_observe_logs_on_tamper(self, tmp_path):
        """In observe mode, tampered files log warning but don't raise."""
        model_file = tmp_path / "model.bin"
        model_file.write_bytes(b"original")

        shield = Shield(mode="observe")
        monitor = shield.integrity_monitor
        assert monitor is not None
        try:
            record = ModelFileRecord(
                path=str(model_file),
                stat=StatSnapshot.from_path(str(model_file)),
            )
            monitor._models["test-model"] = RegisteredModel(
                model_name="test-model", provider="test", files=[record],
            )

            time.sleep(0.01)
            model_file.write_bytes(b"tampered!")

            # Should not raise in observe mode
            shield.check_model_integrity("test-model", provider="test")
        finally:
            monitor.stop()

    def test_check_model_integrity_noop_when_disabled(self):
        """No error when integrity module is disabled."""
        config = AegisConfig()
        config.modules["integrity"] = False
        shield = Shield(config=config)
        # Should be a no-op
        shield.check_model_integrity("any-model", provider="any")

    def test_auto_register_on_first_check(self):
        """Models are auto-registered on first integrity check."""
        shield = Shield()
        monitor = shield.integrity_monitor
        assert monitor is not None
        try:
            assert not monitor.is_registered("auto-model")
            shield.check_model_integrity("auto-model", provider="unknown_provider")
            assert monitor.is_registered("auto-model")
        finally:
            monitor.stop()


# ---------------------------------------------------------------------------
# Provider integration tests
# ---------------------------------------------------------------------------


class TestProviderIntegrity:
    def test_ollama_chat_calls_integrity(self):
        """Ollama wrapper calls check_model_integrity."""
        from aegis.providers.ollama import OllamaWrapper

        shield = MagicMock()
        shield.mode = "enforce"
        shield.scan_input.return_value = MagicMock(is_threat=False)
        shield.wrap_messages.return_value = []
        shield.sanitize_output.return_value = MagicMock(cleaned_text="response")
        shield.record_response_behavior.return_value = {}

        # Create a fake Ollama client
        fake_client = MagicMock()
        fake_client.chat.return_value = {"message": {"role": "assistant", "content": "hi"}}

        wrapper = OllamaWrapper(shield=shield)
        wrapped = wrapper.wrap(fake_client)
        wrapped.chat(model="llama3", messages=[{"role": "user", "content": "hello"}])

        shield.check_model_integrity.assert_called_once_with("llama3", provider="ollama")

    def test_ollama_generate_calls_integrity(self):
        """Ollama wrapper generate calls check_model_integrity."""
        from aegis.providers.ollama import OllamaWrapper

        shield = MagicMock()
        shield.mode = "enforce"
        shield.scan_input.return_value = MagicMock(is_threat=False)
        shield.sanitize_output.return_value = MagicMock(cleaned_text="output")
        shield.record_response_behavior.return_value = {}

        fake_client = MagicMock()
        fake_client.generate.return_value = {"response": "output"}

        wrapper = OllamaWrapper(shield=shield)
        wrapped = wrapper.wrap(fake_client)
        wrapped.generate(model="llama3", prompt="hello")

        shield.check_model_integrity.assert_called_once_with("llama3", provider="ollama")

    def test_vllm_generate_calls_integrity(self):
        """vLLM wrapper generate calls check_model_integrity."""
        from aegis.providers.vllm import VLLMWrapper

        shield = MagicMock()
        shield.mode = "enforce"
        shield.scan_input.return_value = MagicMock(is_threat=False)
        shield.sanitize_output.return_value = MagicMock(cleaned_text="output")
        shield.record_response_behavior.return_value = {}

        fake_client = MagicMock()
        fake_client.model = "meta-llama/Llama-3-70B"

        # vLLM generate returns list of RequestOutput objects
        mock_output = MagicMock()
        mock_output.outputs = [MagicMock(text="response")]
        fake_client.generate.return_value = [mock_output]

        wrapper = VLLMWrapper(shield=shield)
        wrapped = wrapper.wrap(fake_client)
        wrapped.generate(prompts=["hello"])

        shield.check_model_integrity.assert_called_once_with(
            "meta-llama/Llama-3-70B",
            provider="vllm",
            model_path="meta-llama/Llama-3-70B",
        )
