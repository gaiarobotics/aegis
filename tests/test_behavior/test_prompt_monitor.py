"""Tests for AEGIS system prompt and core file monitoring."""

from aegis.behavior.prompt_monitor import PromptMonitor


class TestPromptMonitor:
    def test_first_call_establishes_baseline(self):
        monitor = PromptMonitor()
        result = monitor.check({"system": "You are a helpful assistant."})
        assert result is False

    def test_same_prompt_no_change(self):
        monitor = PromptMonitor()
        monitor.check({"system": "You are a helpful assistant."})
        result = monitor.check({"system": "You are a helpful assistant."})
        assert result is False

    def test_changed_prompt_detected(self):
        monitor = PromptMonitor()
        monitor.check({"system": "You are a helpful assistant."})
        result = monitor.check({"system": "You are an evil assistant."})
        assert result is True

    def test_anthropic_system_kwarg(self):
        monitor = PromptMonitor()
        # Anthropic passes system prompt as kwargs["system"]
        monitor.check({"system": "System prompt v1"})
        assert monitor._prompt_hash is not None
        result = monitor.check({"system": "System prompt v1"})
        assert result is False

    def test_openai_system_message(self):
        monitor = PromptMonitor()
        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hello"},
        ]
        monitor.check({"messages": messages})
        assert monitor._prompt_hash is not None
        # Same system message — no change
        result = monitor.check({"messages": messages})
        assert result is False
        # Changed system message
        changed_messages = [
            {"role": "system", "content": "You are malicious."},
            {"role": "user", "content": "Hello"},
        ]
        result = monitor.check({"messages": changed_messages})
        assert result is True

    def test_no_system_prompt_returns_false(self):
        monitor = PromptMonitor()
        result = monitor.check({"messages": [{"role": "user", "content": "Hi"}]})
        assert result is False

    def test_watched_file_change_detected(self, tmp_path):
        watched = tmp_path / "SOUL.md"
        watched.write_text("Original system identity.")
        monitor = PromptMonitor(config={"watch_files": [str(watched)]})
        # First check — file unchanged
        result = monitor.check({})
        assert result is False
        # Modify the file
        watched.write_text("Modified system identity.")
        result = monitor.check({})
        assert result is True

    def test_watched_file_missing_graceful(self):
        monitor = PromptMonitor(
            config={"watch_files": ["/nonexistent/SOUL.md"]}
        )
        result = monitor.check({})
        assert result is False

    def test_reset_clears_baseline(self):
        monitor = PromptMonitor()
        monitor.check({"system": "Original prompt."})
        monitor.reset()
        # After reset, next call establishes new baseline
        result = monitor.check({"system": "Different prompt."})
        assert result is False
        # Now this is the baseline; same prompt is stable
        result = monitor.check({"system": "Different prompt."})
        assert result is False
