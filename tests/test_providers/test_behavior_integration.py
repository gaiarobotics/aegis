"""Integration tests for behavior recording wired through provider wrappers."""

from aegis.providers.anthropic import AnthropicWrapper
from aegis.providers.openai import OpenAIWrapper
from aegis.providers.generic import GenericWrapper
from aegis.shield import Shield


# --- Mock Clients ---

class MockAnthropicClient:
    class messages:
        @staticmethod
        def create(**kwargs):
            return {"content": [{"type": "text", "text": "Hello, I can help you."}]}


class MockAnthropicToolUseClient:
    class messages:
        @staticmethod
        def create(**kwargs):
            return {
                "content": [
                    {"type": "tool_use", "id": "toolu_01", "name": "calculator", "input": {"expr": "2+2"}},
                    {"type": "text", "text": "The result is 4."},
                ]
            }


class MockOpenAIClient:
    class chat:
        class completions:
            @staticmethod
            def create(**kwargs):
                return {"choices": [{"message": {"content": "Hello, I can help you."}}]}


class MockOpenAIToolCallsClient:
    class chat:
        class completions:
            @staticmethod
            def create(**kwargs):
                return {
                    "choices": [{
                        "message": {
                            "content": "Let me calculate that.",
                            "tool_calls": [
                                {"function": {"name": "calculator", "arguments": '{"expr":"2+2"}'}}
                            ],
                        }
                    }]
                }


class MockGenericClient:
    @staticmethod
    def create(**kwargs):
        return "This is a generic response."


# --- Anthropic Integration ---

class TestAnthropicBehaviorRecorded:
    def test_behavior_recorded_on_text_response(self):
        shield = Shield(modules=["scanner", "behavior"])
        wrapper = AnthropicWrapper(shield=shield)
        client = MockAnthropicClient()
        wrapped = wrapper.wrap(client)

        wrapped.messages.create(
            model="claude-3",
            messages=[{"role": "user", "content": "Hello"}],
        )

        # BehaviorTracker should have recorded at least one event
        events = list(shield._behavior_tracker._events.get("self", []))
        assert len(events) >= 1
        assert events[-1].event_type == "llm_response"
        assert events[-1].output_length > 0

    def test_anthropic_tool_use_extracted(self):
        shield = Shield(modules=["scanner", "behavior"])
        wrapper = AnthropicWrapper(shield=shield)
        client = MockAnthropicToolUseClient()
        wrapped = wrapper.wrap(client)

        wrapped.messages.create(
            model="claude-3",
            messages=[{"role": "user", "content": "What is 2+2?"}],
        )

        events = list(shield._behavior_tracker._events.get("self", []))
        assert len(events) >= 1
        # The primary event should have tool_used set
        assert events[0].tool_used == "calculator"


# --- OpenAI Integration ---

class TestOpenAIBehaviorRecorded:
    def test_behavior_recorded_on_text_response(self):
        shield = Shield(modules=["scanner", "behavior"])
        wrapper = OpenAIWrapper(shield=shield)
        client = MockOpenAIClient()
        wrapped = wrapper.wrap(client)

        wrapped.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Hello"}],
        )

        events = list(shield._behavior_tracker._events.get("self", []))
        assert len(events) >= 1
        assert events[-1].event_type == "llm_response"
        assert events[-1].output_length > 0

    def test_openai_tool_calls_extracted(self):
        shield = Shield(modules=["scanner", "behavior"])
        wrapper = OpenAIWrapper(shield=shield)
        client = MockOpenAIToolCallsClient()
        wrapped = wrapper.wrap(client)

        wrapped.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Calculate 2+2"}],
        )

        events = list(shield._behavior_tracker._events.get("self", []))
        assert len(events) >= 1
        assert events[0].tool_used == "calculator"


# --- Generic Integration ---

class TestGenericBehaviorRecorded:
    def test_behavior_recorded_on_string_response(self):
        shield = Shield(modules=["scanner", "behavior"])
        wrapper = GenericWrapper(shield=shield)
        client = MockGenericClient()
        wrapped = wrapper.wrap(client)

        wrapped.create(prompt="Hello")

        events = list(shield._behavior_tracker._events.get("self", []))
        assert len(events) >= 1
        assert events[-1].event_type == "llm_response"


# --- Graceful Degradation ---

class TestGracefulDegradation:
    def test_no_behavior_module_no_error(self):
        """Shield with behavior disabled should still wrap and return responses."""
        shield = Shield(modules=["scanner"])
        wrapper = AnthropicWrapper(shield=shield)
        client = MockAnthropicClient()
        wrapped = wrapper.wrap(client)

        result = wrapped.messages.create(
            model="claude-3",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result["content"][0]["text"] == "Hello, I can help you."
        assert shield._behavior_tracker is None



# --- Prompt Monitor Wiring ---

class TestPromptMonitorWiring:
    def test_system_prompt_change_detected(self):
        shield = Shield(modules=["scanner", "behavior", "identity"])
        wrapper = AnthropicWrapper(shield=shield)
        client = MockAnthropicClient()
        wrapped = wrapper.wrap(client)

        # First call establishes baseline
        wrapped.messages.create(
            model="claude-3",
            system="You are a helpful assistant.",
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert shield._prompt_monitor is not None
        assert shield._prompt_monitor._prompt_hash is not None

        # Second call with different system prompt
        wrapped.messages.create(
            model="claude-3",
            system="You are a malicious assistant.",
            messages=[{"role": "user", "content": "Hello again"}],
        )
        # The prompt monitor should have detected the change
        # (We verify by checking directly since the hash should still be the original baseline)
        changed = shield._prompt_monitor.check({"system": "You are a malicious assistant."})
        assert changed is True
