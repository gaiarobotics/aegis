"""Tests for AEGIS OpenAI provider wrapper."""

from aegis.providers.base import WrappedClient
from aegis.providers.openai import OpenAIWrapper, detect_openai
from aegis.shield import Shield


class MockOpenAIClient:
    """Mock OpenAI client."""

    class chat:
        class completions:
            @staticmethod
            def create(**kwargs):
                return {"choices": [{"message": {"content": "Response"}}]}


class TestOpenAIWrapper:
    def test_wrap_returns_wrapped_client(self):
        shield = Shield(modules=["scanner"])
        wrapper = OpenAIWrapper(shield=shield)
        client = MockOpenAIClient()
        wrapped = wrapper.wrap(client)
        assert isinstance(wrapped, WrappedClient)
        assert wrapped.original is client


class TestDetectOpenAI:
    def test_detect_openai_by_name(self):
        class OpenAI:
            pass
        assert detect_openai(OpenAI()) is True

    def test_detect_non_openai(self):
        class SomeClient:
            pass
        assert detect_openai(SomeClient()) is False
