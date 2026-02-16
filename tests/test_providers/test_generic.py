"""Tests for AEGIS generic provider wrapper."""

from aegis.providers.base import WrappedClient
from aegis.providers.generic import GenericWrapper, detect_generic
from aegis.shield import Shield


class MockCreateClient:
    """Client with create() method."""

    def create(self, **kwargs):
        return {"result": "created"}


class MockGenerateClient:
    """Client with generate() method."""

    def generate(self, prompt):
        return f"Generated: {prompt}"


class MockBareClient:
    """Client with neither create() nor generate()."""
    pass


class TestGenericWrapper:
    def test_wrap_returns_wrapped_client(self):
        shield = Shield(modules=["scanner"])
        wrapper = GenericWrapper(shield=shield)
        client = MockCreateClient()
        wrapped = wrapper.wrap(client)
        assert isinstance(wrapped, WrappedClient)
        assert wrapped.original is client

    def test_wrap_with_tools(self):
        shield = Shield(modules=[])
        wrapper = GenericWrapper(shield=shield)
        client = MockCreateClient()
        tools = [{"name": "tool1"}]
        wrapped = wrapper.wrap(client, tools=tools)
        assert isinstance(wrapped, WrappedClient)

    def test_wrapped_create_client_delegates(self):
        shield = Shield(modules=[])
        wrapper = GenericWrapper(shield=shield)
        client = MockCreateClient()
        wrapped = wrapper.wrap(client)
        result = wrapped.create(prompt="test")
        assert result == {"result": "created"}

    def test_wrapped_generate_client_delegates(self):
        shield = Shield(modules=[])
        wrapper = GenericWrapper(shield=shield)
        client = MockGenerateClient()
        wrapped = wrapper.wrap(client)
        result = wrapped.generate("hello")
        assert result == "Generated: hello"


class TestDetectGeneric:
    def test_detect_create_client(self):
        assert detect_generic(MockCreateClient()) is True

    def test_detect_generate_client(self):
        assert detect_generic(MockGenerateClient()) is True

    def test_detect_bare_client(self):
        assert detect_generic(MockBareClient()) is False
