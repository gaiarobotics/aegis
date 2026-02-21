"""Tests for AEGIS top-level API."""

import aegis
from aegis.providers.base import WrappedClient


class MockClient:
    """Mock LLM client for API testing."""

    def create(self, **kwargs):
        return {"content": "response"}


class TestTopLevelAPI:
    def test_version_accessible(self):
        assert hasattr(aegis, "__version__")
        assert aegis.__version__ == "0.1.0"

    def test_shield_constructor(self):
        shield = aegis.Shield()
        assert shield.mode == "enforce"

    def test_shield_with_mode(self):
        shield = aegis.Shield(mode="enforce")
        assert shield.mode == "enforce"

    def test_shield_with_modules(self):
        shield = aegis.Shield(modules=["scanner"])
        assert shield.config.is_module_enabled("scanner") is True
        assert shield.config.is_module_enabled("broker") is False

    def test_killswitch_accessible(self):
        assert hasattr(aegis, "killswitch")
        assert hasattr(aegis.killswitch, "is_active")
        assert hasattr(aegis.killswitch, "activate")
        assert hasattr(aegis.killswitch, "deactivate")

    def test_wrap_returns_wrapped_client(self):
        client = MockClient()
        wrapped = aegis.wrap(client)
        assert isinstance(wrapped, WrappedClient)

    def test_wrap_with_mode(self):
        client = MockClient()
        wrapped = aegis.wrap(client, mode="enforce")
        assert isinstance(wrapped, WrappedClient)

    def test_wrap_preserves_client_api(self):
        client = MockClient()
        wrapped = aegis.wrap(client)
        result = wrapped.create(prompt="test")
        assert result == {"content": "response"}

    def test_shield_wrap(self):
        shield = aegis.Shield(modules=["scanner"])
        client = MockClient()
        wrapped = shield.wrap(client)
        assert isinstance(wrapped, WrappedClient)


class TestWrapKwargs:
    def test_wrap_with_modules(self):
        client = MockClient()
        wrapped = aegis.wrap(client, modules=["scanner"])
        assert isinstance(wrapped, WrappedClient)

    def test_wrap_with_policy(self, tmp_path):
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text("mode: enforce\n")
        client = MockClient()
        wrapped = aegis.wrap(client, policy=str(config_file))
        assert isinstance(wrapped, WrappedClient)

    def test_wrap_with_config(self):
        from aegis.core.config import AegisConfig
        cfg = AegisConfig(mode="enforce")
        client = MockClient()
        wrapped = aegis.wrap(client, config=cfg)
        assert isinstance(wrapped, WrappedClient)
