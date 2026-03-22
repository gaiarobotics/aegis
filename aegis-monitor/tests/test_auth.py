"""Tests for AEGIS monitor authentication and authorization."""

import os
import pytest
from monitor.config import MonitorConfig


class TestConfigMigration:
    def test_dict_api_keys(self, tmp_path):
        """New format: dict mapping keys to roles."""
        cfg_file = tmp_path / "monitor.yaml"
        cfg_file.write_text(
            'api_keys:\n  "sk-agent-1": agent\n  "sk-view-1": viewer\n  "sk-ops-1": operator\n'
        )
        cfg = MonitorConfig.load(cfg_file)
        assert cfg.api_keys == {"sk-agent-1": "agent", "sk-view-1": "viewer", "sk-ops-1": "operator"}

    def test_list_api_keys_migration(self, tmp_path):
        """Old format: list of strings treated as operator with warning."""
        cfg_file = tmp_path / "monitor.yaml"
        cfg_file.write_text('api_keys:\n  - "old-key-1"\n  - "old-key-2"\n')
        cfg = MonitorConfig.load(cfg_file)
        assert cfg.api_keys == {"old-key-1": "operator", "old-key-2": "operator"}

    def test_env_var_with_roles(self, monkeypatch):
        """Env var format: key:role,key:role."""
        monkeypatch.setenv("MONITOR_API_KEYS", "sk-a:agent,sk-v:viewer")
        cfg = MonitorConfig.load()
        assert cfg.api_keys == {"sk-a": "agent", "sk-v": "viewer"}

    def test_env_var_without_roles_migration(self, monkeypatch):
        """Env var old format: key,key treated as operator."""
        monkeypatch.setenv("MONITOR_API_KEYS", "old-key-1,old-key-2")
        cfg = MonitorConfig.load()
        assert cfg.api_keys == {"old-key-1": "operator", "old-key-2": "operator"}

    def test_session_secret_from_config(self, tmp_path):
        cfg_file = tmp_path / "monitor.yaml"
        cfg_file.write_text('session_secret: "my-secret-key"\nsession_ttl_seconds: 3600\n')
        cfg = MonitorConfig.load(cfg_file)
        assert cfg.session_secret == "my-secret-key"
        assert cfg.session_ttl_seconds == 3600

    def test_session_secret_default_empty(self):
        cfg = MonitorConfig.load()
        assert cfg.session_secret == ""

    def test_session_ttl_default(self):
        cfg = MonitorConfig.load()
        assert cfg.session_ttl_seconds == 28800


from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from monitor.auth import verify_api_key, require_role, get_config


def _make_app(api_keys: dict[str, str]) -> tuple[FastAPI, TestClient]:
    """Create a minimal FastAPI app with the given api_keys config."""
    test_app = FastAPI()
    cfg = MonitorConfig(api_keys=api_keys)
    test_app.state.config = cfg

    @test_app.get("/agent-only")
    async def agent_only(_role: str = Depends(require_role("agent", "operator"))):
        return {"role": _role}

    @test_app.get("/viewer-only")
    async def viewer_only(_role: str = Depends(require_role("viewer", "operator"))):
        return {"role": _role}

    @test_app.get("/operator-only")
    async def operator_only(_role: str = Depends(require_role("operator"))):
        return {"role": _role}

    return test_app, TestClient(test_app)


class TestRoleResolution:
    def test_open_mode_returns_open(self):
        _, client = _make_app({})
        resp = client.get("/agent-only")
        assert resp.status_code == 200
        assert resp.json()["role"] == "open"

    def test_agent_key_allowed_on_agent_endpoint(self):
        _, client = _make_app({"sk-a": "agent"})
        resp = client.get("/agent-only", headers={"Authorization": "Bearer sk-a"})
        assert resp.status_code == 200
        assert resp.json()["role"] == "agent"

    def test_agent_key_rejected_on_viewer_endpoint(self):
        _, client = _make_app({"sk-a": "agent"})
        resp = client.get("/viewer-only", headers={"Authorization": "Bearer sk-a"})
        assert resp.status_code == 403

    def test_agent_key_rejected_on_operator_endpoint(self):
        _, client = _make_app({"sk-a": "agent"})
        resp = client.get("/operator-only", headers={"Authorization": "Bearer sk-a"})
        assert resp.status_code == 403

    def test_viewer_key_allowed_on_viewer_endpoint(self):
        _, client = _make_app({"sk-v": "viewer"})
        resp = client.get("/viewer-only", headers={"Authorization": "Bearer sk-v"})
        assert resp.status_code == 200

    def test_viewer_key_rejected_on_operator_endpoint(self):
        _, client = _make_app({"sk-v": "viewer"})
        resp = client.get("/operator-only", headers={"Authorization": "Bearer sk-v"})
        assert resp.status_code == 403

    def test_operator_key_allowed_everywhere(self):
        _, client = _make_app({"sk-o": "operator"})
        for path in ["/agent-only", "/viewer-only", "/operator-only"]:
            resp = client.get(path, headers={"Authorization": "Bearer sk-o"})
            assert resp.status_code == 200, f"Failed on {path}"

    def test_invalid_key_rejected(self):
        _, client = _make_app({"sk-a": "agent"})
        resp = client.get("/agent-only", headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 403

    def test_missing_header_rejected(self):
        _, client = _make_app({"sk-a": "agent"})
        resp = client.get("/agent-only")
        assert resp.status_code == 401

    def test_timing_safe_comparison(self):
        """Verify we use hmac.compare_digest (not `in` or `==`)."""
        import inspect
        from monitor import auth
        source = inspect.getsource(auth.verify_api_key)
        assert "compare_digest" in source


import hashlib
import time

from monitor.auth import create_session_token, verify_session_token


class TestSessionTokens:
    SECRET = "test-secret-key"

    def test_roundtrip(self):
        token = create_session_token("viewer", "sk-view-1", self.SECRET)
        payload = verify_session_token(token, self.SECRET, ttl=3600)
        assert payload["role"] == "viewer"
        assert payload["key_hash"] == hashlib.sha256(b"sk-view-1").hexdigest()

    def test_expired_token_rejected(self):
        token = create_session_token("viewer", "sk-view-1", self.SECRET, issued_at=1000)
        payload = verify_session_token(token, self.SECRET, ttl=3600, now=5000)
        assert payload is None

    def test_tampered_token_rejected(self):
        token = create_session_token("viewer", "sk-view-1", self.SECRET)
        parts = token.split(".")
        parts[-1] = "a" + parts[-1][1:]
        tampered = ".".join(parts)
        payload = verify_session_token(tampered, self.SECRET, ttl=3600)
        assert payload is None

    def test_wrong_secret_rejected(self):
        token = create_session_token("viewer", "sk-view-1", self.SECRET)
        payload = verify_session_token(token, "wrong-secret", ttl=3600)
        assert payload is None

    def test_token_contains_key_hash(self):
        token = create_session_token("operator", "sk-ops-1", self.SECRET)
        payload = verify_session_token(token, self.SECRET, ttl=3600)
        expected_hash = hashlib.sha256(b"sk-ops-1").hexdigest()
        assert payload["key_hash"] == expected_hash
