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
