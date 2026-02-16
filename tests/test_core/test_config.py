import json
import os
import tempfile
from pathlib import Path

from aegis.core.config import AegisConfig, load_config


class TestDefaultConfig:
    def test_default_mode(self):
        cfg = AegisConfig()
        assert cfg.mode == "observe"

    def test_default_killswitch_false(self):
        cfg = AegisConfig()
        assert cfg.killswitch is False

    def test_default_modules_all_true(self):
        cfg = AegisConfig()
        for mod in ("scanner", "broker", "identity", "memory", "behavior", "skills", "recovery"):
            assert cfg.modules[mod] is True

    def test_default_scanner_sensitivity(self):
        cfg = AegisConfig()
        assert cfg.scanner["sensitivity"] == 0.5

    def test_default_broker_posture(self):
        cfg = AegisConfig()
        assert cfg.broker["default_posture"] == "deny_write"

    def test_default_telemetry(self):
        cfg = AegisConfig()
        assert cfg.telemetry["local_log"] is True
        assert cfg.telemetry["remote_enabled"] is False


class TestLoadFromYaml:
    def test_load_yaml(self, tmp_path):
        yaml_content = "mode: enforce\nkillswitch: true\nscanner:\n  sensitivity: 0.9\n"
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text(yaml_content)
        cfg = load_config(str(config_file))
        assert cfg.mode == "enforce"
        assert cfg.killswitch is True
        assert cfg.scanner["sensitivity"] == 0.9

    def test_partial_yaml_uses_defaults(self, tmp_path):
        yaml_content = "mode: enforce\n"
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text(yaml_content)
        cfg = load_config(str(config_file))
        assert cfg.mode == "enforce"
        assert cfg.killswitch is False  # default
        assert cfg.scanner["sensitivity"] == 0.5  # default


class TestLoadFromJson:
    def test_load_json(self, tmp_path):
        data = {"mode": "enforce", "scanner": {"sensitivity": 0.8}}
        config_file = tmp_path / "aegis.json"
        config_file.write_text(json.dumps(data))
        cfg = load_config(str(config_file))
        assert cfg.mode == "enforce"
        assert cfg.scanner["sensitivity"] == 0.8


class TestEnvVarOverrides:
    def test_mode_override(self, tmp_path, monkeypatch):
        yaml_content = "mode: observe\n"
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text(yaml_content)
        monkeypatch.setenv("AEGIS_MODE", "enforce")
        cfg = load_config(str(config_file))
        assert cfg.mode == "enforce"

    def test_scanner_sensitivity_override(self, tmp_path, monkeypatch):
        yaml_content = "scanner:\n  sensitivity: 0.5\n"
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text(yaml_content)
        monkeypatch.setenv("AEGIS_SCANNER_SENSITIVITY", "0.9")
        cfg = load_config(str(config_file))
        assert cfg.scanner["sensitivity"] == 0.9


class TestAutoDiscovery:
    def test_discovers_yaml_in_dir(self, tmp_path, monkeypatch):
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text("mode: enforce\n")
        monkeypatch.chdir(tmp_path)
        cfg = load_config()
        assert cfg.mode == "enforce"

    def test_discovers_json_in_dir(self, tmp_path, monkeypatch):
        config_file = tmp_path / "aegis.json"
        config_file.write_text('{"mode": "enforce"}')
        monkeypatch.chdir(tmp_path)
        cfg = load_config()
        assert cfg.mode == "enforce"

    def test_yaml_preferred_over_json(self, tmp_path, monkeypatch):
        (tmp_path / "aegis.yaml").write_text("mode: enforce\n")
        (tmp_path / "aegis.json").write_text('{"mode": "observe"}')
        monkeypatch.chdir(tmp_path)
        cfg = load_config()
        assert cfg.mode == "enforce"

    def test_no_config_uses_defaults(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = load_config()
        assert cfg.mode == "observe"


class TestUnknownSections:
    def test_unknown_sections_ignored(self, tmp_path):
        yaml_content = "mode: enforce\nunknown_module:\n  foo: bar\n"
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text(yaml_content)
        cfg = load_config(str(config_file))
        assert cfg.mode == "enforce"


class TestModuleEnabled:
    def test_module_enabled(self):
        cfg = AegisConfig()
        assert cfg.is_module_enabled("scanner") is True

    def test_module_disabled(self):
        cfg = AegisConfig()
        cfg.modules["scanner"] = False
        assert cfg.is_module_enabled("scanner") is False

    def test_unknown_module_disabled(self):
        cfg = AegisConfig()
        assert cfg.is_module_enabled("nonexistent") is False
