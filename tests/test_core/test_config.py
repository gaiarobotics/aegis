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
        assert cfg.scanner.sensitivity == 0.5

    def test_default_broker_posture(self):
        cfg = AegisConfig()
        assert cfg.broker.default_posture == "deny_write"

    def test_default_telemetry(self):
        cfg = AegisConfig()
        assert cfg.telemetry.local_log is True
        assert cfg.telemetry.remote_enabled is False


class TestLoadFromYaml:
    def test_load_yaml(self, tmp_path):
        yaml_content = "mode: enforce\nkillswitch: true\nscanner:\n  sensitivity: 0.9\n"
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text(yaml_content)
        cfg = load_config(str(config_file))
        assert cfg.mode == "enforce"
        assert cfg.killswitch is True
        assert cfg.scanner.sensitivity == 0.9

    def test_partial_yaml_uses_defaults(self, tmp_path):
        yaml_content = "mode: enforce\n"
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text(yaml_content)
        cfg = load_config(str(config_file))
        assert cfg.mode == "enforce"
        assert cfg.killswitch is False  # default
        assert cfg.scanner.sensitivity == 0.5  # default


class TestLoadFromJson:
    def test_load_json(self, tmp_path):
        data = {"mode": "enforce", "scanner": {"sensitivity": 0.8}}
        config_file = tmp_path / "aegis.json"
        config_file.write_text(json.dumps(data))
        cfg = load_config(str(config_file))
        assert cfg.mode == "enforce"
        assert cfg.scanner.sensitivity == 0.8


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
        assert cfg.scanner.sensitivity == 0.9


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


class TestDeepMerge:
    def test_deep_merge_preserves_unset_keys(self, tmp_path):
        yaml_content = "scanner:\n  sensitivity: 0.9\n"
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text(yaml_content)
        cfg = load_config(str(config_file))
        # sensitivity overridden
        assert cfg.scanner.sensitivity == 0.9
        # other scanner defaults preserved
        assert cfg.scanner.pattern_matching is True
        assert cfg.scanner.confidence_threshold == 0.7
        assert cfg.scanner.signatures.use_bundled is True

    def test_deep_merge_nested_dict(self, tmp_path):
        yaml_content = "scanner:\n  signatures:\n    remote_feed_enabled: true\n"
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text(yaml_content)
        cfg = load_config(str(config_file))
        # Overridden nested key
        assert cfg.scanner.signatures.remote_feed_enabled is True
        # Other nested defaults preserved
        assert cfg.scanner.signatures.use_bundled is True
        assert cfg.scanner.signatures.additional_files == []

    def test_deep_merge_broker_budgets(self, tmp_path):
        yaml_content = "broker:\n  budgets:\n    max_write_tool_calls: 50\n"
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text(yaml_content)
        cfg = load_config(str(config_file))
        assert cfg.broker.budgets.max_write_tool_calls == 50
        # Other budget defaults preserved
        assert cfg.broker.budgets.max_posts_messages == 5
        assert cfg.broker.default_posture == "deny_write"


class TestAllEnvVarOverrides:
    def test_killswitch_override_true(self, tmp_path, monkeypatch):
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text("killswitch: false\n")
        monkeypatch.setenv("AEGIS_KILLSWITCH", "true")
        cfg = load_config(str(config_file))
        assert cfg.killswitch is True

    def test_killswitch_override_false(self, tmp_path, monkeypatch):
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text("killswitch: true\n")
        monkeypatch.setenv("AEGIS_KILLSWITCH", "no")
        cfg = load_config(str(config_file))
        assert cfg.killswitch is False

    def test_scanner_confidence_threshold_override(self, tmp_path, monkeypatch):
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text("scanner:\n  confidence_threshold: 0.7\n")
        monkeypatch.setenv("AEGIS_SCANNER_CONFIDENCE_THRESHOLD", "0.85")
        cfg = load_config(str(config_file))
        assert cfg.scanner.confidence_threshold == 0.85

    def test_broker_default_posture_override(self, tmp_path, monkeypatch):
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text("broker:\n  default_posture: deny_write\n")
        monkeypatch.setenv("AEGIS_BROKER_DEFAULT_POSTURE", "allow_all")
        cfg = load_config(str(config_file))
        assert cfg.broker.default_posture == "allow_all"

    def test_behavior_drift_threshold_override(self, tmp_path, monkeypatch):
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text("behavior:\n  drift_threshold: 2.5\n")
        monkeypatch.setenv("AEGIS_BEHAVIOR_DRIFT_THRESHOLD", "4.0")
        cfg = load_config(str(config_file))
        assert cfg.behavior.drift_threshold == 4.0

    def test_behavior_window_size_override(self, tmp_path, monkeypatch):
        config_file = tmp_path / "aegis.yaml"
        config_file.write_text("behavior:\n  window_size: 100\n")
        monkeypatch.setenv("AEGIS_BEHAVIOR_WINDOW_SIZE", "200")
        cfg = load_config(str(config_file))
        assert cfg.behavior.window_size == 200


class TestPydanticFeatures:
    def test_json_schema_generation(self):
        schema = AegisConfig.model_json_schema()
        assert "properties" in schema
        assert "scanner" in schema["properties"]

    def test_unknown_keys_ignored(self):
        cfg = AegisConfig.model_validate({"mode": "enforce", "unknown_key": 42})
        assert cfg.mode == "enforce"

    def test_type_coercion(self):
        cfg = AegisConfig.model_validate({"scanner": {"sensitivity": "0.9"}})
        assert cfg.scanner.sensitivity == 0.9

    def test_nested_model_from_dict(self):
        cfg = AegisConfig.model_validate({
            "identity": {"trust": {"interaction_min_interval": 0.05}},
        })
        assert cfg.identity.trust.interaction_min_interval == 0.05
