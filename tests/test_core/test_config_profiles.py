"""Tests for config profile loading and deep merge."""

import pytest
import yaml

from aegis.core.config import AegisConfig, load_config, _deep_merge


class TestDeepMerge:
    def test_scalar_overlay_wins(self):
        base = {"a": 1, "b": 2}
        overlay = {"b": 99}
        result = _deep_merge(base, overlay)
        assert result == {"a": 1, "b": 99}

    def test_nested_dict_recursive(self):
        base = {"scanner": {"sensitivity": 0.5, "pattern_matching": True}}
        overlay = {"scanner": {"sensitivity": 0.75}}
        result = _deep_merge(base, overlay)
        assert result["scanner"]["sensitivity"] == 0.75
        assert result["scanner"]["pattern_matching"] is True

    def test_list_replaced_not_appended(self):
        base = {"items": [1, 2, 3]}
        overlay = {"items": [99]}
        result = _deep_merge(base, overlay)
        assert result["items"] == [99]

    def test_new_keys_added(self):
        base = {"a": 1}
        overlay = {"b": 2}
        result = _deep_merge(base, overlay)
        assert result == {"a": 1, "b": 2}

    def test_deeply_nested(self):
        base = {"a": {"b": {"c": 1, "d": 2}}}
        overlay = {"a": {"b": {"c": 99}}}
        result = _deep_merge(base, overlay)
        assert result["a"]["b"]["c"] == 99
        assert result["a"]["b"]["d"] == 2

    def test_base_not_mutated(self):
        base = {"a": {"b": 1}}
        overlay = {"a": {"b": 2}}
        _deep_merge(base, overlay)
        assert base["a"]["b"] == 1


class TestProfileLoading:
    def test_profiles_field_defaults_empty(self):
        config = AegisConfig()
        assert config.profiles == []

    def test_unknown_profile_raises(self, tmp_path):
        base = {"profiles": ["nonexistent_platform_xyz"]}
        base_file = tmp_path / "aegis.yaml"
        base_file.write_text(yaml.dump(base))
        with pytest.raises(FileNotFoundError):
            load_config(str(base_file))

    def test_load_profile_helper(self):
        """Verify _load_profile loads from the profiles directory."""
        from aegis.core.config import _load_profile, _PROFILES_DIR
        # This test will pass once the moltbook.yaml file exists (Task 2)
        # For now, just verify the function raises on missing profiles
        with pytest.raises(FileNotFoundError):
            _load_profile("definitely_not_a_real_profile")
