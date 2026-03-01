"""Tests for preset management."""

from __future__ import annotations

import pytest

from monitor.simulator.models import SimConfig
from monitor.simulator.presets import PresetManager


# ---------------------------------------------------------------------------
# TestPresetManager
# ---------------------------------------------------------------------------


class TestPresetManager:
    """Tests for user-dir preset CRUD operations."""

    @pytest.fixture()
    def manager(self, tmp_path):
        """Return a PresetManager that uses a temporary user directory."""
        return PresetManager(preset_dir=str(tmp_path))

    def test_list_empty(self, manager):
        """A fresh user dir (no builtins loaded) should still list builtins."""
        names = manager.list_presets()
        # Builtins exist, so the list is never truly empty when builtins ship.
        # But no *user* presets have been saved yet.  We just verify it returns
        # a list (builtins are tested separately).
        assert isinstance(names, list)

    def test_save_and_load(self, manager):
        cfg = SimConfig(num_agents=200, seed=42)
        manager.save("my-test", cfg)
        loaded = manager.load("my-test")
        assert loaded.num_agents == 200
        assert loaded.seed == 42

    def test_list_after_save(self, manager):
        cfg = SimConfig(num_agents=200, seed=42)
        manager.save("alpha", cfg)
        names = manager.list_presets()
        assert "alpha" in names

    def test_delete(self, manager):
        cfg = SimConfig(num_agents=50)
        manager.save("to-delete", cfg)
        assert "to-delete" in manager.list_presets()
        manager.delete("to-delete")
        assert "to-delete" not in manager.list_presets()

    def test_load_nonexistent_raises(self, manager):
        with pytest.raises(FileNotFoundError):
            manager.load("does-not-exist")

    def test_delete_nonexistent_raises(self, manager):
        with pytest.raises(FileNotFoundError):
            manager.delete("does-not-exist")


# ---------------------------------------------------------------------------
# TestBuiltinPresets
# ---------------------------------------------------------------------------


class TestBuiltinPresets:
    """Tests for the builtin YAML presets that ship with the package."""

    @pytest.fixture()
    def manager(self):
        """Return a PresetManager with no user dir (builtins only)."""
        return PresetManager()

    def test_builtin_presets_exist(self, manager):
        names = manager.list_presets()
        assert "moltbook-default" in names
        assert "no-aegis-baseline" in names

    def test_load_moltbook_default(self, manager):
        cfg = manager.load("moltbook-default")
        assert cfg.num_agents == 500
        assert cfg.topology.type == "scale_free"

    def test_load_no_aegis_baseline(self, manager):
        cfg = manager.load("no-aegis-baseline")
        assert cfg.modules.scanner is False
        assert cfg.modules.broker is False
        assert cfg.modules.identity is False
        assert cfg.modules.behavior is False
        assert cfg.modules.recovery is False

    def test_load_moltbook_outbreak(self, manager):
        cfg = manager.load("moltbook-outbreak")
        assert cfg.num_agents == 500
        assert cfg.max_ticks == 300
        assert cfg.initial_infected_pct == 0.05
        assert cfg.seed_strategy == "hubs"
        assert cfg.topology.m == 5

    def test_load_scanner_only(self, manager):
        cfg = manager.load("scanner-only")
        assert cfg.modules.scanner is True
        assert cfg.modules.broker is False
        assert cfg.modules.identity is False
        assert cfg.modules.behavior is False
        assert cfg.modules.recovery is False
        assert cfg.modules.scanner_toggles.content_gate is False
