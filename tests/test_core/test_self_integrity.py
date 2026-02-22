"""Tests for self-integrity monitoring."""

import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.config import SelfIntegrityConfig
from aegis.core.self_integrity import SelfIntegrityWatcher


@pytest.fixture
def package_dir(tmp_path):
    """Create a minimal fake package directory."""
    pkg = tmp_path / "fake_pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("# init\n")
    (pkg / "module_a.py").write_text("def hello(): pass\n")
    (pkg / "module_b.py").write_text("class Foo: pass\n")
    sub = pkg / "sub"
    sub.mkdir()
    (sub / "__init__.py").write_text("")
    (sub / "deep.py").write_text("x = 1\n")
    return pkg


@pytest.fixture
def config_file(tmp_path):
    """Create a fake config file."""
    cfg = tmp_path / "aegis.yaml"
    cfg.write_text("mode: enforce\n")
    return cfg


class TestBaselines:
    def test_baseline_computed(self, package_dir):
        cfg = SelfIntegrityConfig(enabled=True, watch_package=True)
        watcher = SelfIntegrityWatcher(
            config=cfg, package_dir=package_dir,
        )
        baselines = watcher.baselines
        # Should have all .py files
        py_files = list(package_dir.rglob("*.py"))
        assert len(baselines) == len(py_files)
        for py in py_files:
            assert str(py) in baselines

    def test_config_file_monitored(self, package_dir, config_file):
        cfg = SelfIntegrityConfig(enabled=True, watch_config=True)
        watcher = SelfIntegrityWatcher(
            config=cfg, package_dir=package_dir, config_path=str(config_file),
        )
        assert str(config_file) in watcher.baselines

    def test_watch_package_false(self, package_dir, config_file):
        cfg = SelfIntegrityConfig(enabled=True, watch_package=False, watch_config=True)
        watcher = SelfIntegrityWatcher(
            config=cfg, package_dir=package_dir, config_path=str(config_file),
        )
        baselines = watcher.baselines
        # Only the config file should be baselined
        assert len(baselines) == 1
        assert str(config_file) in baselines

    def test_watch_config_false(self, package_dir, config_file):
        cfg = SelfIntegrityConfig(enabled=True, watch_package=True, watch_config=False)
        watcher = SelfIntegrityWatcher(
            config=cfg, package_dir=package_dir, config_path=str(config_file),
        )
        assert str(config_file) not in watcher.baselines
        assert len(watcher.baselines) > 0  # package files present

    def test_empty_config_path(self, package_dir):
        cfg = SelfIntegrityConfig(enabled=True, watch_package=True, watch_config=True)
        watcher = SelfIntegrityWatcher(
            config=cfg, package_dir=package_dir, config_path="",
        )
        # No crash, just no config file in baselines
        py_files = list(package_dir.rglob("*.py"))
        assert len(watcher.baselines) == len(py_files)


class TestTamperDetection:
    def test_no_tamper_no_callback(self, package_dir):
        callback = MagicMock()
        cfg = SelfIntegrityConfig(enabled=True, watch_package=True, check_interval_seconds=1)
        watcher = SelfIntegrityWatcher(
            config=cfg, package_dir=package_dir, on_tamper=callback,
        )
        watcher._check_once()
        callback.assert_not_called()

    def test_tamper_triggers_callback(self, package_dir):
        callback = MagicMock()
        cfg = SelfIntegrityConfig(enabled=True, watch_package=True, check_interval_seconds=1)
        watcher = SelfIntegrityWatcher(
            config=cfg, package_dir=package_dir, on_tamper=callback,
        )

        # Modify a file
        target = package_dir / "module_a.py"
        target.write_text("def hello(): return 'hacked'\n")

        watcher._check_once()
        callback.assert_called_once()
        assert str(target) in callback.call_args[0][0]

    def test_deleted_file_triggers_callback(self, package_dir):
        callback = MagicMock()
        cfg = SelfIntegrityConfig(enabled=True, watch_package=True, check_interval_seconds=1)
        watcher = SelfIntegrityWatcher(
            config=cfg, package_dir=package_dir, on_tamper=callback,
        )

        # Delete a file
        target = package_dir / "module_b.py"
        target.unlink()

        watcher._check_once()
        callback.assert_called_once()
        assert str(target) in callback.call_args[0][0]

    def test_config_file_tamper(self, package_dir, config_file):
        callback = MagicMock()
        cfg = SelfIntegrityConfig(enabled=True, watch_package=True, check_interval_seconds=1)
        watcher = SelfIntegrityWatcher(
            config=cfg, package_dir=package_dir,
            config_path=str(config_file), on_tamper=callback,
        )

        # Modify config
        config_file.write_text("mode: observe\n")

        watcher._check_once()
        callback.assert_called_once()
        assert str(config_file) in callback.call_args[0][0]


class TestBackgroundThread:
    def test_start_stop(self, package_dir):
        cfg = SelfIntegrityConfig(enabled=True, watch_package=True, check_interval_seconds=60)
        watcher = SelfIntegrityWatcher(
            config=cfg, package_dir=package_dir,
        )
        watcher.start()
        assert watcher._thread is not None
        assert watcher._thread.is_alive()
        watcher.stop()
        assert not watcher._thread.is_alive()

    def test_background_detects_tamper(self, package_dir):
        callback = MagicMock()
        cfg = SelfIntegrityConfig(enabled=True, watch_package=True, check_interval_seconds=0.1)
        watcher = SelfIntegrityWatcher(
            config=cfg, package_dir=package_dir, on_tamper=callback,
        )
        watcher.start()
        try:
            # Modify a file
            target = package_dir / "module_a.py"
            target.write_text("TAMPERED\n")

            # Wait for detection
            for _ in range(50):
                if callback.called:
                    break
                time.sleep(0.05)

            callback.assert_called_once()
        finally:
            watcher.stop()

    def test_disabled_config_no_thread(self, package_dir):
        cfg = SelfIntegrityConfig(enabled=False, watch_package=True)
        # Watcher can still be created, but Shield won't start it
        watcher = SelfIntegrityWatcher(
            config=cfg, package_dir=package_dir,
        )
        # baselines still computed if watch_package=True
        assert len(watcher.baselines) > 0


class TestShieldIntegration:
    def test_shield_exit_on_tamper(self, package_dir):
        """Verify _on_self_tamper with on_tamper='exit' calls os._exit(78)."""
        from aegis.core.config import AegisConfig
        from aegis.shield import Shield

        config = AegisConfig(
            self_integrity=SelfIntegrityConfig(enabled=False),
            modules={},  # disable all modules
        )
        shield = Shield(config=config)
        # Manually set the on_tamper config to test callback
        shield._config.self_integrity.on_tamper = "exit"

        with patch("aegis.shield.os._exit") as mock_exit:
            shield._on_self_tamper("/fake/path.py")
            mock_exit.assert_called_once_with(78)

    def test_shield_block_on_tamper(self, package_dir):
        """Verify _on_self_tamper with on_tamper='block' sets flag."""
        from aegis.core.config import AegisConfig
        from aegis.shield import Shield, InferenceBlockedError

        config = AegisConfig(
            self_integrity=SelfIntegrityConfig(enabled=False),
            modules={},
        )
        shield = Shield(config=config)
        shield._config.self_integrity.on_tamper = "block"

        assert not shield._self_integrity_blocked
        shield._on_self_tamper("/fake/path.py")
        assert shield._self_integrity_blocked
        assert shield.is_blocked

        with pytest.raises(InferenceBlockedError, match="tampered"):
            shield.check_killswitch()

    def test_shield_log_on_tamper(self, package_dir):
        """Verify _on_self_tamper with on_tamper='log' just logs."""
        from aegis.core.config import AegisConfig
        from aegis.shield import Shield

        config = AegisConfig(
            self_integrity=SelfIntegrityConfig(enabled=False),
            modules={},
        )
        shield = Shield(config=config)
        shield._config.self_integrity.on_tamper = "log"

        # Should not raise or exit
        shield._on_self_tamper("/fake/path.py")
        assert not shield._self_integrity_blocked
