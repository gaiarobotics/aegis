import os
import threading
from aegis.core import killswitch


class TestKillswitch:
    def setup_method(self):
        killswitch.deactivate()
        os.environ.pop("AEGIS_KILLSWITCH", None)
        killswitch.set_config_override(None)
        killswitch._local.forced = False

    def test_default_inactive(self):
        assert killswitch.is_active() is False

    def test_env_var_activates(self):
        os.environ["AEGIS_KILLSWITCH"] = "1"
        assert killswitch.is_active() is True

    def test_env_var_zero_inactive(self):
        os.environ["AEGIS_KILLSWITCH"] = "0"
        assert killswitch.is_active() is False

    def test_programmatic_activate(self):
        killswitch.activate()
        assert killswitch.is_active() is True

    def test_programmatic_deactivate(self):
        killswitch.activate()
        killswitch.deactivate()
        assert killswitch.is_active() is False

    def test_config_override(self):
        killswitch.set_config_override(True)
        assert killswitch.is_active() is True

    def test_config_override_false(self):
        killswitch.set_config_override(False)
        assert killswitch.is_active() is False

    def test_config_override_none_clears(self):
        killswitch.set_config_override(True)
        killswitch.set_config_override(None)
        assert killswitch.is_active() is False

    def test_context_manager_disabled(self):
        assert killswitch.is_active() is False
        with killswitch.disabled():
            assert killswitch.is_active() is True
        assert killswitch.is_active() is False

    def test_context_manager_thread_local(self):
        results = {}

        def check_in_thread():
            results["thread"] = killswitch.is_active()

        with killswitch.disabled():
            t = threading.Thread(target=check_in_thread)
            t.start()
            t.join()
            assert results["thread"] is False  # Not active in other thread
            assert killswitch.is_active() is True  # Active in this thread

    def test_any_source_activates(self):
        """Any single activation source should make is_active() True."""
        killswitch.activate()
        assert killswitch.is_active() is True

    def test_reset(self):
        killswitch.activate()
        killswitch.set_config_override(True)
        killswitch._reset()
        assert killswitch.is_active() is False
