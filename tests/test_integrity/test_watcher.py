"""Tests for aegis.integrity.watcher (Linux inotify).

All tests are skipped on non-Linux platforms.
"""

from __future__ import annotations

import platform
import threading
import time

import pytest

pytestmark = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="inotify is only available on Linux",
)


@pytest.fixture
def watcher_factory(tmp_path):
    """Create watchers with cleanup."""
    watchers = []

    def factory(callback):
        from aegis.integrity.watcher import InotifyWatcher

        stop = threading.Event()
        w = InotifyWatcher(callback=callback, stop_event=stop)
        watchers.append(w)
        return w

    yield factory

    for w in watchers:
        try:
            w.stop()
        except Exception:
            pass


class TestInotifyWatcher:
    def test_file_modification_detected(self, tmp_path, watcher_factory):
        """Modification of a watched file triggers callback."""
        test_file = tmp_path / "model.bin"
        test_file.write_bytes(b"original")

        events = []

        def on_event(file_path, model_name):
            events.append((file_path, model_name))

        watcher = watcher_factory(on_event)
        watcher.start()
        watcher.add_watch(str(test_file), "test-model")

        # Modify the file
        time.sleep(0.1)
        test_file.write_bytes(b"modified content")
        time.sleep(1.0)  # wait for event processing

        assert len(events) > 0
        assert events[0][1] == "test-model"

    def test_file_deletion_detected(self, tmp_path, watcher_factory):
        """Deletion of a watched file triggers callback."""
        test_file = tmp_path / "model.bin"
        test_file.write_bytes(b"data")

        events = []

        def on_event(file_path, model_name):
            events.append((file_path, model_name))

        watcher = watcher_factory(on_event)
        watcher.start()
        watcher.add_watch(str(test_file), "test-model")

        time.sleep(0.1)
        test_file.unlink()
        time.sleep(1.0)

        assert len(events) > 0

    def test_clean_stop(self, watcher_factory):
        """Watcher stops cleanly without errors."""
        watcher = watcher_factory(lambda fp, mn: None)
        watcher.start()
        time.sleep(0.1)
        watcher.stop()
        assert not watcher._thread.is_alive()

    def test_multiple_watches(self, tmp_path, watcher_factory):
        """Can watch multiple files simultaneously."""
        file1 = tmp_path / "model1.bin"
        file2 = tmp_path / "model2.bin"
        file1.write_bytes(b"data1")
        file2.write_bytes(b"data2")

        events = []

        def on_event(file_path, model_name):
            events.append(model_name)

        watcher = watcher_factory(on_event)
        watcher.start()
        watcher.add_watch(str(file1), "model1")
        watcher.add_watch(str(file2), "model2")

        time.sleep(0.1)
        file1.write_bytes(b"modified1")
        time.sleep(0.5)
        file2.write_bytes(b"modified2")
        time.sleep(1.0)

        model_names = set(events)
        assert "model1" in model_names
        assert "model2" in model_names
