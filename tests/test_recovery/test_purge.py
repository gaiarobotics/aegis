"""Tests for MemoryPurge."""

import time

import pytest

from aegis.recovery.purge import MemoryPurge, PurgeResult


class TestMemoryPurge:
    """Tests for the MemoryPurge class."""

    def test_purge_tainted(self):
        """Test purging tainted entries within the time window."""
        mp = MemoryPurge()
        now = time.time()

        entries = {
            "a": {"tainted": True, "timestamp": now - 3600, "data": "bad"},
            "b": {"tainted": False, "timestamp": now - 3600, "data": "good"},
            "c": {"tainted": True, "timestamp": now - 7200, "data": "also bad"},
        }

        result = mp.purge_tainted(entries, window_hours=24)

        assert isinstance(result, PurgeResult)
        assert result.purged_count == 2
        assert set(result.purged_keys) == {"a", "c"}
        assert "a" not in entries
        assert "b" in entries
        assert "c" not in entries

    def test_purge_by_provenance(self):
        """Test purging entries by provenance."""
        mp = MemoryPurge()

        entries = {
            "x": {"provenance": "external", "data": "ext1"},
            "y": {"provenance": "internal", "data": "int1"},
            "z": {"provenance": "external", "data": "ext2"},
        }

        result = mp.purge_by_provenance(entries, provenance="external")

        assert isinstance(result, PurgeResult)
        assert result.purged_count == 2
        assert set(result.purged_keys) == {"x", "z"}
        assert "x" not in entries
        assert "y" in entries
        assert "z" not in entries

    def test_purge_respects_window(self):
        """Test that purge_tainted respects the time window."""
        mp = MemoryPurge()
        now = time.time()

        entries = {
            "recent": {"tainted": True, "timestamp": now - 3600, "data": "recent bad"},
            "old": {"tainted": True, "timestamp": now - 100000, "data": "old bad"},
            "clean": {"tainted": False, "timestamp": now - 100, "data": "clean"},
        }

        # Window of 2 hours = 7200 seconds; "old" is ~27.8 hours old so outside window
        result = mp.purge_tainted(entries, window_hours=2)

        assert result.purged_count == 1
        assert result.purged_keys == ["recent"]
        assert "recent" not in entries
        assert "old" in entries  # outside window, not purged
        assert "clean" in entries  # not tainted

    def test_purge_tainted_empty(self):
        """Test purging an empty dict."""
        mp = MemoryPurge()
        entries = {}
        result = mp.purge_tainted(entries, window_hours=24)
        assert result.purged_count == 0
        assert result.purged_keys == []

    def test_purge_by_provenance_no_match(self):
        """Test purging by provenance with no matching entries."""
        mp = MemoryPurge()
        entries = {
            "a": {"provenance": "internal", "data": "int"},
        }
        result = mp.purge_by_provenance(entries, provenance="external")
        assert result.purged_count == 0
        assert result.purged_keys == []
        assert "a" in entries
