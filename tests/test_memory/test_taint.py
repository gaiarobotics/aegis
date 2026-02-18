"""Tests for aegis.memory.taint — TaintTracker provenance tracking."""
from __future__ import annotations

import time

from aegis.memory.guard import MemoryEntry
from aegis.memory.taint import TaintedEntry, TaintTracker


class TestTaintTracker:
    def _make_entry(self, **overrides) -> MemoryEntry:
        defaults = dict(
            key="user_name",
            value="Alice",
            category="fact",
            provenance="user",
            ttl=None,
            timestamp=time.time(),
        )
        defaults.update(overrides)
        return MemoryEntry(**defaults)

    def test_tag_marks_provenance(self):
        tracker = TaintTracker()
        entry = self._make_entry(provenance="user")
        tainted = tracker.tag(entry, provenance="tool_output")
        assert isinstance(tainted, TaintedEntry)
        assert tainted.provenance == "tool_output"
        assert tainted.entry is entry

    def test_is_tainted(self):
        tracker = TaintTracker()
        user_entry = self._make_entry(provenance="user")
        tool_entry = self._make_entry(provenance="tool_output")

        tracker.tag(user_entry, provenance="user")
        tracker.tag(tool_entry, provenance="tool_output")

        assert tracker.is_tainted(user_entry) is False
        assert tracker.is_tainted(tool_entry) is True

    def test_filter_removes_tainted_from_trusted(self):
        tracker = TaintTracker()
        user_entry = self._make_entry(key="a", provenance="user")
        tool_entry = self._make_entry(key="b", provenance="tool_output")

        tracker.tag(user_entry, provenance="user")
        tracker.tag(tool_entry, provenance="tool_output")

        result = tracker.filter_for_channel([user_entry, tool_entry], channel="trusted")
        assert len(result) == 1
        assert result[0] is user_entry

    def test_filter_keeps_all_for_data(self):
        tracker = TaintTracker()
        user_entry = self._make_entry(key="a", provenance="user")
        tool_entry = self._make_entry(key="b", provenance="tool_output")

        tracker.tag(user_entry, provenance="user")
        tracker.tag(tool_entry, provenance="tool_output")

        result = tracker.filter_for_channel([user_entry, tool_entry], channel="data")
        assert len(result) == 2

    def test_get_provenance(self):
        tracker = TaintTracker()
        entry = self._make_entry(provenance="user")
        tracker.tag(entry, provenance="tool_output")
        assert tracker.get_provenance(entry) == "tool_output"

    def test_untagged_entry_not_tainted(self):
        tracker = TaintTracker()
        entry = self._make_entry(provenance="user")
        assert tracker.is_tainted(entry) is False

    def test_tainted_entry_dataclass(self):
        entry = self._make_entry()
        te = TaintedEntry(entry=entry, provenance="tool_output", tainted=True)
        assert te.tainted is True
        assert te.provenance == "tool_output"


class TestEntryIdKey:
    """Tests that TaintTracker uses entry_id (not id()) as registry key."""

    def _make_entry(self, **overrides) -> MemoryEntry:
        defaults = dict(
            key="user_name",
            value="Alice",
            category="fact",
            provenance="user",
            ttl=None,
            timestamp=time.time(),
        )
        defaults.update(overrides)
        return MemoryEntry(**defaults)

    def test_entry_id_used_as_registry_key(self):
        """Verify taint uses entry_id, not id()."""
        tracker = TaintTracker()
        entry = self._make_entry()
        tracker.tag(entry, provenance="tool_output")

        # The registry key should be the entry_id string
        assert entry.entry_id in tracker._registry
        assert tracker.is_tainted(entry) is True
        assert tracker.get_provenance(entry) == "tool_output"

    def test_entry_id_survives_copy(self):
        """After copying an entry, taint is still found by entry_id."""
        import copy

        tracker = TaintTracker()
        entry = self._make_entry()
        tracker.tag(entry, provenance="tool_output")

        # Copy the entry — id() changes but entry_id stays the same
        copied = copy.copy(entry)
        assert copied is not entry
        assert copied.entry_id == entry.entry_id
        assert id(copied) != id(entry)

        # Taint should still be found via entry_id
        assert tracker.is_tainted(copied) is True
        assert tracker.get_provenance(copied) == "tool_output"
