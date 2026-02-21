"""Tests for ContextRollback."""

import pytest

from aegis.recovery.rollback import ContextRollback, SnapshotInfo


class TestContextRollback:
    """Tests for the ContextRollback class."""

    def test_save_and_rollback(self):
        """Test saving a snapshot and rolling back to it."""
        rb = ContextRollback()
        ctx = {"key": "value", "nested": {"a": 1}}

        snapshot_id = rb.save_snapshot(ctx, snapshot_id="snap1", description="first")
        assert snapshot_id == "snap1"

        # Mutate original context
        ctx["key"] = "changed"
        ctx["nested"]["a"] = 99

        restored = rb.rollback("snap1")
        assert restored["key"] == "value"
        assert restored["nested"]["a"] == 1

        # Ensure returned copy is independent
        restored["key"] = "modified"
        restored2 = rb.rollback("snap1")
        assert restored2["key"] == "value"

    def test_rollback_nonexistent_raises(self):
        """Test that rollback raises KeyError for nonexistent snapshot."""
        rb = ContextRollback()

        with pytest.raises(KeyError):
            rb.rollback("nonexistent")

    def test_list_snapshots(self):
        """Test listing snapshots returns correct info."""
        rb = ContextRollback()
        rb.save_snapshot({"a": 1}, snapshot_id="s1", description="first snapshot")
        rb.save_snapshot({"b": 2}, snapshot_id="s2", description="second snapshot")

        snapshots = rb.list_snapshots()
        assert len(snapshots) == 2
        assert all(isinstance(s, SnapshotInfo) for s in snapshots)

        ids = [s.snapshot_id for s in snapshots]
        assert "s1" in ids
        assert "s2" in ids

        for s in snapshots:
            assert isinstance(s.timestamp, float)
            assert s.timestamp > 0

    def test_auto_generated_id(self):
        """Test that snapshot_id is auto-generated when not provided."""
        rb = ContextRollback()
        sid = rb.save_snapshot({"x": 42}, description="auto id test")

        assert sid is not None
        assert isinstance(sid, str)
        assert len(sid) > 0

        restored = rb.rollback(sid)
        assert restored == {"x": 42}

        snapshots = rb.list_snapshots()
        assert len(snapshots) == 1
        assert snapshots[0].snapshot_id == sid
        assert snapshots[0].description == "auto id test"


class TestSnapshotCap:
    """Tests for the max_snapshots eviction behaviour."""

    def test_default_max_snapshots(self):
        """Default max_snapshots is 50."""
        rb = ContextRollback()
        assert rb._max_snapshots == 50

    def test_custom_max_snapshots(self):
        """Custom max_snapshots value is honoured."""
        rb = ContextRollback(max_snapshots=10)
        assert rb._max_snapshots == 10

    def test_oldest_evicted(self):
        """When exceeding max, the oldest snapshot is evicted."""
        rb = ContextRollback(max_snapshots=3)

        rb.save_snapshot({"v": 1}, snapshot_id="s1")
        rb.save_snapshot({"v": 2}, snapshot_id="s2")
        rb.save_snapshot({"v": 3}, snapshot_id="s3")

        assert len(rb._snapshots) == 3

        # Adding a 4th should evict s1
        rb.save_snapshot({"v": 4}, snapshot_id="s4")
        assert len(rb._snapshots) == 3
        assert "s1" not in rb._snapshots
        assert "s2" in rb._snapshots
        assert "s3" in rb._snapshots
        assert "s4" in rb._snapshots

        # s1 should no longer be rollback-able
        with pytest.raises(KeyError):
            rb.rollback("s1")

        # s2, s3, s4 should still work
        assert rb.rollback("s2") == {"v": 2}
        assert rb.rollback("s3") == {"v": 3}
        assert rb.rollback("s4") == {"v": 4}
