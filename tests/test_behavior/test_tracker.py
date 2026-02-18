"""Tests for behavior tracker."""

import threading
import time

from aegis.behavior.tracker import BehaviorEvent, BehaviorFingerprint, BehaviorTracker


def _make_event(
    agent_id="agent-1",
    event_type="message",
    output_length=100,
    tool_used=None,
    content_type="text",
    target=None,
    timestamp=None,
):
    return BehaviorEvent(
        agent_id=agent_id,
        timestamp=timestamp if timestamp is not None else time.time(),
        event_type=event_type,
        output_length=output_length,
        tool_used=tool_used,
        content_type=content_type,
        target=target,
    )


class TestRecordAndFingerprint:
    def test_record_and_fingerprint(self):
        tracker = BehaviorTracker()
        events = [
            _make_event(output_length=100, tool_used="search", content_type="text", target="a.com"),
            _make_event(output_length=200, tool_used="search", content_type="code", target="b.com"),
            _make_event(output_length=150, tool_used="write", content_type="text", target="a.com"),
        ]
        for e in events:
            tracker.record_event(e)

        fp = tracker.get_fingerprint("agent-1")

        assert isinstance(fp, BehaviorFingerprint)
        assert fp.event_count == 3

        # output_length stats
        ol = fp.dimensions["output_length"]
        assert ol["mean"] == 150.0  # (100+200+150)/3
        assert ol["std"] > 0

        # tool_distribution
        td = fp.dimensions["tool_distribution"]
        assert "search" in td
        assert "write" in td
        assert abs(td["search"] - 2 / 3) < 1e-9
        assert abs(td["write"] - 1 / 3) < 1e-9

        # content_ratios
        cr = fp.dimensions["content_ratios"]
        assert abs(cr["text"] - 2 / 3) < 1e-9
        assert abs(cr["code"] - 1 / 3) < 1e-9

        # unique_targets
        ut = fp.dimensions["unique_targets"]
        assert ut["count"] == 2  # a.com, b.com

        # fingerprint_hash is a non-empty string
        assert isinstance(fp.fingerprint_hash, str)
        assert len(fp.fingerprint_hash) > 0


class TestRollingWindow:
    def test_rolling_window(self):
        tracker = BehaviorTracker(config={"window_size": 5})

        # Add 5 events with output_length=100
        for _ in range(5):
            tracker.record_event(_make_event(output_length=100))

        fp1 = tracker.get_fingerprint("agent-1")
        assert fp1.event_count == 5
        assert fp1.dimensions["output_length"]["mean"] == 100.0

        # Add 5 more events with output_length=200 (old ones should drop off)
        for _ in range(5):
            tracker.record_event(_make_event(output_length=200))

        fp2 = tracker.get_fingerprint("agent-1")
        assert fp2.event_count == 5
        assert fp2.dimensions["output_length"]["mean"] == 200.0


class TestFingerprintHashChanges:
    def test_fingerprint_hash_changes(self):
        tracker = BehaviorTracker()

        tracker.record_event(_make_event(output_length=100, tool_used="search"))
        tracker.record_event(_make_event(output_length=100, tool_used="search"))
        fp1 = tracker.get_fingerprint("agent-1")

        # Add a very different event
        tracker.record_event(_make_event(output_length=9999, tool_used="delete"))
        fp2 = tracker.get_fingerprint("agent-1")

        assert fp1.fingerprint_hash != fp2.fingerprint_hash


class TestMultipleAgents:
    def test_multiple_agents(self):
        tracker = BehaviorTracker()

        tracker.record_event(_make_event(agent_id="agent-1", output_length=100, tool_used="search"))
        tracker.record_event(_make_event(agent_id="agent-2", output_length=500, tool_used="write"))

        fp1 = tracker.get_fingerprint("agent-1")
        fp2 = tracker.get_fingerprint("agent-2")

        assert fp1.event_count == 1
        assert fp2.event_count == 1
        assert fp1.dimensions["output_length"]["mean"] == 100.0
        assert fp2.dimensions["output_length"]["mean"] == 500.0
        assert "search" in fp1.dimensions["tool_distribution"]
        assert "write" in fp2.dimensions["tool_distribution"]
        assert "write" not in fp1.dimensions["tool_distribution"]
        assert "search" not in fp2.dimensions["tool_distribution"]


class TestMaxTrackedAgents:
    def test_default_max_agents(self):
        tracker = BehaviorTracker()
        assert tracker._max_agents == 10000

    def test_custom_max_agents(self):
        tracker = BehaviorTracker(config={"max_tracked_agents": 5})
        assert tracker._max_agents == 5

    def test_rejects_events_beyond_max_agents(self):
        tracker = BehaviorTracker(config={"max_tracked_agents": 3})

        # Add events from 3 agents — all should be accepted
        for i in range(3):
            tracker.record_event(_make_event(agent_id=f"agent-{i}"))

        assert len(tracker._events) == 3

        # Fourth agent should be rejected
        tracker.record_event(_make_event(agent_id="agent-new"))
        assert "agent-new" not in tracker._events
        assert len(tracker._events) == 3

    def test_existing_agents_still_accepted_at_limit(self):
        tracker = BehaviorTracker(config={"max_tracked_agents": 2})

        tracker.record_event(_make_event(agent_id="agent-1"))
        tracker.record_event(_make_event(agent_id="agent-2"))

        # Existing agent should still be accepted
        tracker.record_event(_make_event(agent_id="agent-1", output_length=999))
        fp = tracker.get_fingerprint("agent-1")
        assert fp.event_count == 2


class TestAnchorBaseline:
    def test_anchor_created_after_window(self):
        """After anchor_window events, anchor is frozen."""
        tracker = BehaviorTracker(config={"anchor_window": 10})
        for i in range(10):
            tracker.record_event(
                _make_event(output_length=100, tool_used="search", content_type="text")
            )
        anchor = tracker.get_anchor("agent-1")
        assert anchor is not None
        assert anchor.event_count == 10

    def test_anchor_not_created_before_window(self):
        """Before window events, no anchor should exist."""
        tracker = BehaviorTracker(config={"anchor_window": 10})
        for i in range(9):
            tracker.record_event(
                _make_event(output_length=100, tool_used="search", content_type="text")
            )
        anchor = tracker.get_anchor("agent-1")
        assert anchor is None

    def test_anchor_immutable(self):
        """After anchor is set, new events should not change it."""
        tracker = BehaviorTracker(config={"anchor_window": 10})
        # Record 10 events with output_length=100 to create anchor
        for i in range(10):
            tracker.record_event(
                _make_event(output_length=100, tool_used="search", content_type="text")
            )
        anchor_before = tracker.get_anchor("agent-1")
        assert anchor_before is not None
        original_hash = anchor_before.fingerprint_hash
        original_mean = anchor_before.dimensions["output_length"]["mean"]

        # Record 20 more events with very different characteristics
        for i in range(20):
            tracker.record_event(
                _make_event(output_length=9999, tool_used="delete", content_type="code")
            )

        anchor_after = tracker.get_anchor("agent-1")
        assert anchor_after is not None
        assert anchor_after.fingerprint_hash == original_hash
        assert anchor_after.dimensions["output_length"]["mean"] == original_mean
        assert anchor_after.event_count == 10

        # But the rolling fingerprint should have changed
        current_fp = tracker.get_fingerprint("agent-1")
        assert current_fp.fingerprint_hash != original_hash

    def test_custom_anchor_window(self):
        """Custom anchor_window config is respected."""
        tracker = BehaviorTracker(config={"anchor_window": 5})

        # 4 events: no anchor yet
        for i in range(4):
            tracker.record_event(
                _make_event(output_length=100, tool_used="search", content_type="text")
            )
        assert tracker.get_anchor("agent-1") is None

        # 5th event triggers anchor
        tracker.record_event(
            _make_event(output_length=100, tool_used="search", content_type="text")
        )
        anchor = tracker.get_anchor("agent-1")
        assert anchor is not None
        assert anchor.event_count == 5


class TestTrackerConcurrency:
    def test_has_lock(self):
        tracker = BehaviorTracker()
        assert hasattr(tracker, "_lock")
        assert isinstance(tracker._lock, type(threading.Lock()))

    def test_concurrent_record_and_fingerprint(self):
        """Concurrent record_event and get_fingerprint calls should be safe."""
        tracker = BehaviorTracker(config={"window_size": 50})
        errors = []
        barrier = threading.Barrier(10)

        def record_worker(agent_id):
            try:
                barrier.wait(timeout=5)
                for i in range(20):
                    tracker.record_event(_make_event(
                        agent_id=agent_id,
                        output_length=i * 10,
                        timestamp=time.time() + i * 0.001,
                    ))
            except Exception as e:
                errors.append(e)

        def fingerprint_worker(agent_id):
            try:
                barrier.wait(timeout=5)
                for _ in range(20):
                    tracker.get_fingerprint(agent_id)
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(5):
            agent_id = f"agent-{i}"
            threads.append(threading.Thread(target=record_worker, args=(agent_id,)))
            threads.append(threading.Thread(target=fingerprint_worker, args=(agent_id,)))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert not errors

        # Each agent should have events recorded
        for i in range(5):
            fp = tracker.get_fingerprint(f"agent-{i}")
            assert fp.event_count > 0


class TestBehaviorEventValidation:
    """Tests for BehaviorEvent __post_init__ validation."""

    def test_negative_timestamp_rejected(self):
        """Negative timestamp should raise ValueError."""
        import pytest
        with pytest.raises(ValueError, match="timestamp must be non-negative"):
            BehaviorEvent(
                agent_id="agent-1",
                timestamp=-1.0,
                event_type="message",
                output_length=100,
                tool_used=None,
                content_type="text",
                target=None,
            )

    def test_negative_output_length_rejected(self):
        """Negative output_length should raise ValueError."""
        import pytest
        with pytest.raises(ValueError, match="output_length must be non-negative"):
            BehaviorEvent(
                agent_id="agent-1",
                timestamp=1.0,
                event_type="message",
                output_length=-5,
                tool_used=None,
                content_type="text",
                target=None,
            )

    def test_valid_event_accepted(self):
        """Normal non-negative values should construct without error."""
        event = BehaviorEvent(
            agent_id="agent-1",
            timestamp=0.0,
            event_type="message",
            output_length=0,
            tool_used=None,
            content_type="text",
            target=None,
        )
        assert event.timestamp == 0.0
        assert event.output_length == 0
