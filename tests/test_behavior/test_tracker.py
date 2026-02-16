"""Tests for behavior tracker."""

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
