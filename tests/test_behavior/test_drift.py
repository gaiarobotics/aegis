"""Tests for drift detection."""

import time

from aegis.behavior.drift import DriftDetector, DriftResult
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


def _build_stable_fingerprint(tracker, n=20):
    """Record n identical events and return the fingerprint."""
    for _ in range(n):
        tracker.record_event(
            _make_event(output_length=100, tool_used="search", content_type="text", target="a.com")
        )
    return tracker.get_fingerprint("agent-1")


class TestNoDriftNormalBehavior:
    def test_no_drift_normal_behavior(self):
        tracker = BehaviorTracker()
        fp = _build_stable_fingerprint(tracker)

        detector = DriftDetector()
        # An event that matches the established pattern exactly
        normal_event = _make_event(
            output_length=100, tool_used="search", content_type="text", target="a.com"
        )
        result = detector.check_drift(fp, normal_event)

        assert isinstance(result, DriftResult)
        assert result.is_drifting is False
        assert len(result.new_tools) == 0
        assert result.max_sigma < 2.5


class TestDriftDetectedLengthSpike:
    def test_drift_detected_length_spike(self):
        tracker = BehaviorTracker()
        # Build a profile with varied but small output lengths to get nonzero std
        for i in range(20):
            tracker.record_event(
                _make_event(
                    output_length=100 + (i % 3),
                    tool_used="search",
                    content_type="text",
                )
            )
        fp = tracker.get_fingerprint("agent-1")

        detector = DriftDetector()
        # A massive output length spike
        spike_event = _make_event(output_length=100000, tool_used="search", content_type="text")
        result = detector.check_drift(fp, spike_event)

        assert result.is_drifting is True
        assert result.max_sigma > 2.5
        assert "output_length" in result.anomalous_dimensions


class TestNewToolFlagged:
    def test_new_tool_flagged(self):
        tracker = BehaviorTracker()
        fp = _build_stable_fingerprint(tracker)

        detector = DriftDetector()
        # Event uses a tool never seen before
        new_tool_event = _make_event(output_length=100, tool_used="shell_exec", content_type="text")
        result = detector.check_drift(fp, new_tool_event)

        assert result.is_drifting is True
        assert "shell_exec" in result.new_tools


class TestZeroVarianceHandling:
    def test_zero_variance_handling(self):
        tracker = BehaviorTracker()
        # All identical events => std = 0 for output_length
        fp = _build_stable_fingerprint(tracker)

        detector = DriftDetector()
        # output_length differs from the constant mean of 100
        different_event = _make_event(
            output_length=200, tool_used="search", content_type="text", target="a.com"
        )
        result = detector.check_drift(fp, different_event)

        # Should detect drift via ratio-based fallback since std==0 and value!=mean
        assert result.is_drifting is True
        assert "output_length" in result.anomalous_dimensions

        # If value == mean and std == 0, should NOT flag
        same_event = _make_event(
            output_length=100, tool_used="search", content_type="text", target="a.com"
        )
        result2 = detector.check_drift(fp, same_event)
        assert result2.is_drifting is False


class TestThresholdConfigurable:
    def test_threshold_configurable(self):
        tracker = BehaviorTracker()
        # Build profile with some variance
        for i in range(20):
            tracker.record_event(
                _make_event(
                    output_length=100 + (i % 5),
                    tool_used="search",
                    content_type="text",
                )
            )
        fp = tracker.get_fingerprint("agent-1")

        # With a very high threshold, even a large spike should not trigger
        detector_lenient = DriftDetector(config={"drift_threshold": 100.0})
        spike_event = _make_event(output_length=200, tool_used="search", content_type="text")
        result = detector_lenient.check_drift(fp, spike_event)
        assert result.is_drifting is False

        # With a very low threshold, a small deviation should trigger
        detector_strict = DriftDetector(config={"drift_threshold": 0.1})
        small_event = _make_event(output_length=110, tool_used="search", content_type="text")
        result2 = detector_strict.check_drift(fp, small_event)
        assert result2.is_drifting is True
